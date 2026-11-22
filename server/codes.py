#!/usr/bin/env -S python3 -I
"""codes: verification codes and sign-in links from your Gmail, delivered to a Firefox extension.

usage:
  codes serve                     run the service (Gmail watcher + HTTP API on a Unix socket)
  codes auth                      authorize read-only access to Gmail (once)
  codes token add <device>        create an access key for a browser (shown once)
  codes token list                list access keys
  codes token revoke <device>     revoke an access key
  codes status                    service health, keys and recent accesses
  codes scan [minutes]            show what would be detected in recent emails (default: 60)

Only the code or link is kept, never the email, for 10 minutes and in memory only.
Every access is logged (device, site, sender), never the code itself. Settings: see README.md.
"""
import hashlib, hmac, http.server, json, os, secrets, socket, socketserver, sys, threading, time, urllib.parse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import config
from domains import registrable, same_service
from extract import analyze
from gmail import Gmail, GmailError, NotAuthorized, authorize

VERSION = "1.4.0"
TTL = 600                 # a code is served for 10 minutes after the email arrived
SLOW, FAST = 10, 1        # Gmail polling interval: idle / while a browser is waiting for a code
MAX_WAIT = 50             # longest long-poll accepted from a client (seconds)
MAX_CLIENTS = 32          # concurrent requests; more get 503 (the relay also limits per IP)


def now():
    return time.time()


def log(msg):
    print(f"{datetime.now():%H:%M:%S} {msg}", flush=True)


def journal(msg):
    os.makedirs(os.path.dirname(config.ACCESS_LOG), mode=0o700, exist_ok=True)
    fd = os.open(config.ACCESS_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")


# ---------------------------------------------------------------- access keys (stored as SHA-256 only)
def load_tokens():
    try:
        with open(config.TOKENS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"tokens": []}


def save_tokens(d):
    os.makedirs(config.STATE_DIR, mode=0o700, exist_ok=True)
    tmp = config.TOKENS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, config.TOKENS_FILE)


def check_token(tok):
    """-> device name, or None"""
    if not tok or len(tok) > 200:
        return None
    digest = hashlib.sha256(tok.encode()).hexdigest()
    found = None
    for t in load_tokens()["tokens"]:            # no early exit: same work whether or not the key exists
        if hmac.compare_digest(t["sha256"], digest):
            found = t["name"]
    return found


# ---------------------------------------------------------------- recent codes + Gmail polling
def matches(entry, host):
    """Can this code be handed to a page on `host` without asking the user?"""
    if entry.get("test"):                        # simulated test codes only ever match the relay's own host
        return bool(config.PUBLIC_URL) and host == urllib.parse.urlsplit(config.PUBLIC_URL).hostname
    return same_service(host, entry["sender_domain"]) and (entry["verified"] or not config.REQUIRE_DMARC)


class Store:
    def __init__(self):
        self.items, self.seen = [], {}
        self.cond = threading.Condition()
        self.fast_until = 0
        self.last_poll, self.gmail = 0, "starting"

    def add(self, e):
        """Keep at most 5 fresh items per sender domain and 200 overall, so a flood of emails from one domain
        cannot push out the codes of every other site."""
        with self.cond:
            domain = registrable(e["sender_domain"])
            fresh = [x for x in self.items if now() - x["ts"] < TTL]
            same = [x for x in fresh if registrable(x["sender_domain"]) == domain]
            drop = {id(x) for x in same[:-4]}
            self.items = [x for x in fresh if id(x) not in drop][-199:] + [e]
            self.cond.notify_all()

    def fresh(self):
        with self.cond:
            return [x for x in reversed(self.items) if now() - x["ts"] < TTL]

    def find(self, host, after=0, top=None):
        for x in self.fresh():
            if x["ts"] >= after and matches(x, host) and (top is None or matches(x, top)):
                return x
        return None

    def wait_for(self, host, after, timeout, top=None):
        deadline = now() + timeout
        with self.cond:
            self.fast_until = max(self.fast_until, deadline + 5)
            self.cond.notify_all()                  # wakes the poller up: switch to fast polling right away
        while True:
            x = self.find(host, after, top)
            if x or now() >= deadline:
                return x
            with self.cond:
                self.cond.wait(min(1.0, max(0.05, deadline - now())))

    def mark_seen(self, mid):
        if mid in self.seen:
            return False
        if len(self.seen) > 5000:
            self.seen = dict(list(self.seen.items())[-2500:])
        self.seen[mid] = True
        return True


def process(g, store, mid):
    if not store.mark_seen(mid):
        return
    m = g.message(mid)
    if now() - m["ts"] > TTL:
        return
    a = analyze(m["subject"], m["text"], m["links"])
    if a["code"] or a["link"]:
        store.add({"id": mid, "ts": m["ts"], "sender": m["sender"], "sender_domain": m["sender_domain"],
                   "verified": m["verified"], "subject": m["subject"][:140], "code": a["code"], "link": a["link"]})
        log(f"found a {'code' if a['code'] else 'link'} from {m['sender_domain']}"
            f"{'' if m['verified'] else ' (DMARC not verified)'}, {int(now() - m['ts'])} s after it arrived")


def poller(store):
    g, cursor = Gmail(), None
    while True:
        try:
            if cursor is None:
                cursor = g.history_id()
                for mid in g.recent_ids(minutes=TTL // 60 + 1):
                    process(g, store, mid)
                log(f"watching Gmail (historyId {cursor})")
            ids, cursor = g.new_message_ids(cursor)
            for mid in ids:
                process(g, store, mid)
            store.last_poll, store.gmail = now(), "ok"
            pause = FAST if now() < store.fast_until else SLOW
        except NotAuthorized as e:
            if store.gmail != "not authorized":
                log(str(e))
            store.gmail, pause = "not authorized", 15
        except RuntimeError as e:                   # Google client missing from the settings
            if store.gmail != "not configured":
                log(str(e))
            store.gmail, pause = "not configured", 30
        except GmailError as e:
            store.gmail = "error"
            if e.code == 404:
                log("Gmail history expired, starting over")
                cursor, pause = None, 1
            elif e.code in (403, 429):
                log(f"Gmail quota, pausing 30 s ({e})")
                pause = 30
            else:
                log(f"Gmail error: {e}")
                pause = 15
        except Exception as e:                      # network hiccup and the like: keep going
            store.gmail = "error"
            log(f"error: {e!r}")
            pause = 15
        with store.cond:
            end = now() + pause
            while now() < end:
                if pause > FAST and now() < store.fast_until and store.gmail == "ok":
                    break                           # someone is waiting for a code: poll now
                store.cond.wait(min(1.0, end - now()))


# ---------------------------------------------------------------- test page: a real email, or a simulated code
_test_lock = threading.Lock()
_test_sent = []
DAILY = {"email": 10, "simulated": 20}     # an email costs SMTP quota: fewer of those


def test_mode():
    if not config.TEST_SEND:
        return "off"
    if config.smtp():
        return "email"
    return "simulated" if config.PUBLIC_URL else "off"


def send_test(store):
    mode = test_mode()
    if mode == "off":
        return False, "The test button is disabled on this server."
    with _test_lock:
        t = now()
        _test_sent[:] = [x for x in _test_sent if t - x < 86400]
        if _test_sent and t - _test_sent[-1] < 15:
            return False, "Please wait 15 seconds between two tries."
        if len(_test_sent) >= DAILY[mode]:
            return False, f"Daily limit of {DAILY[mode]} test codes reached."
        _test_sent.append(t)
    code = f"{secrets.randbelow(900000) + 100000}"
    if mode == "simulated":
        host = urllib.parse.urlsplit(config.PUBLIC_URL).hostname
        store.add({"id": "test-" + secrets.token_hex(6), "ts": now(), "sender": f"test@{host}", "sender_domain": host,
                   "verified": True, "test": True, "subject": "Simulated code from the test page",
                   "code": code, "link": None})
        return True, "simulated"
    import smtplib
    from email.message import EmailMessage
    s = config.smtp()
    m = EmailMessage()
    m["Subject"] = "Your sign-in code (codes test page)"
    m["From"] = f'{s["SMTP_FROM_NAME"] or "codes"} <{s["SMTP_FROM"]}>'
    m["To"] = s["TO"]                               # always the owner, never an address coming from the page
    m.set_content(f"Your sign-in code is {code}\n\nIt expires in 10 minutes.\n"
                  "You are receiving this because someone pressed the button on your codes test page.")
    try:
        with smtplib.SMTP(s["SMTP_HOST"], s["SMTP_PORT"], timeout=30) as smtp:
            smtp.starttls()
            smtp.login(s["SMTP_USERNAME"], s["SMTP_PASSWORD"])
            smtp.send_message(m)
    except Exception as e:
        return False, f"Could not send the email ({type(e).__name__})."
    return True, "email"


# ---------------------------------------------------------------- HTTP over a Unix socket (behind the nginx relay)
def public(e, host=None):
    out = {k: e[k] for k in ("id", "code", "link", "sender", "sender_domain", "subject", "verified")}
    out.update(received=int(e["ts"]), age=int(now() - e["ts"]))
    if host:
        out["match"] = matches(e, host)
    return out


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "codes"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    slots = threading.BoundedSemaphore(MAX_CLIENTS)

    def address_string(self):
        return (getattr(self, "headers", None) or {}).get("X-Real-IP", "-")

    def log_message(self, fmt, *args):
        pass

    def send(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def local(self):
        """Request made on the socket directly (codes status), not through the relay, which always sets X-Real-IP."""
        return "X-Real-IP" not in self.headers

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        store = self.server.store
        if u.path == "/v1/health":
            if not self.local():                    # public: nothing that tells when you are signing in
                return self.send(200, {"ok": True, "test": test_mode()})
            return self.send(200, {"ok": True, "version": VERSION, "gmail": store.gmail,
                                   "last_poll": int(store.last_poll), "test": test_mode()})
        auth = self.headers.get("Authorization", "")
        device = check_token(auth[7:].strip() if auth.startswith("Bearer ") else "")
        if not device:
            journal(f"DENIED invalid key ip={self.address_string()} {u.path}")
            time.sleep(1)
            return self.send(401, {"error": "invalid access key"})
        host = (q.get("domain") or "").lower()[:253]
        top = (q.get("top") or "").lower()[:253] or None      # site of the tab, when the field is in a frame
        if u.path == "/v1/me":
            return self.send(200, {"device": device, "version": VERSION, "gmail": store.gmail})
        if u.path == "/v1/code":
            if not host or "." not in host:
                return self.send(400, {"error": "missing domain parameter"})
            try:
                wait = max(0, min(MAX_WAIT, int(q.get("wait", "0"))))
                after = float(q.get("after", "0"))
            except ValueError:
                return self.send(400, {"error": "invalid parameters"})
            e = store.find(host, after, top)
            if not e and wait:
                if not self.slots.acquire(blocking=False):  # long-polls hold a thread: cap them
                    return self.send(503, {"error": "busy"})
                try:
                    e = store.wait_for(host, after, wait, top)
                finally:
                    self.slots.release()
            if not e:
                return self.send(204)
            journal(f"SERVED {'code' if e['code'] else 'link'} device={device} site={registrable(host)} "
                    f"sender={e['sender_domain']} id={e['id']} ip={self.address_string()}")
            return self.send(200, public(e, host))
        if u.path == "/v1/recent":
            items = [public(e, host or None) for e in store.fresh()]
            if items:
                journal(f"LISTED {len(items)} item(s) device={device} site={registrable(host) if host else '-'} "
                        f"ip={self.address_string()}")
            return self.send(200, {"items": items})
        return self.send(404, {"error": "not found"})

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/test/send":
            return self.send(404, {"error": "not found"})
        origin = self.headers.get("Origin")
        if origin and origin.rstrip("/") != config.PUBLIC_URL:   # another website posting here (CSRF)
            journal(f"TEST refused origin={origin[:100]!r} ip={self.address_string()}")
            return self.send(403, {"ok": False, "error": "forbidden"})
        ok, msg = send_test(self.server.store)
        journal(f"TEST {msg if ok else 'refused'} ip={self.address_string()}")
        return self.send(200 if ok else 429, {"ok": ok, "mode": msg if ok else None, "error": None if ok else msg})


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        req, _ = super().get_request()
        return req, ("-", 0)


def serve():
    sock_dir = os.path.dirname(config.SOCKET)
    os.makedirs(config.STATE_DIR, mode=0o700, exist_ok=True)
    os.makedirs(sock_dir, exist_ok=True)
    if os.path.dirname(sock_dir) == config.STATE_DIR:
        os.chmod(config.STATE_DIR, 0o700)
    try:
        os.chmod(sock_dir, 0o711)                   # nginx runs as another user: it may traverse, not list
    except PermissionError:
        pass
    if os.path.exists(config.SOCKET):
        os.unlink(config.SOCKET)
    store = Store()
    threading.Thread(target=poller, args=(store,), daemon=True).start()
    srv = Server(config.SOCKET, Handler)
    os.chmod(config.SOCKET, 0o666)                  # anyone may connect; every request still needs a valid key
    srv.store = store
    log(f"codes {VERSION} listening on {config.SOCKET} (test page: {test_mode()})")
    srv.serve_forever()


# ---------------------------------------------------------------- command line
def cli_token(args):
    d = load_tokens()
    if args[:1] == ["add"] and len(args) == 2:
        name = args[1]
        if not name.replace("-", "").replace("_", "").isalnum() or len(name) > 40:
            sys.exit("device name: letters, digits, - and _ only (40 max)")
        if any(t["name"] == name for t in d["tokens"]):
            sys.exit(f"a key named '{name}' already exists (codes token revoke {name})")
        tok = "cdx_" + secrets.token_urlsafe(32)
        d["tokens"].append({"name": name, "sha256": hashlib.sha256(tok.encode()).hexdigest(),
                            "created": datetime.now().isoformat(timespec="seconds")})
        save_tokens(d)
        print(f"Access key for '{name}'. It is shown only once: paste it in the extension settings.\n\n{tok}\n")
    elif args == ["list"]:
        for t in d["tokens"]:
            print(f"{t['name']:20} created {t['created']}")
        if not d["tokens"]:
            print("no keys yet (codes token add <device>)")
    elif args[:1] == ["revoke"] and len(args) == 2:
        n = len(d["tokens"])
        d["tokens"] = [t for t in d["tokens"] if t["name"] != args[1]]
        save_tokens(d)
        print("revoked" if len(d["tokens"]) < n else "no such key")
    else:
        sys.exit("usage: codes token add <device> | list | revoke <device>")


def unix_get(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(config.SOCKET)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: codes\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while chunk := s.recv(65536):
        data += chunk
    s.close()
    return data.split(b"\r\n\r\n", 1)[1].decode()


def main():
    a = sys.argv[1:]
    if a == ["serve"]:
        serve()
    elif a == ["auth"]:
        try:
            authorize()
        except (RuntimeError, GmailError) as e:
            sys.exit(str(e))
    elif a[:1] == ["token"]:
        cli_token(a[1:])
    elif a == ["status"]:
        try:
            print("service:", unix_get("/v1/health"))
        except OSError as e:
            print(f"service unreachable on {config.SOCKET}: {e}")
        print("keys:", ", ".join(t["name"] for t in load_tokens()["tokens"]) or "none")
        if os.path.exists(config.ACCESS_LOG):
            print("recent accesses:")
            with open(config.ACCESS_LOG, encoding="utf-8") as f:
                for line in f.readlines()[-8:]:
                    print("  " + line.rstrip())
    elif a[:1] == ["scan"] and len(a) <= 2:
        g = Gmail()
        try:
            for mid in g.recent_ids(minutes=int(a[1]) if len(a) > 1 else 60):
                m = g.message(mid)
                r = analyze(m["subject"], m["text"], m["links"])
                if r["code"] or r["link"]:
                    flag = "dmarc ok " if m["verified"] else "UNVERIFIED"
                    print(f"{m['sender_domain'][:28]:28} {flag} {m['subject'][:44]:44} {r['code'] or r['link'][:60]}")
        except (NotAuthorized, RuntimeError, GmailError) as e:
            sys.exit(str(e))
    else:
        print(__doc__.strip())
        sys.exit(0 if a in ([], ["help"], ["-h"], ["--help"]) else 2)


if __name__ == "__main__":
    main()
