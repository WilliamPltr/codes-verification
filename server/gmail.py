"""Minimal read-only Gmail client (standard library only): OAuth refresh, history polling, message parsing."""
import base64, hashlib, json, os, re, secrets, threading, time, urllib.error, urllib.parse, urllib.request
from email.utils import parseaddr

import config
from domains import registrable
from extract import html_to_text, text_links

API = "https://gmail.googleapis.com/gmail/v1/users/me"
TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
REDIRECT = "http://127.0.0.1:8765/"
SKIP_LABELS = {"SPAM", "TRASH", "DRAFT", "SENT"}


class GmailError(Exception):
    def __init__(self, code, msg):
        super().__init__(f"HTTP {code}: {msg}")
        self.code = code


class NotAuthorized(Exception):
    pass


def _post_form(url, fields):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
            msg = ": ".join(x for x in (body.get("error"), body.get("error_description")) if x)
        except Exception:
            msg = ""
        raise GmailError(e.code, msg) from None


class Gmail:
    def __init__(self):
        self._tok, self._exp, self._lock = None, 0, threading.Lock()

    def _token(self):
        with self._lock:
            if self._tok and time.time() < self._exp - 120:
                return self._tok
            try:
                with open(config.GOOGLE_TOKEN_FILE, encoding="utf-8") as f:
                    refresh = json.load(f)["refresh_token"]
            except (OSError, ValueError, KeyError):
                raise NotAuthorized("no Google authorization yet: run `codes auth`") from None
            cid, secret = config.google_client()
            r = _post_form(TOKEN_URL, {"client_id": cid, "client_secret": secret,
                                       "refresh_token": refresh, "grant_type": "refresh_token"})
            self._tok, self._exp = r["access_token"], time.time() + int(r.get("expires_in", 3600))
            return self._tok

    def get(self, path, **params):
        q = urllib.parse.urlencode(params, doseq=True)
        req = urllib.request.Request(f"{API}{path}" + (f"?{q}" if q else ""),
                                     headers={"Authorization": "Bearer " + self._token()})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error", "")
                msg = msg.get("message", msg) if isinstance(msg, dict) else msg
            except Exception:
                msg = ""
            if e.code == 401:
                self._tok = None
            raise GmailError(e.code, msg) from None

    def profile(self):
        return self.get("/profile")

    def history_id(self):
        return self.profile()["historyId"]

    def new_message_ids(self, start):
        """-> (ids of messages added since `start`, new historyId). GmailError 404 when `start` is too old."""
        ids, page, last = [], None, start
        while True:
            p = {"startHistoryId": start, "historyTypes": "messageAdded", "maxResults": 100}
            if page:
                p["pageToken"] = page
            r = self.get("/history", **p)
            for h in r.get("history", []):
                for m in h.get("messagesAdded", []):
                    if not set(m["message"].get("labelIds", [])) & SKIP_LABELS:
                        ids.append(m["message"]["id"])
            last = r.get("historyId", last)
            page = r.get("nextPageToken")
            if not page:
                return list(dict.fromkeys(ids)), last

    def recent_ids(self, minutes=15):
        q = f"after:{int(time.time() - minutes * 60)} -in:spam -in:trash -in:sent -in:drafts"
        return [m["id"] for m in self.get("/messages", q=q, maxResults=20).get("messages", [])]

    def message(self, mid):
        """-> dict(id, ts, sender, sender_domain, verified, subject, text, links)"""
        m = self.get(f"/messages/{mid}", format="full")
        headers = [(h["name"].lower(), h["value"]) for h in m["payload"].get("headers", [])]
        hdr = dict(reversed(headers))                    # first occurrence wins
        plain, html_parts = [], []

        def walk(p, depth=0):
            if depth > 30:                       # absurdly nested MIME: ignore the rest
                return
            body = p.get("body", {})
            if body.get("data") and not p.get("filename") and len(body["data"]) < 4_000_000:
                raw = base64.urlsafe_b64decode(body["data"] + "==")
                cs = "utf-8"
                for h in p.get("headers", []):
                    if h["name"].lower() == "content-type" and "charset=" in h["value"].lower():
                        cs = h["value"].lower().split("charset=")[1].split(";")[0].strip("\"' ")
                try:
                    s = raw.decode(cs, errors="replace")
                except LookupError:
                    s = raw.decode("utf-8", errors="replace")
                if p.get("mimeType") == "text/plain":
                    plain.append(s)
                elif p.get("mimeType") == "text/html":
                    html_parts.append(s)
            for c in p.get("parts", []) or []:
                walk(c, depth + 1)

        walk(m["payload"])
        links, htext = [], ""
        if html_parts:
            htext, links = html_to_text("\n".join(html_parts))
        text = "\n".join(plain).strip() or htext
        links += text_links("\n".join(plain))
        addr = parseaddr(hdr.get("from", ""))[1].lower()
        domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
        return {"id": mid, "ts": int(m.get("internalDate", "0")) / 1000, "sender": addr, "sender_domain": domain,
                "verified": dmarc_pass(headers, domain), "subject": hdr.get("subject", ""),
                "text": text[:50000], "links": links[:300]}


def _strip_comments(value):
    """Remove quoted strings and (nested) comments, so nothing the sender wrote can pass for a clause."""
    value = re.sub(r'"(?:[^"\\]|\\.)*"', '""', value)
    while True:
        stripped = re.sub(r"\([^()]*\)", " ", value)
        if stripped == value:
            return value
        value = stripped


def dmarc_pass(headers, sender_domain):
    """True when Gmail itself says the From domain passed DMARC.

    Gmail puts its own Authentication-Results header on top of the message, so only the first one counts: anything
    below it may have been written by the sender. Inside it, only a single, well-formed `dmarc=` clause is accepted
    (the spf clause quotes the envelope sender, which the sender chooses)."""
    for name, value in headers:
        if name != "authentication-results":
            continue
        clauses = [" ".join(c.split()) for c in _strip_comments(value).split(";")]
        if clauses[0].lower() != "mx.google.com":
            return False
        dmarc = [c for c in clauses[1:] if c.lower().startswith("dmarc=")]
        if len(dmarc) != 1:
            return False
        m = re.fullmatch(r"dmarc=(\w+) header\.from=([A-Za-z0-9.-]+)", dmarc[0], re.I)
        return bool(m and m.group(1).lower() == "pass" and sender_domain
                    and registrable(m.group(2)) == registrable(sender_domain))
    return False


# ---------------------------------------------------------------- one-time authorization (`codes auth`)
def authorize():
    cid, secret = config.google_client()
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    url = AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": cid, "redirect_uri": REDIRECT, "response_type": "code", "scope": SCOPE,
        "access_type": "offline", "prompt": "consent", "code_challenge": challenge,
        "code_challenge_method": "S256", "state": state})
    print("1. Open this address in your browser and allow read-only access to Gmail:\n")
    print("   " + url + "\n")
    print("2. Google then sends you to http://127.0.0.1:8765/?state=...&code=...")
    print("   The page will not load. That is expected: copy the whole address from the address bar.\n")
    pasted = input("3. Paste it here: ").strip()
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(pasted).query)
    if "error" in q:
        raise SystemExit(f"Google refused: {q['error'][0]}")
    if q.get("state", [""])[0] != state:
        raise SystemExit("This address does not belong to this attempt (state mismatch). Run `codes auth` again.")
    if "code" not in q:
        raise SystemExit("No authorization code found in that address.")
    r = _post_form(TOKEN_URL, {"client_id": cid, "client_secret": secret, "code": q["code"][0],
                               "code_verifier": verifier, "redirect_uri": REDIRECT,
                               "grant_type": "authorization_code"})
    if "refresh_token" not in r:
        raise SystemExit("Google did not return a refresh token. Remove the app at "
                         "https://myaccount.google.com/permissions and run `codes auth` again.")
    os.makedirs(os.path.dirname(config.GOOGLE_TOKEN_FILE), mode=0o700, exist_ok=True)
    tmp = config.GOOGLE_TOKEN_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"refresh_token": r["refresh_token"], "scope": r.get("scope", SCOPE),
                   "created": int(time.time())}, f)
    os.replace(tmp, config.GOOGLE_TOKEN_FILE)
    print(f"\nAuthorized: {Gmail().profile()['emailAddress']} (read-only). Saved to {config.GOOGLE_TOKEN_FILE}")
