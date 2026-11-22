"""Sender matching, DMARC parsing, and the HTTP API over a real Unix socket (no Gmail involved)."""
import hashlib, json, os, socket, sys, tempfile, threading, time, unittest

TMP = tempfile.mkdtemp(prefix="codes-test-")
os.environ.update(CODES_CONFIG=os.path.join(TMP, "none.env"), CODES_STATE_DIR=TMP,
                  CODES_SOCKET=os.path.join(TMP, "sock", "codes.sock"), CODES_ALIASES_FILE=os.path.join(TMP, "aliases.json"),
                  CODES_PUBLIC_URL="https://codes.example.org", CODES_REQUIRE_DMARC="1")
for k in ("CODES_TEST_MAIL_TO", "SMTP_HOST", "CODES_SMTP_ENV_FILE"):
    os.environ.pop(k, None)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import codes, config
from domains import registrable, same_service
from gmail import dmarc_pass


class Domains(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(registrable("accounts.google.com"), "google.com")
        self.assertEqual(registrable("www.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(registrable("Example.COM."), "example.com")
        self.assertEqual(registrable("login.mybank.com.ar"), "mybank.com.ar")      # Public Suffix List
        self.assertEqual(registrable("evil.github.io"), "evil.github.io")          # private section too
        self.assertEqual(registrable("www.ck"), "www.ck")                          # exception rule
        self.assertEqual(registrable("a.b.foo.ck"), "b.foo.ck")                    # wildcard rule

    def test_same_service(self):
        self.assertTrue(same_service("github.com", "noreply.github.com"))
        self.assertTrue(same_service("login.microsoftonline.com", "accountprotection.microsoft.com"))
        self.assertFalse(same_service("github.com", "github-security.com"))
        self.assertFalse(same_service("accounts.google.com", "gmail.com"))     # anyone can send from gmail.com
        self.assertFalse(same_service("", "github.com"))
        self.assertFalse(same_service("phishing.com.ar", "mybank.com.ar"))
        self.assertFalse(same_service("evil.github.io", "noreply.github.io"))
        self.assertFalse(same_service("com.ar", "com.ar"))                        # bare public suffix
        self.assertFalse(same_service("x.githubusercontent.com", "github.com"))   # hosts user content

    def test_user_aliases(self):
        with open(config.ALIASES_FILE, "w") as f:
            json.dump([["myschool.edu", "school-mail.net"]], f)
        os.utime(config.ALIASES_FILE, (time.time() + 5, time.time() + 5))
        self.assertTrue(same_service("portal.myschool.edu", "school-mail.net"))


class Dmarc(unittest.TestCase):
    GOOD = ("mx.google.com; dkim=pass header.i=@github.com header.s=pf2023; spf=pass smtp.mailfrom=noreply@github.com; "
            "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com")

    def test_pass(self):
        self.assertTrue(dmarc_pass([("authentication-results", self.GOOD)], "github.com"))

    def test_fail_or_other_domain(self):
        bad = self.GOOD.replace("dmarc=pass", "dmarc=fail")
        self.assertFalse(dmarc_pass([("authentication-results", bad)], "github.com"))
        self.assertFalse(dmarc_pass([("authentication-results", self.GOOD)], "evil.com"))
        self.assertFalse(dmarc_pass([], "github.com"))

    def test_only_gmail_header_counts(self):
        # a forged header further down must not win over Gmail's own (the first one)
        forged = [("authentication-results", "mx.google.com; dmarc=fail (p=NONE) header.from=bank.com"),
                  ("authentication-results", "mx.google.com; dmarc=pass (p=NONE) header.from=bank.com")]
        self.assertFalse(dmarc_pass(forged, "bank.com"))
        self.assertFalse(dmarc_pass([("authentication-results", "evil.example; dmarc=pass header.from=bank.com")], "bank.com"))
        self.assertFalse(dmarc_pass([("authentication-results", "mx.google.comevil; dmarc=pass header.from=bank.com")], "bank.com"))

    def test_envelope_sender_cannot_fake_a_clause(self):
        # the spf clause quotes the envelope sender, which the attacker chooses
        tricks = [
            "mx.google.com; spf=pass (google.com: domain of dmarc=pass.header.from=bank.com@evil.com designates 1.2.3.4) "
            "smtp.mailfrom=dmarc=pass.header.from=bank.com@evil.com; dmarc=fail (p=NONE) header.from=bank.com",
            'mx.google.com; spf=pass smtp.mailfrom="x;dmarc=pass header.from=bank.com"@evil.com; '
            "dmarc=fail (p=NONE) header.from=bank.com",
            "mx.google.com; spf=pass (x; dmarc=pass header.from=bank.com) smtp.mailfrom=a@evil.com; "
            "dmarc=fail header.from=bank.com",
            "mx.google.com; dmarc=pass header.from=bank.com; dmarc=fail header.from=bank.com",
        ]
        for value in tricks:
            with self.subTest(value=value):
                self.assertFalse(dmarc_pass([("authentication-results", value)], "bank.com"))


def request(path, token=None, method="GET", headers=None, relay=True):
    """relay=True adds X-Real-IP, as nginx does: the request looks like it came from the Internet."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(config.SOCKET)
    extra = dict(headers or {})
    if token:
        extra["Authorization"] = f"Bearer {token}"
    if relay:
        extra["X-Real-IP"] = "203.0.113.7"
    lines = "".join(f"{k}: {v}\r\n" for k, v in extra.items())
    s.sendall(f"{method} {path} HTTP/1.1\r\nHost: codes\r\n{lines}Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while chunk := s.recv(65536):
        data += chunk
    s.close()
    head, body = data.split(b"\r\n\r\n", 1)
    return int(head.split()[1]), json.loads(body) if body else None


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token = "cdx_test_" + "x" * 30
        codes.save_tokens({"tokens": [{"name": "laptop", "sha256": hashlib.sha256(cls.token.encode()).hexdigest(),
                                       "created": "2026-01-01T00:00:00"}]})
        os.makedirs(os.path.dirname(config.SOCKET), exist_ok=True)
        cls.store = codes.Store()
        cls.srv = codes.Server(config.SOCKET, codes.Handler)
        cls.srv.store = cls.store
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def add(self, **kw):
        e = {"id": kw.get("id", "m1"), "ts": time.time(), "sender": "noreply@github.com", "sender_domain": "github.com",
             "verified": True, "subject": "Your code", "code": "123456", "link": None}
        e.update(kw)
        self.store.add(e)
        return e

    def test_health(self):
        status, body = request("/v1/health")
        self.assertEqual((status, body), (200, {"ok": True, "test": "simulated"}))   # public: says nothing more
        status, body = request("/v1/health", relay=False)                           # codes status, on the socket
        self.assertIn("last_poll", body)
        self.assertIn("gmail", body)

    def test_key_required(self):
        self.assertEqual(request("/v1/me")[0], 401)
        self.assertEqual(request("/v1/me", "cdx_wrong")[0], 401)
        status, body = request("/v1/me", self.token)
        self.assertEqual((status, body["device"]), (200, "laptop"))

    def test_code_for_matching_site_only(self):
        self.add(id="gh1")
        status, body = request("/v1/code?domain=github.com", self.token)
        self.assertEqual((status, body["code"], body["match"]), (200, "123456", True))
        self.assertEqual(request("/v1/code?domain=evil.com", self.token)[0], 204)

    def test_unverified_sender_is_not_auto_filled(self):
        self.store.items.clear()
        self.add(id="spoof", sender_domain="bank.com", verified=False)
        self.assertEqual(request("/v1/code?domain=bank.com", self.token)[0], 204)
        status, body = request("/v1/recent?domain=bank.com", self.token)
        self.assertEqual(status, 200)
        self.assertFalse(body["items"][0]["match"])

    def test_frame_needs_matching_tab(self):
        self.store.items.clear()
        self.add(id="frame", sender_domain="bank.com")
        self.assertEqual(request("/v1/code?domain=www.bank.com&top=www.bank.com", self.token)[0], 200)
        # bank.com framed (invisibly) by another site: no auto-fill
        self.assertEqual(request("/v1/code?domain=www.bank.com&top=evil.com", self.token)[0], 204)

    def test_flood_from_one_domain_keeps_other_codes(self):
        self.store.items.clear()
        self.add(id="real", sender_domain="github.com", code="111111")
        for i in range(300):
            self.add(id=f"spam{i}", sender_domain="spam.example", code=f"{i:06d}")
        self.assertEqual(request("/v1/code?domain=github.com", self.token)[1]["code"], "111111")
        self.assertLessEqual(len(self.store.items), 10)

    def test_long_poll(self):
        self.store.items.clear()
        threading.Timer(1.0, lambda: self.add(id="late", code="999111")).start()
        t = time.time()
        status, body = request("/v1/code?domain=github.com&wait=5", self.token)
        self.assertEqual((status, body["code"]), (200, "999111"))
        self.assertLess(time.time() - t, 4)

    def test_simulated_test_code(self):
        status, body = request("/test/send", method="POST")
        self.assertEqual((status, body["mode"]), (200, "simulated"))
        status, body = request("/v1/code?domain=codes.example.org", self.token)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["code"]), 6)
        # a simulated code never matches any other site, even on the same domain
        self.assertEqual(request("/v1/code?domain=www.example.org", self.token)[0], 204)
        self.assertEqual(request("/test/send", method="POST")[0], 429)   # rate limited
        status = request("/test/send", method="POST", headers={"Origin": "https://evil.example"})[0]
        self.assertEqual(status, 403)                                     # other websites can't press the button

    def test_bad_requests(self):
        self.assertEqual(request("/v1/code", self.token)[0], 400)
        self.assertEqual(request("/v1/code?domain=github.com&wait=abc", self.token)[0], 400)
        self.assertEqual(request("/v1/nope", self.token)[0], 404)
        self.assertEqual(request("/v1/me", self.token, method="POST")[0], 404)


if __name__ == "__main__":
    unittest.main()
