"""Settings.

Every setting is an environment variable. When running outside Docker they can also live in a KEY=VALUE file
(default ~/.config/codes-verification/codes.env, or the path in CODES_CONFIG). Real environment variables win over the file.
"""
import os


def expand(path):
    return os.path.expanduser(os.path.expandvars(path)) if path else path


def read_env_file(path):
    """Parse a simple KEY=VALUE file (comments, blank lines, optional quotes, optional `export`)."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip().removeprefix("export ").strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            out[key] = value
    return out


CONFIG_FILE = expand(os.environ.get("CODES_CONFIG", "~/.config/codes-verification/codes.env"))
_file = read_env_file(CONFIG_FILE) if os.path.isfile(CONFIG_FILE) else {}


def get(key, default=""):
    value = os.environ.get(key)
    return _file.get(key, default) if value is None else value


def flag(key, default):
    return get(key, "1" if default else "0").strip().lower() not in ("0", "false", "no", "off", "")


STATE_DIR = expand(get("CODES_STATE_DIR", "~/.local/state/codes-verification"))
SOCKET = expand(get("CODES_SOCKET", f"{STATE_DIR}/sock/codes.sock"))
TOKENS_FILE = f"{STATE_DIR}/tokens.json"
ACCESS_LOG = expand(get("CODES_ACCESS_LOG", f"{STATE_DIR}/access.log"))
GOOGLE_TOKEN_FILE = expand(get("CODES_GOOGLE_TOKEN_FILE", f"{STATE_DIR}/google-token.json"))
ALIASES_FILE = expand(get("CODES_ALIASES_FILE", "~/.config/codes-verification/aliases.json"))
PUBLIC_URL = get("CODES_PUBLIC_URL").strip().rstrip("/")
REQUIRE_DMARC = flag("CODES_REQUIRE_DMARC", True)
TEST_SEND = flag("CODES_TEST_SEND", True)


def google_client():
    """-> (client_id, client_secret). From GOOGLE_CLIENT_ID/SECRET, or from the JSON file Google lets you download."""
    cid, secret = get("GOOGLE_CLIENT_ID").strip(), get("GOOGLE_CLIENT_SECRET").strip()
    path = expand(get("CODES_GOOGLE_CLIENT_FILE"))
    if not (cid and secret) and path:
        import json
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data = data.get("installed") or data.get("web") or data
        cid, secret = data.get("client_id", ""), data.get("client_secret", "")
    if not (cid and secret):
        raise RuntimeError("Google client not configured: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
    return cid, secret


def smtp():
    """SMTP settings for the test-page mail, or None when not configured."""
    src = dict(_file)
    path = expand(get("CODES_SMTP_ENV_FILE"))
    if path and os.path.isfile(path):
        src.update(read_env_file(path))
    keys = ("SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_FROM_NAME")
    s = {k: os.environ.get(k, src.get(k, "")) for k in keys}
    s["TO"] = get("CODES_TEST_MAIL_TO").strip()
    if not all(s[k] for k in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM", "TO")):
        return None
    s["SMTP_PORT"] = int(s["SMTP_PORT"] or 587)
    return s
