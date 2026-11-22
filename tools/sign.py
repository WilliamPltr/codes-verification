#!/usr/bin/env python3
"""Have Mozilla sign the extension as an UNLISTED add-on (not published on addons.mozilla.org), then download it.

usage: tools/sign.py [--id codes@yourdomain.com] [--server https://codes.yourdomain.com] [--credentials FILE]

API credentials come from https://addons.mozilla.org/developers/addon/api/key/ and are read from
AMO_JWT_ISSUER and AMO_JWT_SECRET: environment first, then --credentials FILE (KEY=VALUE lines), then the
repository's .env. --id and --server work as in tools/build.py.
Bump "version" in extension/manifest.json before each new signature: Mozilla never signs the same version twice.
"""
import argparse, base64, hashlib, hmac, json, os, secrets, sys, time, urllib.error, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build import DIST, PLACEHOLDER_ID, build, setting

API = "https://addons.mozilla.org/api/v5"


def creds(path=None):
    env = {}
    if path:
        for line in open(os.path.expanduser(path), encoding="utf-8"):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k.strip()] = v.strip().strip("\"'")
    iss = os.environ.get("AMO_JWT_ISSUER") or env.get("AMO_JWT_ISSUER") or setting("AMO_JWT_ISSUER")
    secret = os.environ.get("AMO_JWT_SECRET") or env.get("AMO_JWT_SECRET") or setting("AMO_JWT_SECRET")
    if not (iss and secret):
        sys.exit("AMO_JWT_ISSUER / AMO_JWT_SECRET not found (environment, --credentials file or .env)")
    return iss, secret


def jwt(iss, secret):
    b64 = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=")
    now = int(time.time())
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"iss": iss, "jti": secrets.token_hex(16), "iat": now, "exp": now + 60}).encode())
    sig = b64(hmac.new(secret.encode(), head + b"." + body, hashlib.sha256).digest())
    return (head + b"." + body + b"." + sig).decode()


def call(method, url, iss, secret, data=None, ctype=None, raw=False):
    h = {"Authorization": "JWT " + jwt(iss, secret)}
    if ctype:
        h["Content-Type"] = ctype
    req = urllib.request.Request(url if url.startswith("http") else API + url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            b = r.read()
    except urllib.error.HTTPError as e:
        sys.exit(f"AMO HTTP {e.code} {url}: {e.read()[:600].decode(errors='replace')}")
    return b if raw else (json.loads(b) if b else {})


def multipart(fields, file_field, path):
    b = "amo" + secrets.token_hex(8)
    out = b""
    for k, v in fields.items():
        out += f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
    out += (f"--{b}\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"{os.path.basename(path)}\"\r\n"
            f"Content-Type: application/x-xpinstall\r\n\r\n").encode() + open(path, "rb").read() + f"\r\n--{b}--\r\n".encode()
    return out, f"multipart/form-data; boundary={b}"


def main():
    p = argparse.ArgumentParser(description="Sign the extension (unlisted) with addons.mozilla.org.")
    p.add_argument("--id", help="add-on ID, e.g. codes@yourdomain.com")
    p.add_argument("--server", help="default server address baked into the build")
    p.add_argument("--credentials", help="file with AMO_JWT_ISSUER=... and AMO_JWT_SECRET=...")
    a = p.parse_args()
    iss, secret = creds(a.credentials)
    xpi, version, guid = build(a.id, a.server)
    if guid == PLACEHOLDER_ID:
        sys.exit("Choose your own add-on ID first: --id codes@yourdomain.com (or CODES_EXTENSION_ID in .env)")
    print(f"uploading {os.path.basename(xpi)} (version {version}, id {guid}, unlisted)")
    body, ct = multipart({"channel": "unlisted"}, "upload", xpi)
    up = call("POST", "/addons/upload/", iss, secret, body, ct)
    for _ in range(60):
        if up.get("processed"):
            break
        time.sleep(5)
        up = call("GET", f"/addons/upload/{up['uuid']}/", iss, secret)
    if not up.get("valid"):
        sys.exit("rejected by Mozilla's validator: " + json.dumps(up.get("validation", {}), ensure_ascii=False)[:1500])
    print("automatic validation passed")
    exists = True
    try:
        urllib.request.urlopen(urllib.request.Request(f"{API}/addons/addon/{guid}/",
                                                      headers={"Authorization": "JWT " + jwt(iss, secret)}), timeout=30)
    except urllib.error.HTTPError as e:
        exists = e.code != 404
    payload = json.dumps({"upload": up["uuid"]} if exists else {"version": {"upload": up["uuid"]}}).encode()
    if exists:
        v = call("POST", f"/addons/addon/{guid}/versions/", iss, secret, payload, "application/json")
    else:
        addon = call("POST", "/addons/addon/", iss, secret, payload, "application/json")
        v = addon.get("latest_unlisted_version") or addon.get("current_version")
    vid = v["id"]
    print(f"version {version} created (id {vid}), waiting for the signature…")
    for _ in range(120):
        v = call("GET", f"/addons/addon/{guid}/versions/{vid}/", iss, secret)
        f = v.get("file") or {}
        if f.get("status") == "public" and f.get("url"):
            data = call("GET", f["url"], iss, secret, raw=True)
            out = os.path.join(DIST, f"codes-{version}-signed.xpi")
            open(out, "wb").write(data)
            print(f"signed: {out}")
            return
        if f.get("status") == "disabled":
            sys.exit("Mozilla refused this version")
        time.sleep(10)
    sys.exit("still waiting for the signature: run again later (the version already exists on Mozilla's side)")


if __name__ == "__main__":
    main()
