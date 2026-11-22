"""Does this email sender belong to the site the user is on?

A code is only filled in automatically when the sender's registrable domain ("eTLD+1", e.g. example.co.uk) equals the
page's, or when both are listed in the same alias group (one service, several domains). Registrable domains come from
the Public Suffix List, including its private section: evil.github.io and yourname.github.io are different sites.

Alias groups never include free mailbox providers (anyone can send from gmail.com) nor domains that host other
people's content (githubusercontent.com...).
"""
import json, os

import config

PSL_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "public_suffix_list.dat")

ALIASES = [
    ["microsoft.com", "microsoftonline.com", "office.com", "accountprotection.microsoft.com"],
    ["google.com", "youtube.com"],
    ["amazon.com", "amazon.fr", "amazon.de", "amazon.co.uk", "amazon.es", "amazon.it"],
    ["apple.com", "id.apple.com"],
    ["paypal.com", "paypal.fr"],
    ["eventbrite.com", "eventbrite.fr", "eventbrite.co.uk"],
    ["x.com", "twitter.com"],
    ["discord.com", "discordapp.com"],
    ["notion.so", "notion.com", "makenotion.com"],
    ["claude.ai", "anthropic.com"],
    ["chatgpt.com", "openai.com"],
    ["ameli.fr", "assurance-maladie.fr"],
    ["sncf.com", "sncf-connect.com", "connect.sncf"],
]


def _ascii(name):
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def _load_psl():
    rules, wildcards, exceptions = set(), set(), set()
    with open(PSL_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = ".".join(_ascii(label) for label in line.split()[0].lower().split("."))
            if rule.startswith("!"):
                exceptions.add(rule[1:])
            elif rule.startswith("*."):
                wildcards.add(rule[2:])
            else:
                rules.add(rule)
    return rules, wildcards, exceptions


RULES, WILDCARDS, EXCEPTIONS = _load_psl()


def registrable(host):
    """'login.example.co.uk' -> 'example.co.uk' (eTLD+1). A bare public suffix is returned as is."""
    host = _ascii((host or "").lower().strip().strip(".").split(":")[0])
    labels = [x for x in host.split(".") if x]
    if not labels:
        return ""
    suffix = 1                                   # default rule "*": the last label is a public suffix
    for i in range(len(labels)):                 # longest candidate first, so the first hit is the longest match
        candidate = ".".join(labels[i:])
        if candidate in EXCEPTIONS:
            suffix = len(labels) - i - 1
            break
        if candidate in RULES or ".".join(labels[i + 1:]) in WILDCARDS and i + 1 < len(labels):
            suffix = len(labels) - i
            break
    if len(labels) <= suffix:
        return ".".join(labels)
    return ".".join(labels[-(suffix + 1):])


_cache = {"mtime": None, "groups": None}


def _groups():
    """Built-in groups plus the optional user file ([["a.com", "b.net"], ...]), reloaded when it changes."""
    try:
        mtime = os.stat(config.ALIASES_FILE).st_mtime
    except OSError:
        mtime = 0
    if _cache["groups"] is None or _cache["mtime"] != mtime:
        extra = []
        if mtime:
            try:
                with open(config.ALIASES_FILE, encoding="utf-8") as f:
                    extra = [list(g) for g in json.load(f) if isinstance(g, list)]
            except (OSError, ValueError, TypeError):
                extra = []
        _cache["groups"] = [{registrable(d) for d in g} for g in ALIASES + extra]
        _cache["mtime"] = mtime
    return _cache["groups"]


def same_service(site_host, sender_domain):
    a, b = registrable(site_host), registrable(sender_domain)
    if not a or not b or a in RULES or b in RULES:   # never match on a bare public suffix
        return False
    return a == b or any(a in g and b in g for g in _groups())
