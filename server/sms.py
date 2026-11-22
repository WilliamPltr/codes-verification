"""Find a verification code in a text message (SMS). Same rules as emails: regular expressions only, never executed.

parse_sms(text) -> (code, domain) or None
- domain is the website the SMS declares for itself with the standard last line "@example.com #123456"
  (the format browsers and phones use for one-tap autofill), or "" when the SMS says nothing about a site.
"""
import re

from domains import registrable
from extract import analyze, NEG_NEAR, NEG_BEFORE

# "@example.com #123456", optionally followed by "%token" (Apple), optionally preceded by "<#>" (old Android)
ORIGIN = re.compile(r"(?m)^\s*(?:<#>\s*)?@([A-Za-z0-9.-]{3,253})\s+#([A-Za-z0-9-]{3,12})(?:\s+%\S+)?\s*$")
# "G-123456" (Google): letter prefix and dash, which the generic rules don't take for a code
PREFIXED = re.compile(r"\b[A-Z]{1,3}-(\d{4,8})\b")
KEYWORD = re.compile(r"code|otp|pin\b|passcode|mot de passe|verif|v[ée]rif|confirm|connexion|s[ée]curit|authenti|one.?time|2fa", re.I)
DIGITS = re.compile(r"(?<![\w.,/@#:+-])(\d{3}[ -]\d{3}|\d{4,8})(?![\w,/%@:-]|\.\d)")


def parse_sms(text):
    text = (text or "")[:1000]
    m = ORIGIN.search(text)
    if m:
        domain = m.group(1).lower().strip(".")
        if "." in domain and registrable(domain) != domain.split(".")[-1]:
            return re.sub(r"[ -]", "", m.group(2)), domain
    m = PREFIXED.search(text)
    if m and KEYWORD.search(text):
        return m.group(1), ""
    code = analyze("Code", text, [])["code"]   # the subject "Code" stands for: this message is about a code
    if code:
        return code, ""
    # a short message that talks about a code and holds exactly one number of 4 to 8 digits
    if len(text) <= 300 and KEYWORD.search(text):
        found = {re.sub(r"[ -]", "", m.group(1)) for m in DIGITS.finditer(text)
                 if not NEG_NEAR.search(text[max(0, m.start() - 30):m.end() + 15])
                 and not NEG_BEFORE.search(text[max(0, m.start() - 30):m.start()])}
        if len(found) == 1:
            return found.pop(), ""
    return None
