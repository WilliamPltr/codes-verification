"""Find a verification code or a sign-in link in an email. Plain heuristics: regular expressions and a score.

analyze(subject, text, links) -> {"code": str|None, "link": str|None, "score": int}
- text:  the email body (text/plain, or HTML converted to text)
- links: list of (url, link text) taken from the HTML

The email is untrusted input: it is only ever matched against regular expressions, never executed or interpreted.
"""
import html.parser, re

KW_STRONG = re.compile(
    r"(verification|v[ée]rification|security|s[ée]curit[ée]|one[- ]?time|login|log[- ]?in|sign[- ]?in|connexion|"
    r"confirmation|authenti\w*|access|acc[èe]s|2fa|otp|pin|passcode|temporary|temporaire|single[- ]use|usage unique|"
    r"verify|v[ée]rifier|validation)?\s*(code|pin|otp|passcode|token|cl[ée])\b|\b(otp|passcode|2fa|mfa)\b|验证码|認証コード|인증",
    re.I)
# the subject has to be about signing in (not about an order, a sale...)
KW_SUBJECT = re.compile(
    r"\bcode\b|\botp\b|passcode|\bpin\b|v[ée]rif|connexion|se connecter|sign[- ]?in|log[- ]?in|identit[ée]|"
    r"security code|code de s[ée]curit|authenti|r[ée]initialis\w* (de |du |votre |ton )?(mot de passe|password)|reset (your )?password|2fa|mfa|one[- ]?time|magic link|lien magique|"
    r"confirm\w* (votre |your |l'|ton )?(adresse |e-?mail|email|compte|account|inscription|identit)|activ\w* (votre |your )?(compte|account)|"
    r"验证码", re.I)
NEG_SUBJECT = re.compile(r"commande|order|facture|invoice|re[çc]u|receipt|livraison|delivery|newsletter|promo|soldes|offre", re.I)
NEG_NEAR = re.compile(r"promo|r[ée]duction|discount|coupon|remise|offre|voucher|parrain|referral|%|code postal|zip", re.I)
NEG_BEFORE = re.compile(
    r"(n[°o]\.?|num[ée]ro|number|commande|order|r[ée]f[ée]rence|ref\.?|facture|invoice|ticket|client|dossier|"
    r"t[ée]l\.?|phone|siret|siren|iban|bic|tva|prix|price|total|montant|amount|zip|postal|cp|#)\s*[:\-]?\s*$", re.I)
CURRENCY = re.compile(r"[€$£¥]|\b(eur|usd|gbp)\b", re.I)
CAND = re.compile(r"(?<![\w@/.#:+-])(\d{3}[ -]\d{3}|\d{4,8}|[A-Z0-9]{5,10})(?![\w@/.:%-]|,\d)")

LINK_GOOD = re.compile(
    r"verif|v[ée]rif|confirm|sign[-_ ]?in|log[-_ ]?in|connexion|connecter|magic|auth|activat|activer|valider|validate|"
    r"token|passwordless|one[-_]?time|approve|approuver", re.I)
LINK_BAD = re.compile(
    r"unsubscribe|d[ée]sinscri|desabonn|d[ée]sabonn|preferences|pr[ée]f[ée]rences|privacy|confidentialit|help|aide|support|"
    r"facebook|twitter|(?<![\w.-])x\.com|linkedin|instagram|youtube|tiktok|apps\.apple|play\.google|\.png|\.jpg|\.gif|tracking|"
    r"view.?in.?browser|navigateur|mailto:|legal|terms|cgu|cgv|faq|contact|report|signaler|not.?you|pas.?vous|secure.?account|"
    r"s[ée]curiser|block", re.I)


def _norm(code):
    return re.sub(r"[ -]", "", code)


def _score(text, m, subject_part):
    code = m.group(1)
    raw = _norm(code)
    has_digit = any(c.isdigit() for c in raw)
    has_alpha = any(c.isalpha() for c in raw)
    if not has_digit:                       # words in capitals (HELLO, PARIS...) are never codes
        return -99
    if has_alpha and not (5 <= len(raw) <= 8):
        return -99
    s = 0
    start, end = m.start(1), m.end(1)
    before = text[max(0, start - 80):start]
    near = text[max(0, start - 40):start]
    after = text[end:end + 40]
    if KW_STRONG.search(near):
        s += 6
    elif KW_STRONG.search(before) or KW_STRONG.search(after[:30]):
        s += 4
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line = text[line_start:line_end if line_end != -1 else len(text)].strip()
    if _norm(line) == raw:
        s += 3                               # the code is alone on its line
    if subject_part:
        s += 2
    if len(raw) == 4 and re.fullmatch(r"(19|20)\d\d", raw):
        s -= 8                               # a year
    if NEG_BEFORE.search(text[max(0, start - 30):start]):
        s -= 8                               # order number, phone number...
    if CURRENCY.search(text[max(0, start - 6):start]) or CURRENCY.search(after[:6]):
        s -= 8                               # an amount of money
    if len(raw) > 8 and not has_alpha:
        s -= 6
    if len(raw) in (6, 8) and not has_alpha:
        s += 1
    if NEG_NEAR.search(text[max(0, start - 50):end + 20]):
        s -= 8                               # promo code, postcode
    if len(raw) == 5 and not has_alpha and re.match(r"\s+[A-ZÉ][a-zé]+", after):
        s -= 8                               # French postcode followed by a city
    if has_alpha and re.fullmatch(r"[A-Z]{2,}\d{1,2}", raw):
        s -= 8                               # SUMMER10, XMAS25: promo codes
    return s


# "code: X", "code is X", "验证码为：X": the next word is the code, even without digits (e.g. srXu)
EXPLICIT = re.compile(
    r"(?:\bcode\b|\bpin\b|\botp\b|passcode|验证码)[^\n.]{0,30}?(?:\bis\b|\best\b|:|：|为|=)\s*([A-Za-z0-9]{4,10})(?![\w@/.-])", re.I)


def _explicit_ok(tok):
    has_d, has_u, has_l = any(c.isdigit() for c in tok), any(c.isupper() for c in tok), any(c.islower() for c in tok)
    return has_d or (has_u and has_l and len(tok) <= 8) or (has_u and not has_l and 4 <= len(tok) <= 8)


NEG_QUALIF = re.compile(r"(entreprise|company|soci[ée]t[ée]|client|customer|postal|zip|produit|product|article|iban|bic|swift|naf|ape|"
                        r"fiscal|tva|vat|registration|immatricul|promo|cadeau|gift|parrain|referral|tracking|suivi|colis|douane|"
                        r"commande|order|r[ée]servation|booking)", re.I)


def find_code(subject, text):
    best, best_s = None, -99
    subj_ok = bool(KW_SUBJECT.search(subject or "")) and not NEG_SUBJECT.search(subject or "")
    for part in (subject or "", text or ""):
        for m in EXPLICIT.finditer(part):
            tok = m.group(1)
            if _explicit_ok(tok) and not (tok.isdigit() and re.fullmatch(r"(19|20)\d\d", tok)) \
                    and not NEG_NEAR.search(part[max(0, m.start() - 30):m.end() + 10]) \
                    and not NEG_QUALIF.search(part[max(0, m.start() - 20):m.start(1)]):
                s = (10 if subj_ok else 5) if not tok.isdigit() else _score(part, m, part is subject) + 2
                if s > best_s:
                    best, best_s = tok, s
    for part, is_subject in ((subject or "", True), (text or "", False)):
        for m in CAND.finditer(part):
            s = _score(part, m, is_subject)
            if s > best_s:
                best, best_s = _norm(m.group(1)), s
    if (best_s >= 6 and subj_ok) or best_s >= 10:
        return best, best_s
    return None, best_s


def find_link(subject, links):
    best, best_s = None, 0
    for url, label in links:
        if not url.lower().startswith("https://") or len(url) > 2000:
            continue
        hay = f"{label} {url}"
        if LINK_BAD.search(hay):
            continue
        s = 0
        if LINK_GOOD.search(label or ""):
            s += 5
        if LINK_GOOD.search(url):
            s += 3
        if s and len((label or "").strip()) <= 60:
            s += 1                           # a real button rather than a paragraph
        if s > best_s:
            best, best_s = url, s
    if best_s >= 5 and KW_SUBJECT.search(subject or "") and not NEG_SUBJECT.search(subject or ""):
        return best
    return None


def analyze(subject, text, links):
    code, score = find_code(subject, text)
    link = None if code else find_link(subject, links)
    return {"code": code, "link": link, "score": score}


class _HTML(html.parser.HTMLParser):
    """HTML -> readable text + links (url, text)."""
    BLOCK = {"p", "div", "br", "tr", "td", "li", "h1", "h2", "h3", "h4", "table", "section", "center"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.links, self._href, self._label, self._skip = [], [], None, [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script", "head", "title"):
            self._skip += 1
        if tag in self.BLOCK:
            self.out.append("\n")
        if tag == "a":
            self._href, self._label = dict(attrs).get("href"), []

    def handle_endtag(self, tag):
        if tag in ("style", "script", "head", "title") and self._skip:
            self._skip -= 1
        if tag in self.BLOCK:
            self.out.append("\n")
        if tag == "a" and self._href:
            self.links.append((self._href.strip(), " ".join("".join(self._label).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.out.append(data)
        if self._href is not None:
            self._label.append(data)


def html_to_text(h):
    p = _HTML()
    try:
        p.feed(h)
    except Exception:
        pass
    text = re.sub(r"[ \t ​‌‍﻿]+", " ", "".join(p.out))
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip(), p.links


def text_links(text):
    return [(u, "") for u in re.findall(r"https://[^\s<>\"')\]]+", text or "")]
