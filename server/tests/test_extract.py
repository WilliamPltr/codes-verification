"""Detection tests: realistic emails (anonymized) and the traps they come with."""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from extract import analyze, html_to_text

# (subject, text, links, expected code, link expected?)
FOUND = [
    ("[GitHub] Sudo email verification code",
     "Hey!\nHere is your GitHub sudo authentication code:\n16523749\nThis code is valid for 15 minutes", [], "16523749", False),
    ("Code de sécurité pour votre compte", "Utilisez ce code valable 15 minutes : 8894 pour poursuivre votre démarche",
     [], "8894", False),
    ("919725 est votre code de vérification PIN - Billetterie", "Votre code PIN : 919725", [], "919725", False),
    ("Your code is: 35GQKN", "Use this code to sign in: 35GQKN", [], "35GQKN", False),
    ("Votre code de connexion - Alumni - 906483", "Votre code de connexion est le 906483.", [], "906483", False),
    ("--验证码", "邮箱验证码为：srXu，有效时长5分钟。", [], "srXu", False),
    ("Your Bitwarden Verification Code", "Your two-step verification code is: 800494", [], "800494", False),
    ("Votre code de vérification", "Votre code : 123 456", [], "123456", False),
    ("Your sign-in code (codes test page)", "Your sign-in code is 482913\n\nIt expires in 10 minutes.", [], "482913", False),
    ("Confirm your email address", "Click below to confirm",
     [("https://ex.com/verify?t=abc", "Confirm my address"), ("https://ex.com/unsubscribe", "Unsubscribe")], None, True),
]

# nothing should be detected in these
TRAPS = [
    ("Votre commande est confirmée !", "Commande n° 123456789, total 49,99 €, code postal 75003 Paris"),
    ("Your photo gallery", "Get 10% off with the code SUMMER10"),
    ("Welcome aboard", "Example Ltd (company code: HE430310, registered office...)"),
    ("Order confirmation for CLUB", "Venue: 12 rue X, 75003 Paris. Door code 2026"),
    ("Your booking is confirmed", "Booking 482913 for 12/11/2026 at 19:30"),
    ("Stronger than a password", "Discover our new app", ),
    ("Your November invoice", "Invoice no. 2026-1188, amount 12.00 €, customer code 558812"),
]


class Detection(unittest.TestCase):
    def test_found(self):
        for subject, text, links, code, link in FOUND:
            with self.subTest(subject=subject):
                r = analyze(subject, text, links)
                self.assertEqual(r["code"], code)
                self.assertEqual(bool(r["link"]), link)

    def test_traps(self):
        for subject, text in TRAPS:
            with self.subTest(subject=subject):
                r = analyze(subject, text, [("https://t.example.com/r/?id=1", "click here")])
                self.assertIsNone(r["code"])
                self.assertIsNone(r["link"])

    def test_html(self):
        text, links = html_to_text('<p>Code: <b>654321</b></p><a href="https://x.fr/login?t=1">Sign in</a><style>.a{}</style>')
        self.assertIn("654321", text)
        self.assertNotIn(".a{}", text)
        self.assertEqual(links, [("https://x.fr/login?t=1", "Sign in")])


if __name__ == "__main__":
    unittest.main()
