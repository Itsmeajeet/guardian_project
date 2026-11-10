"""URL checker: judge a link BEFORE you click it.

Two layers again: (1) a blocklist of known-bad addresses, (2) rules of thumb
that catch phishing links nobody has reported yet.
"""

import re
from urllib.parse import urlparse

from .signatures import SignatureDB

RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "work", "country"}
BRAND_WORDS = ("paypal", "google", "microsoft", "apple", "amazon", "netflix",
               "facebook", "instagram", "whatsapp", "bank", "sbi", "hdfc", "icici",
               "login", "verify", "secure", "update", "account")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}


def check_url(url: str, db: SignatureDB | None = None) -> tuple[int, list[str]]:
    """Return (risk 0-100, reasons)."""
    db = db or SignatureDB.load()
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    u = urlparse(url)
    host = (u.hostname or "").lower()
    risk, why = 0, []

    if url.lower() in db.bad_urls or host in db.bad_urls:
        return 100, ["Listed in a known-malicious URL database."]

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        risk += 35; why.append("Uses a raw IP address instead of a name.")
    if "@" in (u.netloc or ""):
        risk += 35; why.append("Contains '@' which can hide the real destination.")
    if "xn--" in host:
        risk += 30; why.append("Uses punycode, often for look-alike characters.")
    if u.scheme == "http":
        risk += 10; why.append("Not encrypted (http, not https).")
    labels = host.split(".")
    if len(labels) > 4:
        risk += 15; why.append("Unusually many subdomains.")
    if labels and labels[-1] in RISKY_TLDS:
        risk += 15; why.append(f"Domain ending '.{labels[-1]}' is frequently abused.")
    if host in SHORTENERS:
        risk += 15; why.append("Shortened link hides the real destination.")
    if len(url) > 100:
        risk += 10; why.append("Very long URL.")

    # Brand words in the host but not as the real registered domain,
    # e.g. "paypal.secure-login.example.com".
    registered = ".".join(labels[-2:]) if len(labels) >= 2 else host
    for word in BRAND_WORDS:
        if word in host and word not in registered.split(".")[0]:
            risk += 25
            why.append(f"Contains '{word}' but is not that company's domain.")
            break

    return min(risk, 100), why
