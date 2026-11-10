"""Updater: pull fresh threat intelligence from the internet.

This is how Guardian "learns from today's threats". Security groups publish
free lists of known-bad file hashes and URLs. We download them and merge them
into the local signature database.

IMPORTANT SAFETY NOTES (read the guide, section 7):
  * Only download from sources you trust, over HTTPS.
  * Treat everything downloaded as DATA, never as code. We only parse text
    lines; we never execute anything we fetch. An updater that runs
    downloaded code is exactly how attackers hijack security software.
  * Feed locations change and some now require a free account/API key.
    Edit feeds.json in the Guardian data folder to match the current
    documentation of each provider.
"""

import json
import urllib.request

from . import config
from .signatures import SignatureDB

# Starting list. abuse.ch (MalwareBazaar / URLhaus) publishes free feeds, but
# check their site for current URLs and any API-key requirement before use.
DEFAULT_FEEDS = [
    {"name": "malwarebazaar-recent-sha256", "kind": "hashes",
     "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/"},
    {"name": "urlhaus-online-urls", "kind": "urls",
     "url": "https://urlhaus.abuse.ch/downloads/text_online/"},
]

MAX_DOWNLOAD = 50 * 1024 * 1024  # never accept more than 50 MB from a feed


def load_feeds() -> list[dict]:
    p = config.feeds_path()
    if not p.exists():
        p.write_text(json.dumps(DEFAULT_FEEDS, indent=2))
    return json.loads(p.read_text())


def _fetch_lines(url: str, timeout: int = 30) -> list[str]:
    if not url.lower().startswith("https://"):
        raise ValueError("Refusing non-HTTPS feed")
    req = urllib.request.Request(url, headers={"User-Agent": "Guardian/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(MAX_DOWNLOAD + 1)
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError("Feed too large")
    return [ln.strip() for ln in raw.decode("utf-8", errors="ignore").splitlines()
            if ln.strip() and not ln.startswith("#")]


def update_all() -> dict:
    """Download every feed. One failing feed never stops the others."""
    db = SignatureDB.load()
    report = {}
    for feed in load_feeds():
        try:
            lines = _fetch_lines(feed["url"])
            if feed["kind"] == "hashes":
                added = db.add_hashes({ln: feed["name"] for ln in lines})
            else:
                added = db.add_urls(set(lines))
            report[feed["name"]] = f"ok, {added} new entries"
        except Exception as e:  # network errors are normal; report, do not crash
            report[feed["name"]] = f"failed: {e}"
    db.save()
    return report
