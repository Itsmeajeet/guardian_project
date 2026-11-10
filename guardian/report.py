"""Reports: save scan results as JSON (for programs) or HTML (for people).

SECURITY NOTE: file names and archive member names come from whoever made the
file, so they are UNTRUSTED. If we pasted a name like  <script>alert(1)</script>
straight into an HTML report, opening the report would run the attacker's code
(this is "cross-site scripting", XSS). html.escape() turns the dangerous
characters into harmless text. Never skip it.
"""

import dataclasses
import html
import json
import time
from pathlib import Path

CSS = """
body{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1d1d1b}
h1{font-size:22px} .meta{color:#5f5e5a;margin-bottom:1.5rem}
.card{border:1px solid #d3d1c7;border-radius:8px;padding:.8rem 1rem;margin:.7rem 0}
.malicious{background:#fceaea;border-color:#e24b4a}.suspicious{background:#faeeda;border-color:#ba7517}
.v{font-weight:600;text-transform:uppercase;font-size:12px}.p{font-family:ui-monospace,monospace;word-break:break-all}
ul{margin:.4rem 0 0 1.2rem;padding:0}
"""


def to_json(flagged: list, total: int, target: str) -> str:
    return json.dumps({
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "target": target,
        "files_scanned": total, "flagged": [dataclasses.asdict(r) for r in flagged],
    }, indent=2)


def to_html(flagged: list, total: int, target: str) -> str:
    e = html.escape
    cards = []
    for r in flagged:
        reasons = "".join(f"<li>{e(x)}</li>" for x in r.reasons)
        sig = f"<div>Known threat: <b>{e(r.signature)}</b></div>" if r.signature else ""
        cards.append(
            f'<div class="card {e(r.verdict)}"><div class="v">{e(r.verdict)} '
            f'&middot; risk {r.score:.0%}</div><div class="p">{e(r.path)}</div>{sig}'
            f'<ul>{reasons}</ul></div>')
    body = "".join(cards) or "<p>Nothing suspicious was found.</p>"
    return (f"<!doctype html><meta charset='utf-8'><title>Guardian report</title>"
            f"<style>{CSS}</style><h1>Guardian scan report</h1>"
            f"<div class='meta'>Target: {e(target)}<br>{total} files scanned, "
            f"{len(flagged)} flagged &middot; {e(time.strftime('%Y-%m-%d %H:%M'))}</div>{body}")


def write_report(flagged: list, total: int, target: str, out_path: str) -> Path:
    out = Path(out_path)
    text = to_json(flagged, total, target) if out.suffix.lower() == ".json" \
        else to_html(flagged, total, target)
    out.write_text(text, encoding="utf-8")
    return out
