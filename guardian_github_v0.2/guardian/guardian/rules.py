"""Custom detection rules: a tiny, safe cousin of YARA.

WHAT: a rule is "if these text patterns appear in a file, raise a flag".
Rules live in a plain JSON file (rules.json in the Guardian data folder) so
you can add your own WITHOUT touching Python code. This is how real products
ship new detections between program updates.

WHY literal strings only (no regular expressions): a user-supplied regex can
be written to run for hours on a crafted file ("ReDoS"), freezing the scanner.
Plain substring search cannot do that. Safe by design beats powerful here.

Severity levels feed the AI score (see ai_score.py):
    1 = informational   2 = suspicious   3 = strongly malicious
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

from . import config

def _j(*pieces: str) -> str:
    """Join pattern pieces AT RUNTIME.

    WHY: if a pattern is written in one piece, this very source file contains
    it and scanners (including Guardian) flag the rules file itself. Splitting
    with "a" + "b" is NOT enough: Python's compiler merges constants and writes
    the whole pattern into the compiled .pyc file, which gets flagged instead.
    A function call is not merged, so the pattern never exists in either file.
    """
    return "".join(pieces)


DEFAULT_RULES = [
    {"name": "PHP-webshell-eval-base64", "severity": 3, "match": "any",
     "description": "PHP code that decodes and runs a request parameter (a webshell).",
     "strings": [_j("eval(base64", "_decode($_")]},
    {"name": "Reverse-shell-one-liner", "severity": 3, "match": "any",
     "description": "Command that hands a remote attacker a shell on this machine.",
     "strings": [_j("bash -i >", "& /dev/tcp/"), _j("nc -e /bin/", "sh"), _j("nc -e /bin/", "bash")]},
    {"name": "PowerShell-download-cradle", "severity": 2, "match": "all", "nocase": True,
     "description": "PowerShell that downloads text from the internet and runs it.",
     "strings": [_j("new-object net.", "webclient"), _j("download", "string")]},
    {"name": "Ransom-note-phrases", "severity": 2, "match": "any", "nocase": True,
     "description": "Wording typical of ransomware notes.",
     "strings": [_j("your files have been ", "encrypted"), _j("to decrypt your ", "files"), _j("send bitcoin ", "to")]},
    {"name": "Crypto-miner-config", "severity": 2, "match": "any", "nocase": True,
     "description": "Configuration typical of hidden cryptocurrency miners.",
     "strings": [_j("stratum+", "tcp://"), _j("stratum+", "ssl://")]},
]

MAX_RULES = 500
MAX_STRINGS = 20
MAX_STRING_LEN = 200


@dataclass
class Rule:
    name: str
    severity: int
    match_all: bool
    nocase: bool
    needles: tuple        # bytes patterns (already lower-cased if nocase)
    description: str
    extensions: tuple     # optional: only apply to these file extensions


def _validate(raw) -> Optional[Rule]:
    """Turn one JSON object into a Rule, or None if it is malformed.

    WHY so strict: rules files can be edited by hand or downloaded. A bad
    entry must be ignored, never crash the scanner or slow it down.
    """
    try:
        name = str(raw["name"])[:80]
        severity = int(raw["severity"])
        strings = raw["strings"]
        if severity not in (1, 2, 3):
            return None
        if not isinstance(strings, list) or not 1 <= len(strings) <= MAX_STRINGS:
            return None
        nocase = bool(raw.get("nocase", False))
        needles = []
        for s in strings:
            if not isinstance(s, str) or not 1 <= len(s) <= MAX_STRING_LEN:
                return None
            b = s.encode("utf-8", errors="ignore")
            needles.append(b.lower() if nocase else b)
        exts = tuple(str(e).lower() for e in raw.get("extensions", []))[:20]
        return Rule(name, severity, raw.get("match", "any") == "all", nocase,
                    tuple(needles), str(raw.get("description", ""))[:300], exts)
    except (KeyError, TypeError, ValueError):
        return None


class Rules:
    def __init__(self, raw_rules: list) -> None:
        self.rules = [r for r in (_validate(x) for x in raw_rules[:MAX_RULES]) if r]
        self.version = hashlib.sha256(
            json.dumps(raw_rules, sort_keys=True).encode()).hexdigest()[:16]

    @classmethod
    def load(cls) -> "Rules":
        path = config.rules_path()
        if not path.exists():
            path.write_text(json.dumps(DEFAULT_RULES, indent=2))
        try:
            raw = json.loads(path.read_text())
            if not isinstance(raw, list):
                raise ValueError("rules file must contain a list")
        except (json.JSONDecodeError, OSError, ValueError):
            raw = DEFAULT_RULES
        return cls(raw)

    def match(self, name: str, data: bytes) -> list:
        """Return [(rule, ...)] for every rule that fires on this data."""
        if not self.rules:
            return []
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        lowered = None
        hits = []
        for r in self.rules:
            if r.extensions and ext not in r.extensions:
                continue
            if r.nocase:
                if lowered is None:
                    lowered = data.lower()
                hay = lowered
            else:
                hay = data
            found = [n in hay for n in r.needles]
            if (all(found) if r.match_all else any(found)):
                hits.append(r)
        return hits
