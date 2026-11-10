"""Advisor: the "Jarvis" layer that explains results in plain language.

Two modes:
  1. explain()  works offline, using built-in templates.
  2. ask_ai()   optional: sends a SHORT SUMMARY (never the file itself) to an
     AI model for a friendlier, more detailed answer. It only runs if you set
     the ANTHROPIC_API_KEY environment variable.

WHY never send the file: privacy. Users' documents must not leave their
computer without clear consent. Sending only the verdict, reasons and file
type is enough for a good explanation.
"""

import json
import os
import urllib.request

from .scanner import ScanResult

ADVICE = {
    "suspicious": "Be careful. This file has traits common in malware but may be "
                  "harmless. Only open it if you know exactly who sent it and why. "
                  "You can check it at virustotal.com before opening. If you are sure "
                  "it is safe, run 'guardian allow <file>' so it stops being flagged.",
    "clean": "No known threat or suspicious traits found. No scanner is perfect, "
             "so stay careful with files from unknown senders.",
    "error": "The file could not be read, so it was not checked.",
}

AFTER_RUNNING = ("If you already opened or ran it, disconnect from the internet, run a full "
                 "scan with your main antivirus, and change passwords for accounts you used "
                 "on this computer recently.")


def advice_for(r: ScanResult) -> str:
    if r.verdict == "malicious":
        # Say what actually happened to the file: never claim it was handled
        # when it was not (an earlier version got this wrong).
        if r.quarantined:
            head = "Do NOT open this file. It was moved to quarantine, so it is isolated. "
        else:
            head = ("Do NOT open this file. It is still where it was found. Isolate it "
                    "with 'guardian scan <path> -q'. ")
        return head + AFTER_RUNNING
    return ADVICE.get(r.verdict, "")


def explain(r: ScanResult) -> str:
    lines = [f"File: {r.path}", f"Verdict: {r.verdict.upper()}  (risk score {r.score:.0%})"]
    if r.signature:
        lines.append(f"Known threat: {r.signature}")
    for reason in r.reasons:
        lines.append(f" - {reason}")
    lines.append(advice_for(r))
    return "\n".join(lines)


def ask_ai(r: ScanResult, question: str = "Explain this result simply and tell me what to do.") -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return "Set the ANTHROPIC_API_KEY environment variable to enable AI explanations.\n\n" + explain(r)
    summary = {"file_name": os.path.basename(r.path), "verdict": r.verdict,
               "risk_score": round(r.score, 2), "signature": r.signature,
               "reasons": r.reasons, "quarantined": r.quarantined}
    body = json.dumps({
        "model": "claude-haiku-5-5",
        "max_tokens": 500,
        "system": "You are a calm security assistant. Explain scan results to a "
                  "non-technical person in under 150 words. Never claim certainty.",
        "messages": [{"role": "user",
                      "content": f"{question}\n\nScan summary: {json.dumps(summary)}"}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body,
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return data["content"][0]["text"]
    except Exception as e:
        return f"(AI explanation unavailable: {e})\n\n" + explain(r)
