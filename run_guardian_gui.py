"""Tiny launcher used for packaging: PyInstaller needs a plain script to start from."""

from guardian.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["gui"]))
