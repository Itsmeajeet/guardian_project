"""A simple window app using tkinter.

WHY tkinter: it ships with Python on Windows and macOS (and most Linux
installs), so the app opens on every desktop OS with zero extra downloads.
It is not pretty. Later you can replace this ONE file with a modern interface
(Flutter, Electron, Qt, Tauri) without touching the scanner, because the
scanner never imports anything from here. Keeping "engine" and "interface"
separate is the most important design rule in this project.
"""

import threading
from pathlib import Path


def run() -> None:
    import tkinter as tk
    from tkinter import filedialog, scrolledtext

    from .advisor import explain
    from .scanner import scan_path

    root = tk.Tk()
    root.title("Guardian")
    root.geometry("720x480")

    out = scrolledtext.ScrolledText(root, wrap="word")
    out.pack(fill="both", expand=True, padx=8, pady=8)
    status = tk.StringVar(value="Ready.")
    tk.Label(root, textvariable=status, anchor="w").pack(fill="x", padx=8)

    def log(text: str) -> None:
        # tkinter is not thread-safe, so background threads hand work to the
        # main thread with after().
        root.after(0, lambda: (out.insert("end", text + "\n"), out.see("end")))

    def do_scan(target: str) -> None:
        count = bad = 0
        for r in scan_path(Path(target)):
            count += 1
            if r.verdict in ("suspicious", "malicious"):
                bad += 1
                log(explain(r) + "\n")
        root.after(0, lambda: status.set(f"Done: {count} files, {bad} flagged."))

    def pick(folder: bool) -> None:
        target = filedialog.askdirectory() if folder else filedialog.askopenfilename()
        if target:
            status.set(f"Scanning {target} ...")
            threading.Thread(target=do_scan, args=(target,), daemon=True).start()

    bar = tk.Frame(root)
    bar.pack(fill="x", padx=8, pady=(0, 8))
    tk.Button(bar, text="Scan a file", command=lambda: pick(False)).pack(side="left")
    tk.Button(bar, text="Scan a folder", command=lambda: pick(True)).pack(side="left", padx=6)
    root.mainloop()
