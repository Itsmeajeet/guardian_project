# Guardian: Build Your Own Security App (Learning Guide)

This guide goes with the `guardian` project. It explains **what** every part does, **why** it is written that way, and **how** you can grow it into a real product. Read it next to the code.

> **Honest note first.** Guardian is a *learning-grade* scanner. It really works (it detects the standard EICAR test file, disguised programs, suspicious scripts, risky links) but it is **not** a replacement for Microsoft Defender, Bitdefender or similar. Real products have large analyst teams, kernel-level drivers and years of data. Use Guardian to learn and as a starting point for your own product, and keep a proven antivirus running on your real computer.

---

## 1. The big picture: how any app is built

Every app, antivirus or not, is the same five layers:

| Layer | Question it answers | In Guardian |
|---|---|---|
| **Engine / logic** | What does the app actually *do*? | `scanner.py`, `heuristics.py`, `ai_score.py` |
| **Data / storage** | What does it remember? | `signatures.py`, `quarantine.py`, `config.py` (JSON files) |
| **Network** | Does it talk to the internet? | `updater.py`, `advisor.py` |
| **Interface** | How does a human use it? | `cli.py` (text), `gui.py` (window) |
| **Packaging** | How do others install it? | `pyproject.toml`, PyInstaller (section 8) |

**The most important rule:** keep the *engine* separate from the *interface*. `scanner.py` never imports `gui.py`. That is why you can later replace the window with a phone app and keep the same brain.

---

## 2. The bases of every antivirus / anti-malware product

Every security product, from a free tool to an enterprise suite, stacks the same detection ideas. Guardian has a small version of each.

1. **Signatures (fingerprints).** Compute a hash of a file and look it up in a list of known-bad hashes. *Fast, almost no false alarms, but only catches threats already seen.* → `hashing.py`, `signatures.py`
2. **Heuristics (rules of thumb).** Look at *how a file looks or behaves*: fake extensions, packed code, download-and-run commands. *Catches new threats, but can false-alarm.* → `heuristics.py`
3. **Machine learning (scoring).** Instead of one rule deciding, combine many weak signals into a probability. *Learns from examples and improves.* → `ai_score.py`
4. **Behaviour monitoring.** Watch programs *while running* (is this "calculator" suddenly encrypting all my files?). Needs deep OS access (drivers). Not in Guardian; this is where big products spend most of their effort.
5. **Reputation and cloud intelligence.** "Millions of users have this file and it is fine" vs "first seen 10 minutes ago". Needs a server and many users.
6. **Real-time protection.** Check files *the moment* they appear, not only when you press Scan. → `watcher.py`
7. **Containment and response.** Isolate (quarantine), explain, and let the user undo. → `quarantine.py`, `advisor.py`
8. **Web protection.** Judge links before you visit them. → `urlcheck.py`
9. **Updates.** Threats change daily; a scanner that does not update is nearly useless within weeks. → `updater.py`

**Defence in depth** is the principle tying these together: no single layer is perfect, so you stack several different ones.

---

## 3. Step-by-step: how this project was built

Follow these same steps for any app you build later.

**Step 1. Define the problem in one sentence.**
"Tell the user whether a file or link is dangerous, explain why, and contain it." Everything you add must serve this sentence.

**Step 2. Choose the language and tools.**
Python, standard library only. *Why:* readable, runs on Windows/macOS/Linux, huge security community, zero installs. The trade-off is speed and that users need Python (solved by packaging, section 8).

**Step 3. Build the smallest working engine first.**
`hashing.py` → `signatures.py` → `scanner.py`. At this point you can already detect a known-bad file. Always get one thing working end-to-end before adding more.

**Step 4. Add a way to test it safely.**
You must never test with real malware. The **EICAR test string** is a harmless text that every antivirus agrees to flag. That is why `signatures.py` seeds it.

**Step 5. Add smarter detection.**
`heuristics.py` (rules) then `ai_score.py` (scoring). Each rule becomes a *number*, not a verdict, so the model can weigh them.

**Step 6. Add the actions around detection.**
Quarantine, folder watcher, URL checker. Detection alone is not protection; the app must *do* something safe about it.

**Step 7. Add the interface.**
Command line first (easy to test and script), window second. Both only *call* the engine.

**Step 8. Write tests.**
`tests/test_basic.py`. In security software a silent failure is dangerous, so every behaviour you rely on gets a test.

**Step 9. Add updates and the AI helper.**
`updater.py` pulls fresh threat lists; `advisor.py` explains results.

**Step 10. Package and ship.** Section 8.

---

## 4. Code tour: what each file does and why

### `config.py`: one place for paths and settings
All other files ask this file "where do I store things?". `Path.home()` is a standard-library function that finds the user's home folder on *any* OS, which is the secret to cross-platform code: **never hard-code `C:\` or `/home/`**. The `GUARDIAN_HOME` environment variable lets tests use a throw-away folder.

### `hashing.py`: fingerprints and randomness
- `sha256_file` reads in 1 MB chunks so a huge file never exhausts memory.
- `shannon_entropy` measures randomness (0 to 8). Packed/encrypted code looks random, so high entropy in a program is a weak warning sign.

### `signatures.py`: the known-bad database
A Python dictionary `{hash: threat name}` saved as JSON. Lookup is instant because dictionaries use hashing internally. It also stores bad URLs. A corrupt file is ignored rather than crashing, because **a security tool must fail safe**.

### `heuristics.py`: the rules
Each rule has a real-world reason:
- *Double extension* (`invoice.pdf.exe`): hides a program inside a "document" name.
- *Right-to-left override* character: reverses how a name is *displayed*.
- *Magic numbers*: the first bytes of a file reveal its true type (`MZ` = Windows program, `\x7fELF` = Linux program). A "photo.jpg" starting with `MZ` is lying.
- *Suspicious script commands*: patterns such as encoded PowerShell or `curl … | sh` are how malware downloads and launches its payload.
- *Macros in Office files*: a classic infection route.
- *Programs in temp or hidden locations*.

It returns `(features, reasons)`: numbers for the model, sentences for the human.

### `ai_score.py`: the learning part
Logistic regression: `probability = sigmoid(bias + Σ weight × feature)`.
- `DEFAULT_MODEL` weights are hand-set from security knowledge, so the app is useful on day one.
- `train()` uses gradient descent: for each labelled example, `weight += learning_rate × error × feature`. Repeat. That one idea powers much of modern machine learning.
- `top_factors()` returns *why* the score is high. **Explainability** builds user trust and helps you debug false alarms.

### `scanner.py`: the decision-maker
Runs the layers in order of certainty: signature first (certain), then AI score. `scan_path` is a *generator* (`yield`), so results appear live during a long scan. It skips symbolic links to avoid loops and escapes out of the target folder.

### `quarantine.py`: containment
Moves, renames to `.quar`, removes execute permission, records the original location. Never deletes, because detections can be wrong, and **restore** must always be possible.

### `watcher.py`: real-time guarding
Polls a folder and scans new files once their size stops changing (browsers write downloads gradually, and scanning half a file gives wrong answers). Production tools use OS-level notifications instead of polling.

### `urlcheck.py`: link safety
Blocklist first, then scoring rules: raw IP hosts, `@` tricks, punycode look-alikes, brand words in the wrong place (`paypal.secure-login.example.xyz`), risky endings, shorteners.

### `updater.py`: staying current
Downloads text feeds of known-bad hashes/URLs over HTTPS only, with a size cap, and treats them purely as **data**. Never run downloaded code in an updater. Attackers target security updaters because they run with high trust.

### `advisor.py`: the "Jarvis" layer
Offline templates explain each verdict. Optionally, with your own `ANTHROPIC_API_KEY`, it sends only a *summary* (never the file) to an AI model for a friendlier explanation. This is where a conversational assistant lives; you can later add voice input and chat.

### `cli.py` and `gui.py`: interfaces
`argparse` builds commands (`scan`, `watch`, `url`, `update`, `explain`, `train`, `quarantine`, `gui`). `tkinter` ships with Python on desktop OSes, so the window needs no downloads. GUI scanning runs in a background thread so the window never freezes.

---

## 4b. Advanced features added in v0.2: what, why, how

Each feature below follows the same pattern: the problem, the design, the attack it stops, and the programming concept you learn from it.

### Archive scanning (`archive.py`)
- **Problem:** malware rarely arrives bare; it arrives as `invoice.zip` because mail filters ignore what is inside.
- **Design:** open the archive and read each member **into memory**, run the same checks on it, and recurse into nested archives (depth 2).
- **Attacks it defends against:**
  - *Zip-slip*: a member named `../../startup/evil.exe` writes outside the folder you extract to. We never extract to disk, so there is nothing to escape.
  - *Zip bomb*: a 40 KB file that expands to terabytes. We cap member count, size per member, total size and depth, and flag extreme compression ratios.
  - *Lying headers*: an archive can claim a small size and deliver a huge one. We read at most the limit plus one byte and see what we really got.
- **Concept:** **resource limits**. Any code that reads untrusted data needs a budget for time, memory and depth.
- **Concept:** **dependency injection**. `inspect()` receives an `evaluate` function instead of importing the scanner, which avoids a circular import and makes the module easy to test.

### Custom rules (`rules.py`)
- **Problem:** new threats appear daily; you cannot ship a new program version for each one.
- **Design:** detections live in `rules.json` (data, not code). A rule is a name, a severity (1-3) and literal text patterns. Severity feeds the AI score: 1 is informational, 2 pushes a file to *suspicious*, 3 to *malicious*.
- **Why literal strings and not regular expressions:** a hand-crafted regex can run for hours on a crafted file ("ReDoS"). Plain substring search cannot. Safe by design beats powerful.
- **Concept:** **validate everything that comes from outside**. `_validate()` rejects bad entries and enforces length limits; a corrupt file falls back to defaults instead of crashing.

### The `Engine` class (`scanner.py`)
- **Problem:** loading signatures, rules and the model from disk for *every file* is slow.
- **Design:** load once into an `Engine`, then judge many files. `Engine.stamp()` is a fingerprint of everything the engine knows.
- **Concept:** **separating setup from work**, and building a **cache key** that changes whenever the answer could change.

### Parallel scanning and the cache (`scanner.py`, `history.py`)
- **Parallel:** scanning is mostly waiting for the disk and hashing, which release Python's global lock, so a `ThreadPoolExecutor` genuinely speeds up big folders. Files are queued 64 at a time so a million-file scan does not eat memory.
- **Cache:** a file with the same path, size and modified-time, judged by an engine with the same stamp, is not rescanned. Update the signatures, retrain the model, edit a rule or allowlist a file, and the stamp changes, so old answers are never reused wrongly.
- **Concept:** **cache invalidation** ("one of the two hard problems in computer science"). Only the main thread touches SQLite, because a connection must not be shared across threads.

### History in SQLite (`history.py`)
- **Why a database and not JSON:** history grows without limit and we need questions answered ("last 10 scans?"). SQLite ships inside Python, needs no server, survives crashes and runs on every OS.
- **Security lesson:** every value goes in through `?` placeholders. File names are attacker-controlled; pasting them into SQL text would allow **SQL injection**. A test (`test_sql_injection_in_filename_is_harmless`) proves it.

### Reports (`report.py`)
- **Security lesson:** a file can be named `<script>alert(1)</script>.exe`. Pasting that into an HTML report would run the attacker's code when you open the report (**cross-site scripting, XSS**). `html.escape()` makes it inert, and a test checks it.
- **Concept:** names, paths and archive contents are **untrusted input** everywhere, including in your own reports.

### Allowlist (`allowlist.py`)
- **Problem:** every detector makes mistakes. A nagging false alarm teaches users to ignore warnings, or to uninstall the tool.
- **Design:** allowlist by **hash**, so if malware swaps the file, the exemption disappears. It can cancel heuristic verdicts but never a known-malware signature.
- **Concept:** **false positives are a product problem**, not just a technical one.

### Startup audit (`autoruns.py`)
- **Problem:** after getting in, malware wants to survive a reboot ("persistence"), so it adds itself to the startup places.
- **Design:** list those places per OS (Windows Run keys, macOS LaunchAgents, Linux autostart / systemd / cron), then judge each command with the same malware-pattern list used for scripts.
- **Design choice:** it is **read-only**. Deleting a startup entry blindly can break a real program, so the human decides.
- **Concept:** **platform-specific code behind one interface**. `collect()` takes the platform and home folder as parameters so tests can fake them.

### Reports of real bugs found while building (read these, they are the best lessons)
1. **A scanner flagged its own compiled file.** The rule patterns were split in the source (`"a" + "b"`), so the `.py` file was clean, yet scanning Guardian's own folder flagged `rules.cpython-313.pyc`. Python's compiler merges constants, so the compiled cache contained the full pattern. Fix: join the pieces at runtime inside a function call. The same trap applies to the EICAR string, and a real antivirus on your PC can flag a `.pyc` for exactly this reason.
2. **An invisible character in source code.** A hidden "right-to-left override" character had ended up in a source file. That is the **"Trojan Source"** attack: invisible characters can make code read differently from how it runs. Fix: write it as the visible escape `\u202e`, and scan your own repository for bidi characters.
3. **A test that was wrong, not the code.** Test files in a temp folder scored higher (programs in temp folders are riskier), so a test expecting "suspicious" saw "malicious". Lesson: when a test fails, ask whether the test or the code is wrong before changing either.
4. **An advice message that lied.** Version 0.1 told users a file "has been (or should be) quarantined" even when it had not. Now the result carries a `quarantined` flag and the message says what really happened. **Never let your UI claim an action that did not occur.**

---

## 5. Run it on your PC (Windows, macOS, Linux)

1. Install Python 3.10 or newer from python.org.
2. Open a terminal in the `guardian` folder.
3. Run the tests: `python -m unittest discover tests`
4. Scan something: `python -m guardian scan C:\Users\you\Downloads` (Windows) or `python -m guardian scan ~/Downloads`
5. Guard downloads live: `python -m guardian watch`
6. Check a link: `python -m guardian url "http://example.com"`
7. Fetch fresh threat data: `python -m guardian update`
8. Open the window: `python -m guardian gui`

Safe demo: create the EICAR file with `python -c "from guardian.signatures import EICAR; open('eicar.txt','wb').write(EICAR)"` and scan it. Some real antiviruses will delete it immediately; that proves *they* work.

---

## 6. How the "self-updating AI" works, and its honest limits

What Guardian does today:
- **Threat data updates** (`update`): new known-bad hashes and URLs are merged in. This is real "learning from the current world".
- **Model retraining** (`train`): you give labelled examples (CSV of features plus label 1/0) and the weights adjust.

What it does *not* do (yet), and what real products do:
- Real products train big models on **millions** of files, in the cloud, then ship the updated model to users.
- If you ship model updates to users, they **must be digitally signed** and the app must verify the signature. Otherwise an attacker who tampers with your update server can turn off protection on every user.
- AI makes mistakes both ways: **false positives** (flagging safe files) annoy users; **false negatives** (missing malware) hurt them. Always show reasons, always allow restore, and measure both error rates on data the model has never seen.
- Attackers adapt to ML models. Treat AI as one layer, not the whole defence.

Free threat-data sources to study (check each site for current access rules and API keys): abuse.ch MalwareBazaar and URLhaus, and Google Safe Browsing (API key required). VirusTotal offers an API too, with usage limits.

---

## 7. Security rules for building security software

Because your app is a high-value target, follow these from day one:
1. **Treat all input as hostile**: file contents, filenames, downloaded feeds.
2. **Never execute files you are scanning.** Only read them.
3. **Never run downloaded code.** Update data, not programs, or sign and verify everything.
4. **HTTPS only**, with size limits and timeouts on downloads.
5. **Least privilege**: do not run as administrator unless essential.
6. **Privacy**: never upload a user's files without clear consent. Send hashes or summaries instead.
7. **Fail safe and visible**: if scanning fails, say so; do not show "clean".
8. **Be honest in marketing**. Never promise "100% protection"; app stores and regulators punish this.

---

## 8. Packaging: turning code into an installable PC app

Users should not need Python. Use **PyInstaller**:

```
pip install pyinstaller
pyinstaller --onefile --windowed --name Guardian run_guardian_gui.py
```
`run_guardian_gui.py` is a tiny launcher included in the project: PyInstaller needs a plain script to start from, and this one just opens the window app.

Important: PyInstaller builds for the OS you run it on. Build the Windows `.exe` on Windows, the macOS app on a Mac, the Linux binary on Linux (GitHub Actions can do all three automatically).

To distribute properly you also need:
- **Windows**: a code-signing certificate (otherwise SmartScreen warns users), an installer (Inno Setup or MSIX).
- **macOS**: an Apple Developer account (paid), signing and *notarization*.
- **Linux**: `.deb`, `.rpm`, AppImage or Flatpak.

Note: an unsigned security tool built with PyInstaller may be flagged by *other* antivirus products as suspicious. This is a common headache; signing and a reputation history fix it over time.

---

## 9. Android and iPhone: the reality (important)

You asked for Android and Apple stores. Here is what is actually possible. **Phones work very differently from PCs.**

**iPhone (iOS)**
- Apps are sandboxed: **no app can scan other apps or the whole file system.** "Antivirus" apps on the App Store are really things like Safe Browsing/web filters, VPN-based link blocking, call/SMS filters, breach alerts, and Wi-Fi checks.
- So an iOS version of Guardian would be: *link checker, phishing warnings, file/hash checker for files the user explicitly shares to the app, and the AI advisor.* The signature scanner of this project cannot scan the phone.
- Apple Developer Program costs about US$99 per year, and apps go through App Review.

**Android**
- More open. An app can scan files it has permission for (downloads, SD card) and can inspect installed apps' names/permissions. Google Play restricts broad storage access and expects a clear privacy policy and a justified use of each permission.
- Google Play requires a developer account (a one-time fee) and testing before release.

**How to build the mobile apps**
- The Python engine cannot just be dropped into a phone app for the stores. Practical routes:
  1. **Flutter** (one codebase for Android and iOS, Dart language). Re-implement the engine logic (hashing, rules, scoring) in Dart. The logic in Guardian is simple enough to port by reading this guide.
  2. **Kotlin** (native Android) and **Swift** (native iOS) for the deepest features.
  3. Keep heavy AI and threat-intelligence on a **server** (a small API). Phone apps send hashes and URLs, get verdicts back. This is how most commercial products work and it keeps the app small.

**Suggested roadmap**
1. Finish and polish the PC app (you are here).
2. Make a small cloud API (FastAPI) that returns verdicts for hashes and URLs.
3. Build an Android app (Flutter or Kotlin) that scans downloads, checks links, shows the AI advisor.
4. Build the iOS app as a link/phishing guard plus advisor.
5. Add paid features (family plans, breach alerts) and a clear privacy policy.

---

## 10. Listing on app stores and starting a company

- Prepare: privacy policy, support email, honest app description, screenshots, age rating.
- Security apps are reviewed more closely. Explain every permission you request.
- Expect rejections the first time; read the reviewer's note and fix exactly what it says.
- Legal: register a business, check data-protection laws where your users live (India's DPDP Act, EU GDPR), and have your terms and refund policy reviewed by a lawyer.
- Realistic startup advice: the general antivirus market is crowded. Niches that are less crowded and more valuable: **scam and phishing protection for elderly users and families, UPI/payment fraud warnings, WhatsApp link safety, small-business file safety, safe-download helpers for students.** A "Jarvis" that explains threats in plain language (and in Hindi and other Indian languages) is a genuine differentiator.

---

## 11. Your learning path

1. **Python basics**: variables, functions, lists/dicts, files, classes. (Weeks 1-4)
2. **Read this project line by line.** Change one thing, run the tests, break one on purpose, fix it. (Weeks 4-6)
3. **Add features yourself**, in this order of difficulty:
   - Scan inside Office files (`.docx` is a ZIP) for embedded programs.
   - A scan history log.
   - Better GUI with a progress bar.
   - Your own heuristic rule, plus a test for it.
   - Replace polling in `watcher.py` with the `watchdog` library.
4. **Learn the next layer**: networking (HTTP, DNS, TLS), operating-system internals (processes, permissions), basic reverse engineering (strings, PE/ELF file formats).
5. **Learn machine learning properly**: scikit-learn, train/validation/test split, precision and recall.
6. **Web/API skills**: FastAPI and a database, to build the cloud side.
7. **Mobile**: Flutter or Kotlin.
8. **Practise legally**: CTF sites (picoCTF), TryHackMe, and malware-analysis books such as *Practical Malware Analysis*. Only ever analyse real malware inside an isolated virtual machine with no network.

---

## 12. Glossary

- **Hash**: fixed-size fingerprint of data.
- **Signature**: a known pattern or hash identifying a specific threat.
- **Heuristic**: a rule of thumb that suggests, but does not prove, something.
- **Feature**: a number extracted from data for a model to use.
- **Logistic regression**: simple model turning weighted features into a probability.
- **False positive / negative**: safe thing flagged / bad thing missed.
- **Quarantine**: isolating a file without destroying it.
- **Sandbox**: restricted environment limiting what code can touch.
- **Entropy**: measure of randomness.
- **Payload / dropper**: the harmful part of malware / a small program that installs it.
- **Phishing**: tricking people into giving secrets via fake messages or sites.
- **EICAR**: harmless standard test file for antivirus software.
- **Zip bomb**: a tiny archive that expands to an enormous size to crash a scanner.
- **Zip-slip**: an archive member whose path escapes the extraction folder.
- **Persistence**: how malware makes itself run again after a reboot.
- **ReDoS**: a crafted input that makes a regular expression run for hours.
- **XSS (cross-site scripting)**: untrusted text that runs as code when shown in a web page.
- **SQL injection**: untrusted text that changes the meaning of a database query.
- **Allowlist**: items you have explicitly marked as trusted.
- **Cache invalidation**: making sure saved answers are discarded when they could be out of date.
