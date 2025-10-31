# BSOD Analyser

A Windows troubleshooting tool that scans **Blue Screen of Death (BSOD)** crash artefacts *and* broader system health signals to produce a human‑readable report. It’s designed for quick triage on your own machine or a family/friend’s PC.

> Built by Hugh Knight. This repo contains the GUI and core scanner plus sample reports.

## What it does
- Parses recent **BugCheck** events and minidumps (if available) and maps common stop codes to plain‑English causes.
- Reads Windows **Event Logs** (System/Application) to surface related errors and warnings in the same time window.
- Highlights **likely suspects** (drivers/services) and a short list of **recommended actions**.
- Checks **driver update** info for common vendors (helper links included).
- Captures a **system snapshot** (OS build, hardware basics, Windows Update status).
- Optional **health tools** launcher: SFC, DISM, CHKDSK, Memory Diagnostic.
- Saves a Markdown/text **report** you can share with a tech.

## Folders & files
```
bsod_core.py        # scanning + report builder
bsod_ui.py          # modern ttk GUI wrapper
driver_updates.py   # helper utilities for driver lookups
settings.json       # persistent settings (paths/lookback etc.)
bugchecks.csv       # stop-code quick reference
suspects.csv        # common culprits and hints
examples/           # sample outputs for reference
```
> Note: the code looks in the **repo root** for `bugchecks.csv`, `suspects.csv`, and `settings.json`.

## Getting started
1. **Requirements:** Windows 10/11 with Python 3.10+.
2. **Install deps (optional):**
   ```bash
   pip install matplotlib
   ```
   Matplotlib is only needed if you want the optional timeline chart.
3. **Run the GUI:**
   ```bash
   python bsod_ui.py
   ```
4. **Run headless (CLI):**
   ```bash
   python bsod_core.py
   ```
   The tool will generate a report folder and write Markdown/Text outputs there.

## How it works (quick flow)
1. Determine a time window (from `settings.json` or UI input).
2. Query Windows Event Logs for BugChecks (+ related errors/warnings).
3. Map stop codes using `bugchecks.csv` and cross‑reference `suspects.csv`.
4. Assemble a **BSOD_Report.md** (and text copy) with: timeline, suspects, fixes.
5. Provide quick‑launch buttons for health tools and links for driver/vendor updates.

## Packaging to EXE (optional)
You can create a single‑file Windows executable with PyInstaller:
```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed bsod_ui.py
```
The resulting exe will live under `dist/`. Ship it with `bugchecks.csv`, `suspects.csv`, and `settings.json` in the same folder.

## Troubleshooting
- **No data found:** increase the lookback window in the UI or `settings.json`.
- **Permission issues:** run the app **as Administrator** to access all event logs.
- **Charts not showing:** install matplotlib (see above) or disable the timeline option.

## Roadmap
- Minidump parsing integration when dumps are present.
- Deeper vendor driver APIs.
- Export to HTML/PDF with styling.

---
Licensed under the MIT License © 2025 Hugh Knight.