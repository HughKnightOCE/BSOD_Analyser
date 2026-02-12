# BSOD Analyzer

Windows Error Checker: Blue Screen of Death analyzer with event log scanning, hardware diagnostics, and driver management.

**Version:** 0.9.1  
**Author:** H.Knight  
**License:** MIT

## Overview

BSOD Analyzer is a comprehensive Windows diagnostic tool that:

- **Scans Event Logs** for Blue Screen (BSOD) events and related crashes
- **Analyzes Error Patterns** to identify frequently recurring issues
- **Correlates Events** near BSOD times to find likely culprits (drivers, hardware, firmware)
- **Monitors Hardware** — GPU info, SMART status, storage reliability counters
- **Suggests Fixes** with human-readable descriptions for common stop codes (0x50, 0x1E, 0x3B, 0x116, 0x124, etc.)
- **Manages Drivers** — lists and installs updates from Windows Update
- **Runs Health Checks** — SFC, DISM, CHKDSK, and Windows Memory Diagnostic
- **Generates Reports** — Markdown + CSV exports for analysis and troubleshooting

## Requirements

- **Windows 10/11** (21H2 or later recommended)
- **Python 3.8+** (3.11+ recommended for best compatibility)
- **Administrator rights** for full functionality (logs, minidumps, driver install)

## Installation

### Option 1: From Source (Development)

1. Clone or download the repository
2. Create a virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
3. Install in editable mode:
   ```powershell
   pip install -e .
   ```
4. Run the GUI:
   ```powershell
   python bsod_ui.py
   ```

### Option 2: Build Distribution (Wheel)

```powershell
python -m pip install build
python -m build
# Wheel will be in dist/
pip install dist/bsod_analyzer-0.9.1-py3-none-any.whl
```

## Usage

### GUI (Recommended)

```powershell
python bsod_ui.py
```

**Tabs:**
- **Summary** — Latest BugChecks, dump file locations, report path
- **Errors** — Recent system/application errors and warnings
- **BugChecks** — BSOD stop codes with parameter analysis
- **Suspects** — Events that correlate with crash times
- **Driver Updates** — Windows Update driver list, install managed
- **System Info** — GPU, SMART, storage, updates; health tools (SFC, DISM, CHKDSK, Memory Test)
- **Live Monitor** — Real-time System log polling

### Settings

Edit or create `settings.json`:

```json
{
  "report_dir": "C:\\path\\to\\report\\folder",
  "lookback_days": 30,
  "window_min": 15,
  "poll_seconds": 10
}
```

- **report_dir** — Location for report output (Markdown, CSV)
- **lookback_days** — How far back to scan event logs (1–365)
- **window_min** — Time window (±minutes) to correlate events near BSOD
- **poll_seconds** — Live monitor polling interval

### Command-Line

```powershell
python bsod_core.py
```

Runs analysis and prints summary to console.

## Stop Code Quick Reference

| Code | Name | Typical Cause |
|------|------|---------------|
| **0x50** | PAGE_FAULT_IN_NONPAGED_AREA | RAM, drivers, disk corruption |
| **0x1E** | KMODE_EXCEPTION_NOT_HANDLED | Buggy driver or kernel extension |
| **0x3B** | SYSTEM_SERVICE_EXCEPTION | GPU/display, antivirus, drivers |
| **0x116** | VIDEO_TDR_FAILURE | GPU driver/hardware/thermals |
| **0x124** | WHEA_UNCORRECTABLE_ERROR | CPU/VRM/RAM/PCIe hardware issue |
| **0x9F** | DRIVER_POWER_STATE_FAILURE | Sleep/USB/Wi-Fi drivers |
| **0x7E** | SYSTEM_THREAD_EXCEPTION_NOT_HANDLED | Drivers or low-level software |

## Features

### Event Log Analysis
- BugCheck (Event 1001) extraction and parameter parsing
- System/Application error/warning aggregation
- Temporal correlation with BSOD times

### Hardware Diagnostics
- GPU info (model, driver version, date)
- SMART disk status
- Storage reliability counters (wear, temperature, errors)
- System snapshot (CPU, BIOS, RAM, OS version, power plan)

### Health Tools (Admin required)
- **SFC** — System File Checker scan
- **DISM** — Windows image restore
- **CHKDSK** — Disk integrity check
- **Memory Diagnostic** — RAM test

### Driver Management (Admin required)
- Search Windows Update for available driver updates
- Display update information (manufacturer, version, date)
- One-click install with reboot scheduling

### Report Generation
- **ErrorChecker_Report.md** — Human-readable summary
- **bugchecks.csv** — BSOD codes, times, parameters, dump paths
- **suspects.csv** — Correlated event summary
- **Timeline chart** (if matplotlib available) — BSOD frequency by day

## Architecture

- **bsod_core.py** — Analysis engine: event querying, parsing, inventory
- **bsod_ui.py** — Tkinter GUI with 7 tabs and async threading
- **driver_updates.py** — PowerShell COM wrapper for Windows Update

All PowerShell operations are run with `-NoProfile -ExecutionPolicy Bypass` for compatibility.

## Known Limitations

- Requires Windows 10/11; earlier versions not supported
- .dmp minidump analysis requires WinDbg (installation separate)
- Some system info (SMART, storage reliability) may not be available on all systems
- PowerShell scripts require full execution policy

## Troubleshooting

### "Not running as Administrator"
Relaunch with elevated privileges by clicking **Run Elevated** button or:
```powershell
Start-Process python -ArgumentList "bsod_ui.py" -Verb RunAs
```

### No BugChecks found
- Check System event log retention (Settings → Admin Tools → Event Viewer)
- Verify Event ID 1001 is not being filtered
- Try increasing **Lookback (days)** in UI

### PowerShell errors
Ensure execution policy allows unsigned scripts:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
```

### Missing driver updates
- Windows Update may not have indexed yet (usually 24 hours)
- Ensure `Microsoft.Update` COM objects are available
- Try running as Administrator

## Development

Clone and set up dev environment:

```powershell
git clone https://github.com/yourusername/bsod-analyzer.git
cd bsod-analyzer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Run tests or modifications to the three main modules in the repo root.

## Contributing

Community feedback and issues are welcome. Please report bugs via GitHub Issues.

## License

MIT License — See LICENSE file for details.

## Disclaimer

This tool is provided as-is for diagnostic purposes. Use at your own risk. Always back up important data before running system repair tools (SFC, DISM, CHKDSK). Windows diagnostics and minidump analysis are complex; consult Microsoft documentation or professional support for interpretation.

---

**Questions?** Check the built-in **Info** and **About** dialogs in the GUI.
