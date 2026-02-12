# BSOD Analyzer

Windows Blue Screen of Death (BSOD) diagnostic tool that automates crash analysis, event log scanning, hardware diagnostics, and driver management.

**Version:** 0.9.1  
**Author:** H.Knight  
**License:** MIT  
**Repository:** [GitHub](https://github.com/HughKnightOCE/BSOD_Analyser)

## 🎯 What It Does

BSOD Analyzer helps you diagnose Windows crashes by:

- **🔍 Scanning Event Logs** — Finds BSOD (Blue Screen) crash events
- **📊 Analyzing Patterns** — Identifies frequently recurring errors
- **⚙️ Correlating Events** — Finds events clustered near crashes (driver suspects)
- **💾 Checking Hardware** — GPU, SMART disk, storage reliability, system info
- **🔧 Managing Drivers** — Lists and installs Windows Update driver updates
- **🛠️ Running Health Tools** — SFC, DISM, CHKDSK, Memory Diagnostic
- **📈 Generating Reports** — Professional Markdown and CSV outputs
- **🚀 Real-Time Monitoring** — Live system event polling

## ⚡ Quick Start

### Download & Run (No Installation)

**[Download BSOD_Analyzer.exe](https://github.com/HughKnightOCE/BSOD_Analyser/releases)** — Standalone executable for Windows 10/11

```powershell
.\BSOD_Analyzer.exe
# or with admin auto-elevation:
.\BSOD_Analyzer_Admin.bat
```

**No Python installation needed!** Everything is bundled into the .exe.

### Run from Python

```powershell
git clone https://github.com/HughKnightOCE/BSOD_Analyser.git
cd BSOD_Analyser
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python bsod_ui.py
```

## 📋 Installation Options

### Option 1: ⭐ Standalone Executable (Easiest)

**Download:** [BSOD_Analyzer.exe](https://github.com/HughKnightOCE/BSOD_Analyser/releases)

- Windows 10/11 only
- 12.11 MB single file
- Python runtime included
- All dependencies bundled
- No installation required

### Option 2: Python from Source

**Clone the repository:**
```powershell
git clone https://github.com/HughKnightOCE/BSOD_Analyser.git
cd BSOD_Analyser
```

**Create virtual environment:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Install dependencies:**
```powershell
pip install -r requirements.txt
```

**Run GUI:**
```powershell
python bsod_ui.py
```

### Option 3: Python Package Installation

```powershell
pip install dist/bsod_analyzer-0.9.1-py3-none-any.whl
```

### Option 4: Build Your Own Executable

```powershell
pip install pyinstaller
pyinstaller --onefile --windowed --name BSOD_Analyzer bsod_ui.py
# Output: dist\BSOD_Analyzer.exe
```

## 🖥️ System Requirements

- **OS:** Windows 10/11 (21H2 or later recommended)
- **Python:** 3.8+ (if running from source; 3.11+ recommended)
- **Admin Rights:** Required for:
  - Full event log access
  - Minidump file access
  - Driver installation
  - Health tools (SFC, DISM, CHKDSK, Memory Test)

## 🎮 Using BSOD Analyzer

### GUI Interface

Seven tabs for comprehensive diagnostics:

| Tab | Purpose |
|-----|---------|
| **Summary** | Latest BugChecks, stop codes, dump file paths |
| **Errors** | Recent System/Application errors with frequency stats |
| **BugChecks** | BSOD events with codes, parameters, timestamps |
| **Suspects** | Events clustered near crash times (likely causes) |
| **Driver Updates** | Available Windows Update drivers with install option |
| **System Info** | GPU, SMART, storage, updates; health diagnostic tools |
| **Live Monitor** | Real-time System log polling and event streaming |

### Tabs Overview

**Summary Tab**
- View latest BSOD crashes
- Check stop codes and friendly names
- See dump file locations (for WinDbg analysis)
- Configure report folder and analysis window

**Errors Tab**
- Recent critical/error/warning events
- Top recurrent issues with color-coded severity
- Time, source provider, event ID, message

**BugChecks Tab**
- All BSOD events in lookback period
- Stop code, friendly name, parameters
- Minidump file paths (if available)
- Export to CSV for archival

**Suspects Tab**
- Events that correlate with crash times
- Severity color-coded (critical/high/medium/low)
- Provider, event ID, occurrence count
- Likely culprits for troubleshooting

**Driver Updates Tab**
- Search Windows Update for driver updates
- Manufacturer, version, release date
- One-click install (requires admin)
- Microsoft support links per driver

**System Info Tab**
- GPU information (model, driver, date)
- SMART disk status (all detected drives)
- Storage reliability counters (wear, temperature, error counts)
- Recent Windows Updates
- System snapshot (CPU, BIOS, RAM, OS)
- Health diagnostic tools

**Live Monitor Tab**
- Real-time event stream from System log
- Auto-scrolling display
- Configurable polling interval (default: 10 seconds)
- Useful for capturing events during troubleshooting

### Configuration

**Via GUI:**
- Change report folder: Summary tab → "Change Report Folder"
- Adjust lookback period: Settings area → "Lookback (days)"
- Set correlation window: Settings area → "BSOD window (±min)"

**Via settings.json:**
```json
{
  "report_dir": "C:\\path\\to\\report\\folder",
  "lookback_days": 30,
  "window_min": 15,
  "poll_seconds": 10
}
```

**Settings explained:**
- `report_dir` — Where to save reports and CSVs
- `lookback_days` — How far back to scan (1–365)
- `window_min` — Event correlation window around BSODs (±minutes)
- `poll_seconds` — Live monitor polling interval (seconds)

### Command-Line

```powershell
python bsod_core.py
```

Runs full analysis and prints summary. Outputs:
- `ErrorChecker_Report/ErrorChecker_Report.md`
- `ErrorChecker_Report/bugchecks.csv`
- `ErrorChecker_Report/suspects.csv`

## 🔍 Stop Code Reference

Common BSOD stop codes with descriptions:

| Code | Name | Typical Cause |
|------|------|---------------|
| **0x0000000A** | IRQL_NOT_LESS_OR_EQUAL | RAM issue, driver problem, overclocking |
| **0x0000001E** | KMODE_EXCEPTION_NOT_HANDLED | Buggy driver or kernel code |
| **0x00000050** | PAGE_FAULT_IN_NONPAGED_AREA | RAM fault, disk error, driver bug |
| **0x0000003B** | SYSTEM_SERVICE_EXCEPTION | GPU driver, antivirus, video driver |
| **0x0000007E** | SYSTEM_THREAD_EXCEPTION_NOT_HANDLED | Faulty driver or system software |
| **0x0000009F** | DRIVER_POWER_STATE_FAILURE | Sleep/USB/Wi-Fi driver |
| **0x00000116** | VIDEO_TDR_FAILURE | GPU driver timeout—overheating, crash, PSU |
| **0x00000124** | WHEA_UNCORRECTABLE_ERROR | Hardware error—CPU, RAM, PCIe, motherboard |

**Pro Tip:** BSOD Analyzer provides detailed descriptions for these codes. Just run a scan!

## 🛠️ Features & Architecture

### Event Log Analysis
- Automatic BSOD event detection (Event 1001)
- Parameter extraction and parsing
- System/Application log aggregation
- Temporal correlation (events near crashes)
- Configurable lookback period

### Hardware Diagnostics
- GPU information (driver version, installation date)
- SMART disk status summary
- Storage reliability counters (wear level, temperature, I/O errors)
- System snapshot (CPU cores, RAM, BIOS, OS version, power plan)
- Windows Update history

### Health Diagnostic Tools
- **SFC** — System File Checker (repairs corrupted system files)
- **DISM** — Deployment Image Servicing and Management (restores Windows)
- **CHKDSK** — Check Disk (online disk integrity check)
- **Memory Diagnostic** — Windows RAM testing (schedules reboot)

### Driver Management
- Windows Update driver search
- Filter by manufacturer, class, version
- Display driver information links
- One-click install with reboot handling
- Admin required for installation

### Report Generation
- **Markdown Report** — Professional, human-readable format
- **BugChecks CSV** — Codes, times, parameters, dump paths
- **Suspects CSV** — Events correlated with crashes
- **Timeline Chart** — BSOD frequency by day (if matplotlib installed)

### Live Monitoring
- Real-time System log polling
- Auto-scrolling event stream
- Configurable interval (default 10 seconds)
- Useful for capturing events during troubleshooting

## 📦 Architecture

**Three main modules:**

- **bsod_core.py** (Analysis Engine)
  - PowerShell event log queries
  - BSOD event parsing
  - Hardware inventory collection
  - Report generation

- **bsod_ui.py** (Tkinter GUI)
  - 7 tabbed interface
  - Async task threading
  - Real-time progress feedback
  - Settings management

- **driver_updates.py** (Windows Update Manager)
  - PowerShell COM wrapper
  - Driver search/install orchestration
  - No external package dependencies

All PowerShell commands use: `-NoProfile -ExecutionPolicy Bypass`

## 📊 Available Distributions

| Format | File | Size | Best For |
|--------|------|------|----------|
| **Executable** | BSOD_Analyzer.exe | 12.11 MB | End users |
| **Wheel** | bsod_analyzer-*.whl | 0.02 MB | Python pip install |
| **Source** | bsod_analyzer-*.tar.gz | 0.02 MB | Distribution/repackaging |
| **Git** | GitHub repo | ~5 MB | Development |

**Download executable:** [GitHub Releases](https://github.com/HughKnightOCE/BSOD_Analyser/releases)

## ⚠️ Known Limitations

- **Windows Only** — Requires Windows 10/11
- **Event Log Retention** — System log often limited to 7–14 days
- **Minidump Analysis** — Requires separate WinDbg installation for deep analysis
- **Hardware Info** — Some systems may not report SMART/storage reliability
- **Execution Policy** — PowerShell requires Bypass or RemoteSigned

## 🔧 Troubleshooting

### "Not running as Administrator"
Need admin rights for full features:
```powershell
Start-Process python -ArgumentList "bsod_ui.py" -Verb RunAs
# or use BSOD_Analyzer_Admin.bat
```

### No BugChecks Found
- Check Event Viewer → System log retention policy
- Increase "Lookback (days)" in UI settings
- Verify Event ID 1001 isn't filtered

### PowerShell Errors
Enable script execution:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
```

### Driver Updates Not Showing
- Windows Update may need 24 hours to index
- Run as Administrator for best results
- Check Settings → Updates for pending operations

### SMART/Storage Reliability Missing
- Not all systems expose these metrics
- Virtual machines may have limited WMI info
- Physical drives more reliable than USB

## 👨‍💻 Development & Contributing

### Clone & Setup
```powershell
git clone https://github.com/HughKnightOCE/BSOD_Analyser.git
cd BSOD_Analyser
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Run from Source
```powershell
python bsod_ui.py
```

### Build Executable
```powershell
pip install pyinstaller
pyinstaller --onefile --windowed bsod_ui.py
```

### Contributing
- **Issues:** [Report bugs](https://github.com/HughKnightOCE/BSOD_Analyser/issues)
- **Pull Requests:** Contributions welcome!
- **Suggestions:** Feature requests appreciated

## 📄 License

**MIT License** — Free to use, modify, and distribute.

See [LICENSE](LICENSE) file for full legal terms.

## 🙋 Support

- **[GitHub Repository](https://github.com/HughKnightOCE/BSOD_Analyser)** — Code and issues
- **[Releases](https://github.com/HughKnightOCE/BSOD_Analyser/releases)** — Download executable
- **[Issues](https://github.com/HughKnightOCE/BSOD_Analyser/issues)** — Bug reports
- **In-App Help** — Info and About buttons in GUI

Comprehensive guides:
- [EXECUTABLE_DISTRIBUTION.md](EXECUTABLE_DISTRIBUTION.md) — Executable user guide
- [DISTRIBUTION_GUIDE.md](DISTRIBUTION_GUIDE.md) — All distribution formats
- [GITHUB_SETUP.md](GITHUB_SETUP.md) — Repository setup

## ⚖️ Disclaimer

This tool is provided **as-is** for diagnostic purposes.

**⚠️ Important:**
- Back up critical data before running repair tools
- Understand what SFC, DISM, CHKDSK do before running
- Consult Microsoft documentation for complex issues
- Professional support recommended for critical systems

Windows diagnostics are complex. Use this tool as a starting point, not a complete solution.

## 📈 Roadmap

Potential future features:
- [ ] Automated minidump WinDbg analysis
- [ ] Advanced crash pattern recognition from historical data
- [ ] Custom event log filter rules
- [ ] PDF report export
- [ ] Crash history tracking and comparison
- [ ] Multi-language support
- [ ] CI/CD marketplace distribution

---

**Created by:** H.Knight  
**Last Updated:** February 2026  
**Status:** Active Development

Made with 🛠️ for Windows troubleshooting.
