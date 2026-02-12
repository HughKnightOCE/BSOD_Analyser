# BSOD Analyzer - Executable Distribution

## Quick Start

**Download:** [BSOD_Analyzer.exe](https://github.com/HughKnightOCE/BSOD_Analyser/releases)

### Running the Executable

1. **Download** the latest `BSOD_Analyzer.exe` from GitHub Releases
2. **Run** the executable directly or use the batch launcher for automatic admin elevation:
   - `BSOD_Analyzer.exe` — Run directly
   - `BSOD_Analyzer_Admin.bat` — Auto-elevate to Administrator (recommended)

No installation required - it's a standalone executable!

## What's Included

- **BSOD_Analyzer.exe** (12.11 MB)
  - Complete Python runtime bundled
  - All dependencies included
  - Tkinter GUI ready to use
  - PowerShell integration for Windows diagnostics

- **BSOD_Analyzer_Admin.bat** (optional)
  - Automatically requests Administrator privileges
  - More convenient for regular use

## Features Available

✓ Full event log scanning  
✓ BSOD analysis with stop code descriptions  
✓ Hardware diagnostics (GPU, SMART, storage)  
✓ Driver update management  
✓ System health tools (SFC, DISM, CHKDSK, Memory Test)  
✓ Real-time monitoring  
✓ Report generation (Markdown + CSV)  

## Requirements

- **Windows 10/11** (21H2 or later recommended)
- **Administrator rights** for full functionality
- No Python installation needed!

## Installation (Optional)

While the .exe is fully standalone, you can:

### Add to Start Menu
1. Right-click `BSOD_Analyzer.exe`
2. Choose "Send to" → "Desktop (create shortcut)"
3. Optionally move shortcut to Start Menu folder

### System Path (Advanced)
```powershell
# Copy exe to system path
Copy-Item BSOD_Analyzer.exe "C:\Windows\System32\bsod-analyzer.exe"

# Then run from anywhere:
bsod-analyzer
```

## First Run

1. **Launch** BSOD_Analyzer.exe
2. **Allow** Windows Defender if prompted
3. **Click** "Run Scan" to start analysis
4. **Grant** Administrator access if prompted

> **Tip:** Use `BSOD_Analyzer_Admin.bat` to auto-elevate and avoid prompts

## Settings & Reports

Reports are saved to:
- Windows: `%APPDATA%\ErrorChecker_Report\` (default)
- Change location in app: Summary tab → "Change Report Folder"

Settings file: `settings.json` in the report directory

## Troubleshooting

### "Windows protected your PC"
Windows SmartScreen may block unsigned executables:

1. Click "More info"
2. Click "Run anyway"
3. (Recommended) Download from official GitHub releases to avoid this

### App won't start
- Ensure you have .NET Framework 4.5+
- Windows 10/11 already includes this
- Try running as Administrator

### No BSOD found
- Check Event Viewer retention (System may be limited to 7 days)
- Increase "Lookback (days)" in UI settings
- Ensure admin rights (for minidumps)

### Driver updates not showing
- Windows Update COM service may need a moment to index
- Manually check Windows Update Settings → Advanced options
- Run as Administrator for best results

## Building from Source

If you want to modify or rebuild the executable:

```powershell
# Clone the repository
git clone https://github.com/HughKnightOCE/BSOD_Analyser.git
cd BSOD_Analyser

# Set up Python environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install pyinstaller

# Build executable
pyinstaller --onefile --windowed --name BSOD_Analyzer bsod_ui.py

# Output: dist\BSOD_Analyzer.exe
```

## Architecture

The executable bundles:
- Python 3.11 runtime
- All Python dependencies (tkinter, etc.)
- Application code (bsod_core.py, driver_updates.py)
- Windows PowerShell scripts (embedded in code)

Total size: ~12 MB (compressed with UPX)

## Distribution History

| Version | Date | Size | Download |
|---------|------|------|----------|
| 0.9.1 | Feb 2026 | 12.11 MB | [Releases](https://github.com/HughKnightOCE/BSOD_Analyser/releases) |

## Support

For issues:
1. Check [GitHub Issues](https://github.com/HughKnightOCE/BSOD_Analyser/issues)
2. Review the [README.md](README.md)
3. Check Windows Event Viewer if diagnostics fail

## License

MIT License - See LICENSE file in repository

---

**Quick Links:**
- [GitHub Repository](https://github.com/HughKnightOCE/BSOD_Analyser)
- [Latest Release](https://github.com/HughKnightOCE/BSOD_Analyser/releases)
- [Report an Issue](https://github.com/HughKnightOCE/BSOD_Analyser/issues)
