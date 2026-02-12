# 🚀 Push to GitHub - Quick Guide

Your BSOD Analyzer is ready to push to GitHub!

## Step 1: Configure Git Remote

```powershell
cd "c:\Users\Hugh\Qsync\Coding projects\BSOD Analyzer"

# Add your GitHub repository as the remote
git remote add origin https://github.com/HughKnightOCE/BSOD_Analyser.git
```

## Step 2: Push to GitHub

```powershell
# Push all commits to GitHub
git push -u origin master
```

If using 'main' branch instead:
```powershell
git branch -m main
git push -u origin main
```

## Step 3: Create a Release on GitHub

After pushing, create a release to make the executable easily downloadable:

1. Go to: https://github.com/HughKnightOCE/BSOD_Analyser/releases
2. Click **"Create a new release"**
3. Set these fields:
   - **Tag version:** `v0.9.1`
   - **Release title:** `BSOD Analyzer v0.9.1`
   - **Description:**
     ```
     Standalone executable release for Windows 10/11
     
     ## What's Included
     - BSOD_Analyzer.exe (12.11 MB) - Standalone executable
     - BSOD_Analyzer_Admin.bat - Admin launcher
     - Python wheel distribution
     - Source package
     
     ## Quick Start
     Download BSOD_Analyzer.exe and run it directly - no installation needed!
     
     ## Features
     ✓ BSOD analysis with stop code descriptions
     ✓ Event log scanning
     ✓ Hardware diagnostics (GPU, SMART, storage)
     ✓ Driver update management
     ✓ System health tools (SFC, DISM, CHKDSK, Memory Test)
     ✓ Live monitoring
     ✓ Report generation
     
     ## Requirements
     - Windows 10/11
     - Administrator rights (for full functionality)
     
     For more information, see README.md
     ```

4. Upload these files as release assets:
   - `dist_exe/BSOD_Analyzer.exe`
   - `dist_exe/BSOD_Analyzer_Admin.bat`
   - `dist/bsod_analyzer-0.9.1-py3-none-any.whl`
   - `dist/bsod_analyzer-0.9.1.tar.gz`

5. Click **"Publish release"**

## All Set! 🎉

Your BSOD Analyzer is now:
- ✅ Pushed to GitHub
- ✅ Available as executable
- ✅ Available as Python package
- ✅ Ready for distribution

Users can now:
- Download the .exe directly from releases
- Install via pip: `pip install bsod-analyzer`
- Clone the repository for development

## File Locations

All distributions are in your project folder:

```
BSOD Analyzer/
├── dist_exe/
│   ├── BSOD_Analyzer.exe           ← Standalone executable
│   └── BSOD_Analyzer_Admin.bat     ← Admin launcher
├── dist/
│   ├── bsod_analyzer-0.9.1-py3-none-any.whl
│   └── bsod_analyzer-0.9.1.tar.gz
└── .git/                            ← Git repository
```

---

**Next:** Run `git push -u origin master` to upload everything to GitHub!
