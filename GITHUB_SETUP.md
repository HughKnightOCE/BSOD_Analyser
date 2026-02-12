# Distribution & GitHub Setup Guide

## Distribution Files

✓ **Successfully created in `dist/` folder:**

- **bsod_analyzer-0.9.1-py3-none-any.whl** — Wheel distribution (ready to install)
- **bsod_analyzer-0.9.1.tar.gz** — Source distribution (source code archive)

### Install from Wheel

```powershell
pip install dist/bsod_analyzer-0.9.1-py3-none-any.whl
```

### Build from Source

```powershell
pip install dist/bsod_analyzer-0.9.1.tar.gz
# or
pip install -e .
```

---

## GitHub Setup

I **don't have direct GitHub access**, but I've prepared everything for you:

### Step 1: Git Repository

✓ **Git repository already initialized locally** with:
- Initial commit of all source code
- Proper `.gitignore` to exclude build artifacts
- All documentation (README, LICENSE)

Check git status:
```powershell
git log --oneline
git status
```

### Step 2: Push to GitHub

**Three ways to push:**

#### **Option A: Automatic Setup Script (Easiest)**

```powershell
.\push-to-github.ps1
```

This script will:
1. Prompt you to create a repo on GitHub
2. Ask for your repository URL
3. Automatically push everything to your remote

#### **Option B: Manual Setup**

1. Create a repository on GitHub: https://github.com/new
   - Name: `bsod-analyzer`
   - Make it Public (recommended for open source)
   - Don't initialize with README (you already have one)

2. Run these commands:
   ```powershell
   git remote add origin https://github.com/YOUR_USERNAME/bsod-analyzer.git
   git branch -m main
   git push -u origin main
   ```

#### **Option C: GitHub CLI (if installed)**

```powershell
gh repo create bsod-analyzer --public --source=. --remote=origin --push
```

### Step 3: GitHub Actions (Optional)

Create `.github/workflows/build.yml` to auto-build distributions on every release:

```yaml
name: Build Distribution

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install build
      - run: python -m build
      - uses: actions/upload-artifact@v3
        with:
          name: dist
          path: dist/
```

---

## Git Credentials Setup

If you haven't configured git yet:

```powershell
git config --global user.name "Your Name"
git config --global user.email "your@email.com"
```

For HTTPS auth (Windows):
- Git will prompt you for credentials on first push
- Or use GitHub Personal Access Token: https://github.com/settings/tokens

For SSH (recommended):
- Generate SSH key: `ssh-keygen -t ed25519`
- Add to GitHub: https://github.com/settings/keys
- Use SSH URL: `git@github.com:YOUR_USERNAME/bsod-analyzer.git`

---

## After Pushing to GitHub

1. **Update README.md** — Change `yourusername` to your actual GitHub username in the repository URLs

2. **Add Topics** — On GitHub repo settings:
   - bsod
   - windows
   - diagnostics
   - tools

3. **Enable Releases** — Tag versions:
   ```powershell
   git tag -a v0.9.1 -m "Initial release v0.9.1"
   git push origin v0.9.1
   ```
   Then attach `dist/bsod_analyzer-0.9.1-py3-none-any.whl` to the release

4. **Optional: Publish to PyPI** — For public package distribution:
   ```powershell
   pip install twine
   twine upload dist/*
   ```
   (Requires PyPI account: https://pypi.org/account/register/)

---

## Project Structure Summary

```
bsod-analyzer/
├── bsod_core.py          # Main analysis engine
├── bsod_ui.py            # Tkinter GUI
├── driver_updates.py     # Windows Update driver management
├── setup.py              # Old-style setup (for compatibility)
├── pyproject.toml        # PEP 517 build config
├── README.md             # Full documentation
├── LICENSE               # MIT License
├── .gitignore            # Git exclusions
├── MANIFEST.in           # Package includes
├── dist/                 # Built distributions
│   ├── bsod_analyzer-0.9.1-py3-none-any.whl
│   └── bsod_analyzer-0.9.1.tar.gz
└── .git/                 # Git repository
```

---

## Quick Commands Reference

```powershell
# View current remote
git remote -v

# Verify repository is ready
git status
git log --oneline

# Push to existing remote
git push

# Create and push a release tag
git tag v0.9.2 -m "Release v0.9.2"
git push origin v0.9.2

# View all branches
git branch -a
```

---

**Ready to go!** Choose your method above and follow the steps. 🚀
