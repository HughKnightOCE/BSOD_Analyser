# BSOD Analyser

A Python-based diagnostic tool that automates the detection of Blue Screen of Death (BSOD) causes.  
Built as part of my cybersecurity and troubleshooting toolkit to demonstrate skills in Python scripting, automation, and data correlation.

---

## 🧩 About This Project
While maintaining Windows systems, I found that manually inspecting BSOD dumps and event logs was time-consuming and error-prone.  
This tool automatically reads and cross-references log data, driver updates, and bugcheck codes to identify patterns, likely culprits, and generate clear summaries — saving time and reducing guesswork.

It’s designed as a lightweight, offline utility that demonstrates applied automation and problem-solving — key skills for IT support and cybersecurity work.

---

## ⚙️ Features
- Parses Windows crash data (CSV and JSON)
- Identifies recurring bug check codes
- Maps driver versions to fault patterns
- Generates clean summaries or CSV exports
- Optional Tkinter GUI for visual reporting

---

## 🗂️ Project Structure
```
src/
 ├── bsod_core.py          # Main logic
 ├── bsod_ui.py            # GUI interface
 └── driver_updates.py     # Driver version lookup
data/
 ├── bugchecks.csv         # Bug check reference data
 └── suspects.csv          # Known problematic drivers
settings.json              # User configuration file
README.md
LICENSE
```

---

## 🚀 Quick Start
```bash
git clone https://github.com/HughKnightOCE/BSOD_Analyser.git
cd BSOD_Analyser
python src/bsod_ui.py
```

---

## 🧰 Requirements
- Python 3.10+
- Uses only standard libraries (no pip installs required)

---

## 📄 License
MIT © Hugh Knight
