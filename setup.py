#!/usr/bin/env python3
"""Setup configuration for BSOD Analyzer."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="bsod-analyzer",
    version="0.9.1",
    author="H.Knight",
    author_email="",
    description="Windows Error Checker: Blue Screen of Death analyzer with event log scanning, hardware diagnostics, and driver management",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bsod-analyzer",
    license="MIT",
    py_modules=["bsod_core", "bsod_ui", "driver_updates"],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Debuggers",
    ],
    keywords="bsod windows error diagnostics hardware driver",
    entry_points={
        "gui_scripts": [
            "bsod-analyzer=bsod_ui:root.mainloop",
        ],
    },
)
