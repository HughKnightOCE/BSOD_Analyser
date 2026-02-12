#!/usr/bin/env python3
"""Quick import test for BSOD Analyzer modules."""

import sys
from pathlib import Path

try:
    print("Testing imports...")
    
    print("  - bsod_core...", end="")
    import bsod_core
    print(" OK")
    
    print("  - driver_updates...", end="")
    import driver_updates
    print(" OK")
    
    print("  - bsod_ui...", end="")
    # Don't actually run the UI, just test import
    import bsod_ui
    print(" OK")
    
    print("\n✓ All imports successful!")
    print(f"App: {bsod_core.APP_NAME} v{bsod_core.APP_VERSION}")
    
except ImportError as e:
    print(f"\n✗ Import Error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"\n✗ Error: {e}")
    sys.exit(1)
