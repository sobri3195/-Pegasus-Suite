#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Test file to verify imports are working
"""

print("Testing imports...")

# Test exploit_tools.py imports
try:
    from colorama import Fore, Style, init
    print("✓ colorama import successful")
except ImportError:
    print("✗ colorama import failed")

# Test osint.py imports
try:
    import requests
    print("✓ requests import successful")
except ImportError:
    print("✗ requests import failed")

# Test from pegabox_imports
try:
    from pegabox_imports import Fore, Style, requests, REQUESTS_AVAILABLE, COLORAMA_AVAILABLE
    print(f"✓ pegabox_imports import successful")
    print(f"  - COLORAMA_AVAILABLE: {COLORAMA_AVAILABLE}")
    print(f"  - REQUESTS_AVAILABLE: {REQUESTS_AVAILABLE}")
except ImportError as e:
    print(f"✗ pegabox_imports import failed: {e}")

print("\nImport test complete.") 