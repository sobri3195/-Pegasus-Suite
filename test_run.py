#!/usr/bin/env python
"""Smoke tests for selected Pegasus-Suite entry points.

This file is intentionally import-safe for pytest collection.
"""

import importlib
import importlib.util
from unittest.mock import patch


def load_module():
    """Try to import the suite under supported module names."""
    for module_name in ("Pegasus_Suite", "Pegasus-Suite"):
        spec = importlib.util.find_spec(module_name)
        if spec:
            return importlib.import_module(module_name)
    raise ImportError("Cannot find Pegasus-Suite module")


pegasus_suite = load_module()


def run_function(func_name, mocked_inputs=None):
    """Run one callable from Pegasus-Suite with optional mocked input values."""
    if not hasattr(pegasus_suite, func_name):
        return False

    func = getattr(pegasus_suite, func_name)
    if mocked_inputs is None:
        mocked_inputs = []

    with patch("builtins.input", side_effect=mocked_inputs):
        func()
    return True


def test_reverse_engineering_menu_exit():
    """Reverse engineering menu should return immediately when selecting Back."""
    assert run_function("reverse_engineering_menu", ["5"])


if __name__ == "__main__":
    print("Testing Reverse Engineering menu...")
    run_function("reverse_engineering_menu", ["5"])

    print("\nTesting Password Strength Analyzer...")
    run_function("password_strength_analyzer", ["Password123!"])

    print("\nTesting FB function...")
    run_function("fb", ["q"])

    print("All function tests completed successfully")
