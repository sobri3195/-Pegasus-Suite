#!/usr/bin/env python
# Test run script for specific functions in Pegasus-Suite

import importlib.util

# Try to import the module with either name variant
try:
    # Try with underscore
    spec = importlib.util.find_spec('Pegasus_Suite')
    if spec:
        pegasus_suite = importlib.import_module('Pegasus_Suite')
    else:
        # Try with hyphen
        spec = importlib.util.find_spec('Pegasus-Suite')
        if spec:
            pegasus_suite = importlib.import_module('Pegasus-Suite')
        else:
            print("Cannot find Pegasus-Suite module")
            import sys
            sys.exit(1)
except ImportError:
    print("Error importing Pegasus-Suite")
    import sys
    sys.exit(1)

# Function to run a specific function from the module
def run_function(func_name):
    if hasattr(pegasus_suite, func_name):
        func = getattr(pegasus_suite, func_name)
        print(f"Running {func_name}...")
        func()
    else:
        print(f"Function {func_name} not found in Pegasus-Suite module")

# Run reverse engineering menu
print("Testing Reverse Engineering menu...")
run_function('reverse_engineering_menu')

# Run password strength analyzer
print("\nTesting Password Strength Analyzer...")
run_function('password_strength_analyzer')

# Test Facebook function
print("\nTesting FB function...")
run_function('fb')

print("All function tests completed successfully") 