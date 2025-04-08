#!/usr/bin/env python
# Function checker for Pegasus-Suite

import sys
import inspect
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
            sys.exit(1)
except ImportError:
    print("Error importing Pegasus-Suite")
    sys.exit(1)

def list_functions():
    """List all functions in the Pegasus-Suite module"""
    all_functions = []
    
    for name, obj in inspect.getmembers(pegasus_suite):
        if inspect.isfunction(obj):
            all_functions.append(name)
    
    # Sort alphabetically
    all_functions.sort()
    
    print(f"Pegasus-Suite has {len(all_functions)} functions:")
    for func in all_functions:
        print(f"- {func}")

def check_function_existence(func_name):
    """Check if a specific function exists in the Pegasus-Suite module"""
    if hasattr(pegasus_suite, func_name):
        func = getattr(pegasus_suite, func_name)
        if inspect.isfunction(func):
            print(f"✓ Function '{func_name}' exists")
            # Show function signature and docstring if available
            sig = inspect.signature(func)
            print(f"  Signature: {func_name}{sig}")
            if func.__doc__:
                doc = func.__doc__.strip()
                print(f"  Documentation: {doc}")
            return True
        else:
            print(f"✗ '{func_name}' exists but is not a function")
    else:
        print(f"✗ Function '{func_name}' does not exist")
    return False

def check_variable_existence(var_name):
    """Check if a specific variable exists in the Pegasus-Suite module"""
    if hasattr(pegasus_suite, var_name):
        value = getattr(pegasus_suite, var_name)
        print(f"✓ Variable '{var_name}' exists")
        print(f"  Type: {type(value).__name__}")
        return True
    else:
        print(f"✗ Variable '{var_name}' does not exist")
    return False

if __name__ == "__main__":
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python function_checker.py list")
        print("  python function_checker.py check <function_name>")
        print("  python function_checker.py check-var <variable_name>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "list":
        list_functions()
    elif command == "check" and len(sys.argv) >= 3:
        check_function_existence(sys.argv[2])
    elif command == "check-var" and len(sys.argv) >= 3:
        check_variable_existence(sys.argv[2])
    else:
        print("Invalid command")
        sys.exit(1) 