#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Compatibility imports for Python 2/3 support.
This module provides backward compatibility for old Python 2 code
to resolve linter errors in the main Pegasus-Suite.py file.
"""

import sys
import os

PY2 = sys.version_info[0] == 2

# Import libraries that exist in both Python 2 and 3
import re
import socket
import json
import glob
import random
import threading
import time
from getpass import getpass
from platform import system
from xml.dom import minidom
from optparse import OptionParser

# Version-specific imports
if PY2:
    # Python 2 imports
    import httplib
    import urllib2
    import Queue as queue
    import urlparse
    import commands
    # In Python 2, raw_input is built-in
    raw_input = raw_input  # type: ignore
    input_func = raw_input  # type: ignore
else:
    # Python 3 imports
    import http.client as httplib
    import urllib.request as urllib2
    import urllib.parse as urlparse
    import queue
    import subprocess as commands  # commands module is deprecated in Python 3
    # In Python 3, input() replaces raw_input()
    raw_input = input  # Define raw_input for Python 3
    input_func = input

# Common imports for both versions
import telnetlib

# Try to import requests with error handling
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None  # Define requests as None to avoid NameError

# Try to import colorama for colored terminal output
try:
    # Use type: ignore to prevent Pylance from flagging this
    from colorama import Fore, Style, init  # type: ignore
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Create dummy colorama classes
    class Fore:
        RED = ''
        GREEN = ''
        YELLOW = ''
        BLUE = ''
        MAGENTA = ''
        CYAN = ''
        WHITE = ''
        RESET = ''
    
    class Style:
        BRIGHT = ''
        RESET_ALL = ''

# Try to import tkinter for GUI features
try:
    if PY2:
        import Tkinter as tk
        import ttk
    else:
        import tkinter as tk
        from tkinter import ttk
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    tk = None
    ttk = None

# Define the URLError for compatibility with urllib
try:
    from urllib.error import URLError
except ImportError:
    try:
        from urllib2 import URLError
    except ImportError:
        class URLError(Exception):
            pass

# Define other variables and functions that might be referenced
def not_implemented(*args, **kwargs):
    """Placeholder for functions that are not implemented."""
    print("This function is not implemented yet.")
    return None

# Export all symbols
__all__ = [
    'httplib', 'urllib2', 'urlparse', 'queue', 'commands', 
    'input_func', 'raw_input', 'telnetlib', 'requests', 'REQUESTS_AVAILABLE',
    'Fore', 'Style', 'COLORAMA_AVAILABLE',
    'tk', 'ttk', 'GUI_AVAILABLE', 'PY2', 'not_implemented', 'URLError'
] 