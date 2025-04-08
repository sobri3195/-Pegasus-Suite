print("Starting import check")
try:
    print("Checking imports...")
    # Python 2 style imports that need to be handled
    try:
        import httplib
        print("httplib imported directly")
    except ImportError:
        import http.client
        print("http.client imported instead of httplib")
    
    try:
        import urllib2
        print("urllib2 imported directly")
    except ImportError:
        import urllib.request
        print("urllib.request imported instead of urllib2")
    
    try:
        import Queue
        print("Queue imported directly")
    except ImportError:
        import queue
        print("queue imported instead of Queue")
    
    try:
        import telnetlib
        print("telnetlib imported")
    except ImportError:
        print("Failed to import telnetlib")
    
    try:
        from commands import *
        print("commands imported directly")
    except ImportError:
        import subprocess
        print("subprocess imported instead of commands")
    
    try:
        from urlparse import urlparse
        print("urlparse imported directly")
    except ImportError:
        from urllib.parse import urlparse
        print("urllib.parse imported instead of urlparse")
    
    # Now check if raw_input is accessible
    try:
        # This is a check to see if raw_input exists, we don't actually run it
        if 'raw_input' in dir(__builtins__):
            print("raw_input is accessible directly")
        else:
            # In Python 3, input is used instead
            print("input is used instead of raw_input")
    except Exception as e:
        print(f"Error checking raw_input: {e}")
    
    print("All imports checked successfully")
except Exception as e:
    print(f"Error: {e}") 