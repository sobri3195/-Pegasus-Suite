#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Reporting tools for Pegasus-Suite
Provides functionality for creating, formatting and exporting reports
"""

import os
import sys
import json
import datetime
from platform import system
import re

# Import from pegabox_imports instead of directly
try:
    from pegabox_imports import Fore, Style, COLORAMA_AVAILABLE  # type: ignore
    if COLORAMA_AVAILABLE:
        from colorama import init  # type: ignore
        init(autoreset=True)
except ImportError:
    # Fallback if pegabox_imports is not available
    try:
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

def create_dir_if_not_exists(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        if COLORAMA_AVAILABLE:
            print(f"{Fore.GREEN}[+] Created directory: {directory}{Style.RESET_ALL}")
        else:
            print(f"[+] Created directory: {directory}")
    return directory

class ReportingTools:
    """Tools for generating assessment reports"""
    
    def __init__(self):
        """Initialize reporting tools"""
        self.reports_dir = create_dir_if_not_exists("reports")
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.system_info = {
            "os": system(),
            "release": system(),
            "version": system(),
            "machine": system(),
            "processor": system()
        }
    
    def create_text_report(self, title, content, category="general"):
        """
        Create a simple text report
        
        Args:
            title (str): Report title
            content (str): Report content
            category (str): Report category
        
        Returns:
            str: Path to the saved report
        """
        category_dir = create_dir_if_not_exists(os.path.join(self.reports_dir, category))
        
        # Sanitize title for filename
        sanitized_title = re.sub(r'[^\w\-_.]', '_', title)
        filename = f"{sanitized_title}_{self.timestamp}.txt"
        file_path = os.path.join(category_dir, filename)
        
        try:
            with open(file_path, 'w') as f:
                f.write(f"{title}\n")
                f.write(f"{'=' * len(title)}\n\n")
                f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"System: {self.system_info['os']} {self.system_info['release']}\n\n")
                f.write(content)
            
            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}[+] Report saved to: {file_path}{Style.RESET_ALL}")
            else:
                print(f"[+] Report saved to: {file_path}")
            
            return file_path
        except Exception as e:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}[!] Error saving report: {e}{Style.RESET_ALL}")
            else:
                print(f"[!] Error saving report: {e}")
            return None
    
    def create_json_report(self, title, data, category="general"):
        """
        Create a JSON report
        
        Args:
            title (str): Report title
            data (dict): Report data
            category (str): Report category
        
        Returns:
            str: Path to the saved report
        """
        category_dir = create_dir_if_not_exists(os.path.join(self.reports_dir, category))
        
        # Sanitize title for filename
        sanitized_title = re.sub(r'[^\w\-_.]', '_', title)
        filename = f"{sanitized_title}_{self.timestamp}.json"
        file_path = os.path.join(category_dir, filename)
        
        # Add metadata to report
        report_data = {
            "title": title,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_info": self.system_info,
            "data": data
        }
        
        try:
            with open(file_path, 'w') as f:
                json.dump(report_data, f, indent=4)
            
            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}[+] JSON report saved to: {file_path}{Style.RESET_ALL}")
            else:
                print(f"[+] JSON report saved to: {file_path}")
            
            return file_path
        except Exception as e:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}[!] Error saving JSON report: {e}{Style.RESET_ALL}")
            else:
                print(f"[!] Error saving JSON report: {e}")
            return None
    
    def create_html_report(self, title, content, category="general"):
        """
        Create an HTML report
        
        Args:
            title (str): Report title
            content (str): Report content (can include HTML)
            category (str): Report category
        
        Returns:
            str: Path to the saved report
        """
        category_dir = create_dir_if_not_exists(os.path.join(self.reports_dir, category))
        
        # Sanitize title for filename
        sanitized_title = re.sub(r'[^\w\-_.]', '_', title)
        filename = f"{sanitized_title}_{self.timestamp}.html"
        file_path = os.path.join(category_dir, filename)
        
        # Create simple HTML template
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        .metadata {{
            background-color: #f2f2f2;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        pre {{
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
        }}
        .success {{ color: #27ae60; }}
        .warning {{ color: #f39c12; }}
        .danger {{ color: #e74c3c; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <div class="metadata">
            <p><strong>Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>System:</strong> {self.system_info['os']} {self.system_info['release']}</p>
        </div>
        <div class="content">
            {content}
        </div>
    </div>
</body>
</html>"""
        
        try:
            with open(file_path, 'w') as f:
                f.write(html_content)
            
            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}[+] HTML report saved to: {file_path}{Style.RESET_ALL}")
            else:
                print(f"[+] HTML report saved to: {file_path}")
            
            return file_path
        except Exception as e:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}[!] Error saving HTML report: {e}{Style.RESET_ALL}")
            else:
                print(f"[!] Error saving HTML report: {e}")
            return None

def run_reporting_tools():
    """Return an instance of the reporting tools."""
    return ReportingTools() 