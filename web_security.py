#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Web Application Security Tools for Pegasus-Suite
"""

import os
import sys
import time
import random
import string
import socket
import re
import urllib.parse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] Requests library not available. Limited functionality.")

class WebSecurityTools:
    """Web application security scanning tools"""
    
    def __init__(self):
        """Initialize web security tools"""
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        self.headers = {"User-Agent": self.user_agent}
        self.timeout = 10
    
    def sqli_scanner(self):
        """SQL Injection vulnerability scanner"""
        print("[+] SQL Injection Scanner")
        
        if not REQUESTS_AVAILABLE:
            print("[!] This tool requires the requests library.")
            print("[!] Install it with: pip install requests")
            return
        
        target = input("Enter target URL (e.g., http://example.com/page.php?id=1): ")
        if not target:
            print("[!] No target provided.")
            return
        
        if not (target.startswith('http://') or target.startswith('https://')):
            target = 'http://' + target
        
        print(f"[*] Target: {target}")
        
        # Basic SQL injection payloads
        payloads = [
            "'", 
            "\"", 
            "1' OR '1'='1", 
            "1\" OR \"1\"=\"1", 
            "' OR 1=1 --", 
            "\" OR 1=1 --", 
            "' OR '1'='1' --", 
            "1' OR '1'='1' --", 
            "admin' --",
            "1'; DROP TABLE users--",
            "1' UNION SELECT 1,2,3--"
        ]
        
        # Error strings that might indicate SQL injection vulnerability
        error_strings = [
            "SQL syntax",
            "MySQL Error",
            "ORA-",
            "Oracle Error",
            "Microsoft SQL Server",
            "ODBC Driver",
            "DB2 SQL Error",
            "SQLite Error",
            "PostgreSQL Error",
            "Unclosed quotation mark",
            "mysql_fetch_array()",
            "Warning: mysql_",
            "function.mysql",
            "MySQL Result"
        ]
        
        print("[*] Testing for SQL injection vulnerabilities...")
        
        # Parse the URL to extract parameters
        parsed_url = urllib.parse.urlparse(target)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if not query_params:
            print("[!] No parameters found in the URL.")
            print("[!] Try a URL with parameters like: http://example.com/page.php?id=1")
            return
        
        print(f"[+] Found parameters: {', '.join(query_params.keys())}")
        
        # Test each parameter
        vulnerable_params = []
        
        try:
            # First get the baseline response
            print("[*] Getting baseline response...")
            baseline_response = requests.get(target, headers=self.headers, timeout=self.timeout)
            baseline_length = len(baseline_response.text)
            baseline_status = baseline_response.status_code
            
            print(f"[*] Baseline response: {baseline_status} status, {baseline_length} bytes")
            
            # Test each parameter with each payload
            for param in query_params:
                print(f"\n[*] Testing parameter: {param}")
                param_value = query_params[param][0]  # Get the original value
                
                for payload in payloads:
                    # Create new query parameters with the payload
                    new_params = query_params.copy()
                    new_params[param] = [payload]
                    
                    # Create new query string
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    
                    # Create new URL
                    new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    print(f"[*] Testing: {payload}")
                    
                    try:
                        response = requests.get(new_url, headers=self.headers, timeout=self.timeout)
                        
                        # Check for significant difference in response size
                        size_diff = abs(len(response.text) - baseline_length)
                        is_significant = size_diff > 50 or response.status_code != baseline_status
                        
                        # Check for error messages
                        has_error = any(error in response.text for error in error_strings)
                        
                        if is_significant or has_error:
                            print(f"[+] Potential SQL injection found!")
                            print(f"    Parameter: {param}")
                            print(f"    Payload: {payload}")
                            print(f"    Response status: {response.status_code}")
                            print(f"    Response size: {len(response.text)} bytes (diff: {size_diff})")
                            
                            if has_error:
                                print(f"    SQL error message detected")
                            
                            if param not in vulnerable_params:
                                vulnerable_params.append(param)
                        
                    except requests.RequestException as e:
                        print(f"[!] Error testing {payload}: {e}")
            
            # Summary
            if vulnerable_params:
                print(f"\n[+] Found {len(vulnerable_params)} potentially vulnerable parameters:")
                for param in vulnerable_params:
                    print(f"  - {param}")
                
                print("\n[*] Recommended actions:")
                print("  1. Validate and sanitize all input parameters")
                print("  2. Use prepared statements or parameterized queries")
                print("  3. Implement proper input validation")
                print("  4. Apply the principle of least privilege on database accounts")
            else:
                print("\n[-] No obvious SQL injection vulnerabilities detected.")
                print("[*] Note: This doesn't guarantee the site is secure.")
                print("[*] Consider more advanced testing for complex vulnerabilities.")
        
        except Exception as e:
            print(f"[!] Error scanning for SQL injection: {e}")
    
    def xss_scanner(self):
        """Cross-Site Scripting (XSS) vulnerability scanner"""
        print("[+] Cross-Site Scripting (XSS) Scanner")
        
        if not REQUESTS_AVAILABLE:
            print("[!] This tool requires the requests library.")
            print("[!] Install it with: pip install requests")
            return
        
        target = input("Enter target URL (e.g., http://example.com/page.php?search=test): ")
        if not target:
            print("[!] No target provided.")
            return
        
        if not (target.startswith('http://') or target.startswith('https://')):
            target = 'http://' + target
        
        print(f"[*] Target: {target}")
        
        # XSS payloads to test
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "';alert('XSS');//",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>prompt('XSS')</script>",
            "<img src=x onmouseover=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
        ]
        
        print("[*] Testing for XSS vulnerabilities...")
        
        # Parse the URL to extract parameters
        parsed_url = urllib.parse.urlparse(target)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if not query_params:
            print("[!] No parameters found in the URL.")
            print("[!] Try a URL with parameters like: http://example.com/page.php?search=test")
            return
        
        print(f"[+] Found parameters: {', '.join(query_params.keys())}")
        
        # Test each parameter
        vulnerable_params = []
        
        try:
            for param in query_params:
                print(f"\n[*] Testing parameter: {param}")
                param_value = query_params[param][0]  # Get the original value
                
                for payload in payloads:
                    # Create new query parameters with the payload
                    new_params = query_params.copy()
                    new_params[param] = [payload]
                    
                    # Create new query string
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    
                    # Create new URL
                    new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    print(f"[*] Testing: {payload[:30]}...")  # Show truncated payload
                    
                    try:
                        response = requests.get(new_url, headers=self.headers, timeout=self.timeout)
                        
                        # Check if the payload is reflected in the response
                        # We need to decode it first since urlencode will encode special characters
                        decoded_payload = urllib.parse.unquote(payload)
                        if decoded_payload in response.text:
                            print(f"[+] Potential XSS vulnerability found!")
                            print(f"    Parameter: {param}")
                            print(f"    Payload: {payload}")
                            print(f"    Payload was reflected in the response")
                            
                            if param not in vulnerable_params:
                                vulnerable_params.append(param)
                        
                    except requests.RequestException as e:
                        print(f"[!] Error testing {payload}: {e}")
            
            # Summary
            if vulnerable_params:
                print(f"\n[+] Found {len(vulnerable_params)} potentially vulnerable parameters:")
                for param in vulnerable_params:
                    print(f"  - {param}")
                
                print("\n[*] Recommended actions:")
                print("  1. Implement output encoding for user-controlled data")
                print("  2. Use Content-Security-Policy headers")
                print("  3. Validate input and sanitize output")
                print("  4. Consider using an XSS protection library")
            else:
                print("\n[-] No obvious XSS vulnerabilities detected.")
                print("[*] Note: This doesn't guarantee the site is secure.")
                print("[*] Manual testing is recommended for complex XSS patterns.")
        
        except Exception as e:
            print(f"[!] Error scanning for XSS: {e}")
    
    def directory_scan(self):
        """Web directory and file scanner"""
        print("[+] Web Directory Scanner")
        
        if not REQUESTS_AVAILABLE:
            print("[!] This tool requires the requests library.")
            print("[!] Install it with: pip install requests")
            return
        
        target = input("Enter target URL (e.g., http://example.com): ")
        if not target:
            print("[!] No target provided.")
            return
        
        if not (target.startswith('http://') or target.startswith('https://')):
            target = 'http://' + target
        
        # Remove trailing slash if present
        if target.endswith('/'):
            target = target[:-1]
        
        print(f"[*] Target: {target}")
        
        # Common directories and files to check
        common_paths = [
            "/admin",
            "/administrator",
            "/wp-admin",
            "/login",
            "/wp-login.php",
            "/admin.php",
            "/upload",
            "/uploads",
            "/backup",
            "/backups",
            "/config",
            "/dashboard",
            "/phpinfo.php",
            "/phpmyadmin",
            "/robots.txt",
            "/server-status",
            "/.git",
            "/.env",
            "/tmp",
            "/log",
            "/logs",
            "/old",
            "/db",
            "/database",
            "/sql",
            "/test",
            "/dev",
            "/install",
            "/setup",
            "/files",
            "/includes",
            "/images",
            "/js",
            "/css",
            "/assets",
            "/api",
            "/v1",
            "/v2",
            "/admin/config.php",
            "/config.php",
            "/info.php",
            "/xmlrpc.php",
            "/wp-config.php",
            "/readme.html"
        ]
        
        print(f"[*] Scanning {len(common_paths)} common directories and files...")
        print("[*] This may take some time...")
        
        found_paths = []
        start_time = time.time()
        
        try:
            for path in common_paths:
                url = f"{target}{path}"
                
                try:
                    response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
                    status = response.status_code
                    size = len(response.content)
                    
                    if status in [200, 301, 302, 403]:  # Found or redirected or forbidden
                        found_paths.append((path, status, size))
                        status_text = self._get_status_text(status)
                        print(f"[+] {url} - {status} {status_text} - {size} bytes")
                
                except requests.RequestException as e:
                    pass  # Silently ignore errors for cleaner output
            
            # Scan complete
            elapsed_time = time.time() - start_time
            
            if found_paths:
                print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds")
                print(f"[+] Found {len(found_paths)} accessible paths:")
                
                print("\nSummary:")
                for path, status, size in found_paths:
                    status_text = self._get_status_text(status)
                    print(f"  {path} - {status} {status_text} - {size} bytes")
                
                print("\n[*] Consider checking these paths for sensitive information or vulnerabilities")
            else:
                print(f"\n[-] Scan completed in {elapsed_time:.2f} seconds")
                print("[-] No accessible paths found")
                print("[*] The target may be well-secured or using non-standard paths")
        
        except Exception as e:
            print(f"[!] Error during directory scan: {e}")
    
    def _get_status_text(self, status):
        """Get text description of HTTP status code"""
        status_texts = {
            200: "OK",
            301: "Moved Permanently",
            302: "Found",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error"
        }
        return status_texts.get(status, "")
    
    def cms_detector(self):
        """Content Management System (CMS) detector"""
        print("[+] CMS Detector")
        
        if not REQUESTS_AVAILABLE:
            print("[!] This tool requires the requests library.")
            print("[!] Install it with: pip install requests")
            return
        
        target = input("Enter target URL (e.g., http://example.com): ")
        if not target:
            print("[!] No target provided.")
            return
        
        if not (target.startswith('http://') or target.startswith('https://')):
            target = 'http://' + target
        
        # Remove trailing slash if present
        if target.endswith('/'):
            target = target[:-1]
        
        print(f"[*] Target: {target}")
        print("[*] Detecting CMS...")
        
        # CMS detection patterns
        cms_patterns = {
            "WordPress": [
                "/wp-content/",
                "/wp-includes/",
                "/wp-admin/",
                "<meta name=\"generator\" content=\"WordPress",
                "/wp-login.php",
                "wp-content/themes/",
                "wp-content/plugins/"
            ],
            "Joomla": [
                "/media/system/js/",
                "/media/jui/",
                "/administrator/",
                "<meta name=\"generator\" content=\"Joomla",
                "/templates/system/",
                "window.joomla"
            ],
            "Drupal": [
                "/sites/default/",
                "/sites/all/",
                "/core/misc/drupal.js",
                "<meta name=\"generator\" content=\"Drupal",
                "jQuery.extend(Drupal.settings",
                "Drupal.behaviors"
            ],
            "Magento": [
                "/skin/frontend/",
                "/js/prototype/",
                "<meta name=\"generator\" content=\"Magento",
                "var BLANK_URL = '",
                "var BLANK_IMG = '",
                "Mage.Cookies.path"
            ],
            "PrestaShop": [
                "/modules/",
                "/themes/",
                "<meta name=\"generator\" content=\"PrestaShop",
                "var prestashop",
                "var baseUri",
                "var baseDir"
            ],
            "Shopify": [
                "cdn.shopify.com",
                "/cdn/shop/",
                "Shopify.theme",
                "<meta name=\"shopify-digital-wallet"
            ],
            "Wix": [
                "static.wixstatic.com",
                "wix-viewer",
                "<meta name=\"generator\" content=\"Wix"
            ],
            "Squarespace": [
                "static1.squarespace.com",
                "<meta name=\"generator\" content=\"Squarespace",
                "Static.SQUARESPACE_CONTEXT"
            ]
        }
        
        # Paths to check for CMS identification
        check_paths = [
            "/",                    # Homepage
            "/robots.txt",          # Robots.txt file
            "/administrator/",      # Joomla admin
            "/wp-login.php",        # WordPress login
            "/wp-admin/",           # WordPress admin
            "/admin/",              # Generic admin
            "/user/login"           # Drupal login
        ]
        
        cms_scores = {}
        
        try:
            # Check the main page first
            main_response = requests.get(target, headers=self.headers, timeout=self.timeout)
            main_content = main_response.text
            
            # Initialize CMS scores
            for cms in cms_patterns:
                cms_scores[cms] = 0
            
            # Check patterns in the main page
            for cms, patterns in cms_patterns.items():
                for pattern in patterns:
                    if pattern in main_content:
                        cms_scores[cms] += 3  # Main page matches are more significant
                        print(f"[+] Found {cms} pattern: {pattern}")
            
            # Check additional paths
            for path in check_paths:
                if path == "/":  # Already checked
                    continue
                    
                try:
                    response = requests.get(target + path, headers=self.headers, timeout=self.timeout, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 403]:  # Found or redirected
                        content = response.text
                        
                        for cms, patterns in cms_patterns.items():
                            for pattern in patterns:
                                if pattern in content:
                                    cms_scores[cms] += 1
                                    print(f"[+] Found {cms} pattern at {path}: {pattern}")
                
                except requests.RequestException:
                    pass  # Ignore errors for individual paths
            
            # Additional specific checks
            
            # WordPress version check
            if cms_scores["WordPress"] > 0:
                wp_version = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', main_content)
                if wp_version:
                    print(f"[+] WordPress version: {wp_version.group(1)}")
            
            # Joomla version check
            if cms_scores["Joomla"] > 0:
                joomla_version = re.search(r'<meta name="generator" content="Joomla! ([0-9.]+)"', main_content)
                if joomla_version:
                    print(f"[+] Joomla version: {joomla_version.group(1)}")
            
            # Determine the most likely CMS
            detected_cms = None
            highest_score = 0
            
            for cms, score in cms_scores.items():
                if score > highest_score:
                    highest_score = score
                    detected_cms = cms
            
            print("\n[*] Scan complete")
            
            if detected_cms and highest_score >= 3:
                print(f"[+] Detected CMS: {detected_cms} (confidence: {highest_score})")
                
                # Additional guidance based on detected CMS
                if detected_cms == "WordPress":
                    print("\n[*] Common WordPress security issues:")
                    print("  - Outdated core, themes, or plugins")
                    print("  - Weak admin credentials")
                    print("  - XML-RPC vulnerabilities")
                    print("  - Exposed wp-config.php")
                    print("\n[*] Recommended actions:")
                    print("  - Keep WordPress and all components updated")
                    print("  - Use strong passwords and limit login attempts")
                    print("  - Consider security plugins like Wordfence or Sucuri")
                elif detected_cms == "Joomla":
                    print("\n[*] Common Joomla security issues:")
                    print("  - Outdated core or extensions")
                    print("  - Insecure administrator access")
                    print("  - Directory traversal vulnerabilities")
                    print("\n[*] Recommended actions:")
                    print("  - Keep Joomla and extensions updated")
                    print("  - Rename /administrator directory")
                    print("  - Implement strong password policies")
                elif detected_cms == "Drupal":
                    print("\n[*] Common Drupal security issues:")
                    print("  - Outdated core or modules")
                    print("  - SQL injection vulnerabilities")
                    print("  - Access bypass issues")
                    print("\n[*] Recommended actions:")
                    print("  - Keep Drupal core and modules updated")
                    print("  - Implement security-focused configuration")
                    print("  - Regularly audit user permissions")
            else:
                print("[-] Could not confidently detect CMS. The website may:")
                print("  - Use a custom CMS or framework")
                print("  - Hide its technology stack effectively")
                print("  - Use a CMS not in our detection database")
        
        except Exception as e:
            print(f"[!] Error during CMS detection: {e}")

# Main function to run the tools
def run_web_security_tools():
    """Run the web security tools"""
    tools = WebSecurityTools()
    return tools 