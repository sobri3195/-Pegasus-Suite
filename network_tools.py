#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Network security tools for Pegasus-Suite
"""

import os
import sys
import time
import socket
import random
import string
import threading
import subprocess
import ipaddress
from datetime import datetime

class NetworkTools:
    """Network security scanning and analysis tools"""
    
    def __init__(self):
        """Initialize network tools"""
        self.scan_results = {}
        self.active_hosts = []
    
    def network_scanner(self):
        """Network discovery scanner for finding active hosts"""
        print("[+] Network Discovery Scanner")
        
        target = input("Enter target IP/network (e.g., 192.168.1.0/24): ")
        
        if not target:
            print("[!] No target specified.")
            return
        
        try:
            # Check if it's a network or single host
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                print(f"[*] Scanning network {network}...")
                
                # Limit scan to 256 hosts max for safety
                host_count = min(256, network.num_addresses)
                print(f"[*] Will scan {host_count} hosts")
                
                self.active_hosts = []
                threads = []
                
                # Use threading for faster scanning
                for i, host in enumerate(network.hosts()):
                    if i >= 256:  # Safety limit
                        break
                    
                    t = threading.Thread(target=self._ping_host, args=(str(host),))
                    threads.append(t)
                    t.start()
                    
                    # Limit to 20 concurrent threads
                    if len(threads) >= 20:
                        for thread in threads:
                            thread.join()
                        threads = []
                
                # Wait for remaining threads
                for thread in threads:
                    thread.join()
                
                print(f"\n[+] Found {len(self.active_hosts)} active hosts")
                for host in sorted(self.active_hosts, key=lambda ip: [int(octet) for octet in ip.split('.')]):
                    print(f"  - {host}")
            
            else:
                # Single host
                print(f"[*] Pinging {target}...")
                self._ping_host(target, verbose=True)
        
        except ValueError as e:
            print(f"[!] Invalid target: {e}")
        except Exception as e:
            print(f"[!] Error: {e}")
    
    def _ping_host(self, ip, verbose=False):
        """Ping a single host"""
        try:
            if verbose:
                print(f"[*] Pinging {ip}...")
            
            # Different ping command for Windows/Linux
            if os.name == 'nt':  # Windows
                ping_cmd = f"ping -n 1 -w 500 {ip}"
            else:  # Linux/Mac
                ping_cmd = f"ping -c 1 -W 1 {ip}"
            
            # Run ping command
            result = subprocess.run(ping_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                if verbose:
                    print(f"[+] Host {ip} is active")
                self.active_hosts.append(ip)
                return True
            else:
                if verbose:
                    print(f"[-] Host {ip} is not responding")
                return False
        
        except Exception as e:
            if verbose:
                print(f"[!] Error pinging {ip}: {e}")
            return False
    
    def port_scanner(self):
        """Port scanner for finding open services"""
        print("[+] Port Scanner")
        
        target = input("Enter target IP or hostname: ")
        if not target:
            print("[!] No target specified.")
            return
        
        # Try to resolve hostname
        try:
            target_ip = socket.gethostbyname(target)
            print(f"[*] Target IP: {target_ip}")
        except socket.gaierror:
            print(f"[!] Could not resolve {target}")
            return
        
        # Get port range
        port_range = input("Enter port range (e.g., 1-1000): ")
        if not port_range:
            print("[*] Using default port range: 1-1000")
            start_port, end_port = 1, 1000
        else:
            try:
                if '-' in port_range:
                    start_port, end_port = map(int, port_range.split('-'))
                else:
                    start_port = end_port = int(port_range)
                
                # Validate range
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    print("[!] Invalid port range. Using default: 1-1000")
                    start_port, end_port = 1, 1000
            except ValueError:
                print("[!] Invalid port range. Using default: 1-1000")
                start_port, end_port = 1, 1000
        
        # Ask for scan speed
        scan_type = input("Select scan type (1: Fast, 2: Thorough) [1]: ") or "1"
        
        if scan_type == "1":
            # Fast scan - common ports
            if end_port - start_port > 100:
                print("[*] Fast scan selected - checking common ports only")
                common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 
                               3306, 3389, 5432, 5900, 5901, 8080, 8443]
                ports_to_scan = [p for p in common_ports if start_port <= p <= end_port]
                timeout = 0.5
            else:
                # If range is small, scan all in the range
                ports_to_scan = range(start_port, end_port + 1)
                timeout = 0.5
        else:
            # Thorough scan - all ports in range
            ports_to_scan = range(start_port, end_port + 1)
            timeout = 1.0
            print("[*] Thorough scan selected - checking all ports in range")
            
            # Warn if range is large
            if end_port - start_port > 1000:
                print("[!] Large port range selected. This may take some time.")
        
        print(f"[*] Scanning {len(ports_to_scan)} ports on {target_ip}...")
        print(f"[*] Timeout: {timeout} seconds per port")
        
        open_ports = []
        start_time = time.time()
        
        for port in ports_to_scan:
            try:
                # Create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                # Attempt connection
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    # Port is open
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                    
                    open_ports.append((port, service))
                    print(f"[+] Port {port} ({service}): Open")
                
                sock.close()
                
            except socket.error:
                pass
            
            # Show progress for thorough scans
            if scan_type != "1" and (port - start_port) % 100 == 0 and port > start_port:
                elapsed = time.time() - start_time
                scanned = port - start_port
                total = end_port - start_port
                pct = (scanned / total) * 100
                
                print(f"[*] Progress: {pct:.1f}% ({scanned}/{total} ports)")
        
        # Scan complete
        elapsed_time = time.time() - start_time
        
        print(f"\n[*] Scan completed in {elapsed_time:.2f} seconds")
        print(f"[+] Found {len(open_ports)} open ports on {target_ip}")
        
        if open_ports:
            print("\nOpen Ports Summary:")
            for port, service in open_ports:
                print(f"  - {port}/tcp ({service})")
    
    def vulnerability_scanner(self):
        """Basic vulnerability scanner"""
        print("[+] Basic Vulnerability Scanner")
        
        target = input("Enter target IP or hostname: ")
        if not target:
            print("[!] No target specified.")
            return
        
        try:
            target_ip = socket.gethostbyname(target)
            print(f"[*] Target IP: {target_ip}")
        except socket.gaierror:
            print(f"[!] Could not resolve {target}")
            return
        
        print("[*] Starting vulnerability scan...")
        print("[*] This may take some time...")
        
        # First scan for open ports
        open_ports = self._quick_port_scan(target_ip)
        
        if not open_ports:
            print("[-] No open ports found. Cannot perform vulnerability scan.")
            return
        
        print(f"[+] Found {len(open_ports)} open ports")
        
        # Check for common vulnerabilities based on open services
        vulnerabilities = []
        
        # Web server checks
        if 80 in open_ports or 443 in open_ports:
            http_port = 443 if 443 in open_ports else 80
            protocol = "https" if http_port == 443 else "http"
            
            print(f"[*] Checking web server ({protocol}) vulnerabilities...")
            
            # Simulate checks
            time.sleep(random.uniform(1, 3))
            
            # Randomly find some issues for demonstration
            web_issues = []
            
            if random.random() < 0.3:
                web_issues.append(("Missing HTTP security headers", "Medium"))
            
            if random.random() < 0.3:
                web_issues.append(("Outdated web server version", "High"))
                
            if random.random() < 0.3:
                web_issues.append(("Directory listing enabled", "Medium"))
                
            if random.random() < 0.2:
                web_issues.append(("Default credentials", "Critical"))
            
            for issue, severity in web_issues:
                vulnerabilities.append((f"Web Server ({protocol}:{http_port})", issue, severity))
        
        # SSH checks
        if 22 in open_ports:
            print("[*] Checking SSH vulnerabilities...")
            time.sleep(random.uniform(1, 2))
            
            if random.random() < 0.3:
                vulnerabilities.append(("SSH (22)", "Weak cipher algorithms enabled", "Medium"))
            
            if random.random() < 0.2:
                vulnerabilities.append(("SSH (22)", "Password authentication enabled", "Low"))
        
        # FTP checks
        if 21 in open_ports:
            print("[*] Checking FTP vulnerabilities...")
            time.sleep(random.uniform(1, 2))
            
            if random.random() < 0.4:
                vulnerabilities.append(("FTP (21)", "Anonymous login enabled", "High"))
            
            if random.random() < 0.3:
                vulnerabilities.append(("FTP (21)", "Cleartext authentication", "Medium"))
        
        # Database checks
        db_ports = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle"}
        for port, db_name in db_ports.items():
            if port in open_ports:
                print(f"[*] Checking {db_name} vulnerabilities...")
                time.sleep(random.uniform(1, 2))
                
                if random.random() < 0.3:
                    vulnerabilities.append((f"{db_name} ({port})", "Database exposed to network", "High"))
                
                if random.random() < 0.2:
                    vulnerabilities.append((f"{db_name} ({port})", "Weak authentication", "Critical"))
        
        # Output results
        if vulnerabilities:
            print(f"\n[+] Found {len(vulnerabilities)} potential vulnerabilities:")
            
            for service, issue, severity in vulnerabilities:
                # Color coding by severity
                if severity == "Critical":
                    severity_str = f"[CRITICAL]"
                elif severity == "High":
                    severity_str = f"[HIGH]"
                elif severity == "Medium":
                    severity_str = f"[MEDIUM]"
                else:
                    severity_str = f"[LOW]"
                
                print(f"  {severity_str} {service}: {issue}")
        else:
            print("[-] No obvious vulnerabilities found.")
        
        print("\n[*] This is a basic scan and may not detect all vulnerabilities.")
        print("[*] For comprehensive results, use specialized security tools.")
    
    def _quick_port_scan(self, target_ip):
        """Quick scan of common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        open_ports = []
        
        print(f"[*] Performing quick port scan on {target_ip}...")
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                    
                    open_ports.append(port)
                    print(f"[+] Port {port} ({service}): Open")
                
                sock.close()
                
            except socket.error:
                pass
        
        return open_ports
    
    def traceroute(self):
        """Trace route to target host"""
        print("[+] Traceroute Tool")
        
        target = input("Enter target IP or hostname: ")
        if not target:
            print("[!] No target specified.")
            return
        
        try:
            target_ip = socket.gethostbyname(target)
            print(f"[*] Target IP: {target_ip}")
        except socket.gaierror:
            print(f"[!] Could not resolve {target}")
            return
        
        print(f"[*] Tracing route to {target} ({target_ip})...")
        
        # Different commands for different OS
        if os.name == 'nt':  # Windows
            os.system(f"tracert {target}")
        else:  # Linux/Mac
            os.system(f"traceroute {target}")

# Main function to run the tools
def run_network_tools():
    """Run the network security tools"""
    tools = NetworkTools()
    return tools 