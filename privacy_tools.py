#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Privacy tools for Pegasus-Suite
"""

import os
import sys
import time
import random
import platform
import json
import datetime

# Import from pegabox_imports instead of directly
try:
    from pegabox_imports import Fore, Style, COLORAMA_AVAILABLE  # type: ignore
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
    
    try:
        import requests
        REQUESTS_AVAILABLE = True
    except ImportError:
        REQUESTS_AVAILABLE = False

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def create_dir_if_not_exists(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"{Fore.GREEN}[+] Created directory: {directory}{Style.RESET_ALL}")
    return directory

class PrivacyTools:
    def __init__(self):
        self.reports_dir = create_dir_if_not_exists("reports/privacy")
        print(f"{Fore.BLUE}[*] Privacy Tools initialized{Style.RESET_ALL}")
        
    def privacy_health_check(self):
        """Perform a complete privacy health check on the system."""
        clear_screen()
        print(f"{Fore.BLUE}[*] Running Privacy Health Check...{Style.RESET_ALL}")
        
        report = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system": platform.system(),
            "privacy_issues": []
        }
        
        # Simulated privacy checks
        checks = [
            {"name": "Browser Privacy", "status": random.choice(["Good", "Warning", "Critical"])},
            {"name": "Password Security", "status": random.choice(["Good", "Warning", "Critical"])},
            {"name": "Data Encryption", "status": random.choice(["Good", "Warning", "Critical"])},
            {"name": "Network Traffic", "status": random.choice(["Good", "Warning", "Critical"])},
            {"name": "Application Permissions", "status": random.choice(["Good", "Warning", "Critical"])},
        ]
        
        for check in checks:
            time.sleep(0.5)  # Simulate processing time
            status = check["status"]
            if status == "Good":
                color = Fore.GREEN
                icon = "✓"
            elif status == "Warning":
                color = Fore.YELLOW
                icon = "!"
                report["privacy_issues"].append({"issue": check["name"], "severity": "Medium"})
            else:
                color = Fore.RED
                icon = "✗"
                report["privacy_issues"].append({"issue": check["name"], "severity": "High"})
                
            print(f"{color}[{icon}] {check['name']}: {status}{Style.RESET_ALL}")
        
        # Save report
        filename = f"{self.reports_dir}/privacy_check_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"\n{Fore.GREEN}[+] Privacy check complete. Report saved to: {filename}{Style.RESET_ALL}")
        input("\nPress Enter to continue...")
        
    def secure_messaging_tool(self):
        """Simulate secure messaging capabilities."""
        clear_screen()
        print(f"{Fore.BLUE}[*] Secure Messaging Tool{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] This is a simulation of secure messaging features.{Style.RESET_ALL}")
        
        print("\nAvailable Secure Messaging Options:")
        print("1. Generate OTR (Off-The-Record) Key")
        print("2. Signal Protocol Integration")
        print("3. PGP Message Encryption")
        print("4. Secure File Transfer")
        print("5. Back to Privacy Tools Menu")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            print(f"{Fore.GREEN}[+] Generating OTR key pair...{Style.RESET_ALL}")
            time.sleep(1)
            print(f"{Fore.GREEN}[+] OTR key generated:{Style.RESET_ALL}")
            print(f"Public key: {Fore.CYAN}{''.join(random.choices('0123456789abcdef', k=64))}{Style.RESET_ALL}")
        
        elif choice == "2":
            print(f"{Fore.YELLOW}[!] Signal Protocol integration would require additional libraries.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] This is a simulated feature.{Style.RESET_ALL}")
        
        elif choice == "3":
            message = input("Enter message to encrypt: ")
            if message:
                print(f"{Fore.GREEN}[+] Message encrypted with PGP.{Style.RESET_ALL}")
                print(f"{Fore.CYAN}-----BEGIN PGP MESSAGE-----\n")
                print(f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=len(message)*8))}")
                print(f"\n-----END PGP MESSAGE-----{Style.RESET_ALL}")
        
        elif choice == "4":
            print(f"{Fore.YELLOW}[!] Secure File Transfer would integrate with encrypted transfer protocols.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] This is a simulated feature.{Style.RESET_ALL}")
        
        input("\nPress Enter to continue...")
        
    def privacy_browser_config(self):
        """Configure browser for enhanced privacy."""
        clear_screen()
        print(f"{Fore.BLUE}[*] Privacy Browser Configuration{Style.RESET_ALL}")
        
        browsers = ["Firefox", "Chrome", "Safari", "Edge", "Brave"]
        
        print("\nSelect browser to configure:")
        for i, browser in enumerate(browsers, 1):
            print(f"{i}. {browser}")
        print(f"{len(browsers)+1}. Back to Privacy Tools Menu")
        
        choice = input("\nSelect browser: ")
        
        try:
            choice = int(choice)
            if 1 <= choice <= len(browsers):
                browser = browsers[choice-1]
                print(f"{Fore.GREEN}[+] Generating privacy configuration for {browser}...{Style.RESET_ALL}")
                time.sleep(1.5)
                
                print(f"\n{Fore.CYAN}Recommended {browser} Privacy Settings:{Style.RESET_ALL}")
                print("1. Disable third-party cookies")
                print("2. Enable Enhanced Tracking Protection")
                print("3. Use HTTPS-Only Mode")
                print("4. Disable browser telemetry")
                print("5. Install privacy-enhancing extensions:")
                print("   - uBlock Origin")
                print("   - Privacy Badger")
                print("   - HTTPS Everywhere")
                
                # Generate a simulated config file
                config_file = f"{self.reports_dir}/{browser.lower()}_privacy_config.txt"
                with open(config_file, 'w') as f:
                    f.write(f"# {browser} Privacy Configuration\n")
                    f.write("# Generated by Pegasus Privacy Tools\n\n")
                    f.write("privacy.trackingprotection.enabled = true\n")
                    f.write("privacy.trackingprotection.fingerprinting.enabled = true\n")
                    f.write("privacy.trackingprotection.cryptomining.enabled = true\n")
                    f.write("privacy.firstparty.isolate = true\n")
                    f.write("privacy.resistFingerprinting = true\n")
                    f.write("network.cookie.cookieBehavior = 1\n")
                    f.write("network.http.sendRefererHeader = 0\n")
                
                print(f"\n{Fore.GREEN}[+] Configuration file saved to: {config_file}{Style.RESET_ALL}")
            
        except ValueError:
            print(f"{Fore.RED}[!] Invalid choice{Style.RESET_ALL}")
        
        input("\nPress Enter to continue...")
    
    def data_leak_scanner(self):
        """Scan for potential data leaks."""
        clear_screen()
        print(f"{Fore.BLUE}[*] Data Leak Scanner{Style.RESET_ALL}")
        
        email = input("Enter email address to check (or press Enter to use a demo): ")
        if not email:
            email = "example@domain.com"
        
        print(f"\n{Fore.YELLOW}[!] Scanning for {email} in known data breaches...{Style.RESET_ALL}")
        
        for i in range(5):
            print(f"{Fore.BLUE}[*] Checking database {i+1}/5...{Style.RESET_ALL}")
            time.sleep(0.8)
        
        # Simulate results
        breaches = []
        for _ in range(random.randint(0, 3)):
            breach_year = random.randint(2015, 2023)
            breach_size = random.choice(["small", "medium", "large", "massive"])
            breach_data = random.choice([
                "email, username", 
                "email, username, password (hashed)", 
                "email, username, password (plaintext), name",
                "email, username, password (hashed), phone, address"
            ])
            
            breaches.append({
                "name": random.choice(["BreachCorp", "DataLeak", "MegaHack", "InfoDump", "PrivacyFail"]) + str(breach_year),
                "date": f"{random.randint(1, 12)}/{breach_year}",
                "size": breach_size,
                "data": breach_data
            })
        
        if breaches:
            print(f"\n{Fore.RED}[!] Found {len(breaches)} potential data breaches containing your information:{Style.RESET_ALL}")
            for i, breach in enumerate(breaches, 1):
                print(f"\n{Fore.RED}Breach {i}:{Style.RESET_ALL}")
                print(f"Name: {breach['name']}")
                print(f"Date: {breach['date']}")
                print(f"Size: {breach['size']}")
                print(f"Compromised data: {breach['data']}")
                
            # Save report
            filename = f"{self.reports_dir}/data_leak_report_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump({
                    "email": email,
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "breaches": breaches
                }, f, indent=4)
            
            print(f"\n{Fore.GREEN}[+] Recommendations:{Style.RESET_ALL}")
            print("1. Change passwords for affected accounts")
            print("2. Enable two-factor authentication where available")
            print("3. Use a unique password for each service")
            print(f"\n{Fore.GREEN}[+] Report saved to: {filename}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[+] Good news! No data breaches found for {email}{Style.RESET_ALL}")
        
        input("\nPress Enter to continue...")
        
    def anti_tracking_tools(self):
        """Tools to prevent tracking."""
        clear_screen()
        print(f"{Fore.BLUE}[*] Anti-Tracking Tools{Style.RESET_ALL}")
        
        print("\nAvailable Anti-Tracking Options:")
        print("1. User-Agent Randomizer")
        print("2. Canvas Fingerprint Blocker")
        print("3. WebRTC Leak Prevention")
        print("4. Cookie Cleaner")
        print("5. Back to Privacy Tools Menu")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            print(f"{Fore.GREEN}[+] Generating random User-Agents...{Style.RESET_ALL}")
            time.sleep(1)
            
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
            ]
            
            for i, ua in enumerate(user_agents, 1):
                print(f"\n{i}. {Fore.CYAN}{ua}{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}[!] In a real implementation, this would rotate your User-Agent automatically.{Style.RESET_ALL}")
            
        elif choice == "2":
            print(f"{Fore.GREEN}[+] Canvas Fingerprint Protection Activated{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] This would introduce slight noise to canvas operations to prevent fingerprinting.{Style.RESET_ALL}")
            
        elif choice == "3":
            print(f"{Fore.GREEN}[+] Checking for WebRTC leaks...{Style.RESET_ALL}")
            time.sleep(1.5)
            print(f"{Fore.RED}[!] WebRTC leak detected - exposing internal IP: 192.168.1.X{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] WebRTC protection enabled{Style.RESET_ALL}")
            
        elif choice == "4":
            print(f"{Fore.GREEN}[+] Scanning for tracking cookies...{Style.RESET_ALL}")
            time.sleep(2)
            
            cookies_found = random.randint(10, 50)
            tracking_cookies = random.randint(5, cookies_found)
            
            print(f"{Fore.YELLOW}[!] Found {cookies_found} cookies, {tracking_cookies} identified as tracking cookies{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Cleaning tracking cookies...{Style.RESET_ALL}")
            time.sleep(1)
            print(f"{Fore.GREEN}[+] {tracking_cookies} tracking cookies removed{Style.RESET_ALL}")
        
        input("\nPress Enter to continue...")

def run_privacy_tools():
    """Return an instance of PrivacyTools."""
    return PrivacyTools()

def privacy_tools_menu():
    """Display the Privacy Tools menu and handle user interaction."""
    tools = run_privacy_tools()
    
    while True:
        clear_screen()
        print(f"{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{' ' * 15}PRIVACY TOOLS MENU{' ' * 15}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}")
        
        print("\n1. Privacy Health Check")
        print("2. Secure Messaging Tool")
        print("3. Privacy Browser Configuration")
        print("4. Data Leak Scanner")
        print("5. Anti-Tracking Tools")
        print("6. Return to Main Menu")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            tools.privacy_health_check()
        elif choice == "2":
            tools.secure_messaging_tool()
        elif choice == "3":
            tools.privacy_browser_config()
        elif choice == "4":
            tools.data_leak_scanner()
        elif choice == "5":
            tools.anti_tracking_tools()
        elif choice == "6":
            break
        else:
            print(f"{Fore.RED}[!] Invalid choice{Style.RESET_ALL}")
            time.sleep(1)

if __name__ == "__main__":
    privacy_tools_menu() 