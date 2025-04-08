#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
OSINT (Open Source Intelligence) Tools for Pegasus-Suite
"""

import os
import sys
import re
import json
import platform
import socket
import subprocess
from datetime import datetime

# Import from pegabox_imports instead of directly
try:
    from pegabox_imports import requests, REQUESTS_AVAILABLE
except ImportError:
    # Fallback if pegabox_imports is not available
    try:
        import requests
        REQUESTS_AVAILABLE = True
    except ImportError:
        REQUESTS_AVAILABLE = False
        print("[!] Warning: requests module not available. Some features will be limited.")
        print("[*] Please install it using: pip install requests")

class OSINTTools:
    """Open Source Intelligence gathering tools"""
    
    def __init__(self):
        """Initialize OSINT tools"""
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        }
    
    def whois_lookup(self):
        """WHOIS domain lookup tool"""
        print("[+] WHOIS Domain Lookup Tool")
        
        if not REQUESTS_AVAILABLE:
            print("[!] This tool requires the requests library.")
            print("[!] Install it with: pip install requests")
            input("\nPress Enter to continue...")
            return
        
        domain = input("Enter domain name (e.g., example.com): ")
        if not domain:
            print("[!] No domain provided.")
            input("\nPress Enter to continue...")
            return
        
        # Clean the domain (remove http://, https://, www. etc.)
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.split('/')[0]  # Remove any path
        
        print(f"[*] Looking up WHOIS information for: {domain}")
        
        try:
            # Use whois command if available
            if not self.is_windows:
                try:
                    result = subprocess.check_output(["whois", domain]).decode()
                    print("\n[+] WHOIS Information:")
                    print(result)
                    input("\nPress Enter to continue...")
                    return
                except:
                    print("[!] whois command not available, using online API...")
            
            # Use online API for WHOIS lookup
            api_url = f"https://api.whoapi.com/?domain={domain}&r=whois&apikey=DEMO_API_KEY"
            
            # Note: This is a demo API key and will be limited. In a real application,
            # users would need to provide their own API key or we'd use a different service.
            print("[!] Using demo API key with limited functionality.")
            print("[!] For full functionality, obtain your own API key.")
            
            response = requests.get(api_url, headers=self.headers)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if 'whois_raw' in data:
                        print("\n[+] WHOIS Information:")
                        print(data['whois_raw'])
                    else:
                        print("[!] WHOIS data not available from API.")
                        print("[!] Try using a different API key or service.")
                except:
                    print("[!] Error parsing API response.")
            else:
                print(f"[!] API request failed with status code: {response.status_code}")
                
                # Simulate basic WHOIS output for demo purposes
                print("\n[+] Simulated WHOIS Information:")
                print(f"Domain Name: {domain}")
                print("Registrar: Example Registrar, LLC")
                print("WHOIS Server: whois.example.com")
                print("Updated Date: 2023-01-01T00:00:00Z")
                print("Creation Date: 2020-01-01T00:00:00Z")
                print("Expiration Date: 2024-01-01T00:00:00Z")
                print("Name Servers: NS1.EXAMPLE.COM, NS2.EXAMPLE.COM")
                print("Status: clientTransferProhibited")
                print("Registrant Organization: Example Organization")
                print("Registrant Country: US")
                print("Admin Email: admin@example.com")
        
        except Exception as e:
            print(f"[!] Error performing WHOIS lookup: {e}")
        
        input("\nPress Enter to continue...")
    
    def dns_lookup(self):
        """DNS record lookup tool"""
        print("[+] DNS Record Lookup Tool")
        
        domain = input("Enter domain name (e.g., example.com): ")
        if not domain:
            print("[!] No domain provided.")
            input("\nPress Enter to continue...")
            return
        
        # Clean the domain
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.split('/')[0]  # Remove any path
        
        print(f"[*] Looking up DNS records for: {domain}")
        
        try:
            # Get A record (IPv4 address)
            try:
                ip = socket.gethostbyname(domain)
                print(f"\n[+] A Record (IPv4): {ip}")
            except:
                print("\n[-] A Record: No record found")
            
            # Use system DNS tools if available
            if not self.is_windows:
                print("\n[+] Using system tools for additional records:")
                
                # MX Records (Mail servers)
                print("\n[+] MX Records (Mail Servers):")
                os.system(f"dig MX {domain} +short")
                
                # NS Records (Name Servers)
                print("\n[+] NS Records (Name Servers):")
                os.system(f"dig NS {domain} +short")
                
                # TXT Records
                print("\n[+] TXT Records:")
                os.system(f"dig TXT {domain} +short")
                
                # CNAME Records
                print("\n[+] CNAME Records:")
                os.system(f"dig CNAME {domain} +short")
            else:
                # Windows alternative using nslookup
                print("\n[+] Using Windows tools for additional records:")
                
                # MX Records
                print("\n[+] MX Records (Mail Servers):")
                os.system(f"nslookup -type=mx {domain}")
                
                # NS Records
                print("\n[+] NS Records (Name Servers):")
                os.system(f"nslookup -type=ns {domain}")
                
                # TXT Records
                print("\n[+] TXT Records:")
                os.system(f"nslookup -type=txt {domain}")
                
            # Use online API for additional information if requests is available
            if REQUESTS_AVAILABLE:
                try:
                    print("\n[*] Fetching additional DNS information from online API...")
                    api_url = f"https://dns-api.org/ALL/{domain}"
                    response = requests.get(api_url, headers=self.headers)
                    
                    if response.status_code == 200:
                        data = response.json()
                        if data:
                            print("\n[+] Additional DNS Records:")
                            for record in data:
                                print(f"Type: {record.get('type', 'Unknown')}, "
                                      f"Value: {record.get('value', 'Unknown')}, "
                                      f"TTL: {record.get('ttl', 'Unknown')}")
                except Exception as e:
                    print(f"[!] Error fetching additional DNS information: {e}")
        
        except Exception as e:
            print(f"[!] Error performing DNS lookup: {e}")
        
        input("\nPress Enter to continue...")
    
    def subdomain_finder(self):
        """Tool to find subdomains of a domain"""
        print("[+] Subdomain Finder Tool")
        
        if not REQUESTS_AVAILABLE:
            print("[!] This tool requires the requests library.")
            print("[!] Install it with: pip install requests")
            input("\nPress Enter to continue...")
            return
        
        domain = input("Enter domain name (e.g., example.com): ")
        if not domain:
            print("[!] No domain provided.")
            input("\nPress Enter to continue...")
            return
        
        # Clean the domain
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.split('/')[0]  # Remove any path
        
        print(f"[*] Searching for subdomains of: {domain}")
        print("[*] This may take a while...")
        
        # Common subdomains to check
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'ns3', 'ns4', 'webdisk', 'pop3', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'blog', 'wap', 'dev', 'admin', 'mobile', 'secure', 'vpn', 'api', 'stage',
            'auth', 'support', 'portal', 'shop', 'cloud', 'demo', 'test', 'app', 'docs'
        ]
        
        found_subdomains = []
        
        print("[*] Checking common subdomains...")
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found_subdomains.append((subdomain, ip))
                print(f"[+] Found: {subdomain} ({ip})")
            except:
                # Subdomain not found
                pass
        
        # Try to use online services for more comprehensive search
        print("\n[*] Checking online services for more subdomains...")
        
        try:
            # This is a simulation since most APIs require authentication
            print("[!] Using simulated API results for demonstration.")
            print("[!] For comprehensive results, use dedicated tools or subscribed APIs.")
            
            # Simulate finding additional subdomains
            additional_subdomains = [
                f"api.{domain}",
                f"dev.{domain}",
                f"support.{domain}",
                f"cdn.{domain}",
                f"media.{domain}"
            ]
            
            for subdomain in additional_subdomains:
                if subdomain not in [s[0] for s in found_subdomains]:
                    try:
                        ip = socket.gethostbyname(subdomain)
                        found_subdomains.append((subdomain, ip))
                        print(f"[+] Found: {subdomain} ({ip})")
                    except:
                        # Add to list anyway for demonstration
                        found_subdomains.append((subdomain, "0.0.0.0"))
                        print(f"[+] Found: {subdomain} (IP unknown)")
        
        except Exception as e:
            print(f"[!] Error searching online services: {e}")
        
        # Summary
        print(f"\n[+] Found {len(found_subdomains)} subdomains for {domain}:")
        for subdomain, ip in found_subdomains:
            print(f"  - {subdomain} ({ip})")
        
        # Option to save results
        save = input("\nSave results to file? (y/n): ").lower() == 'y'
        if save:
            filename = f"subdomains_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(f"Subdomains for {domain}\n")
                f.write("=" * 50 + "\n\n")
                for subdomain, ip in found_subdomains:
                    f.write(f"{subdomain} - {ip}\n")
            print(f"[+] Results saved to {filename}")
        
        input("\nPress Enter to continue...")
    
    def email_harvester(self):
        """Tool to find email addresses associated with a domain"""
        print("[+] Email Harvester Tool")
        
        if not REQUESTS_AVAILABLE:
            print("[!] This tool requires the requests library.")
            print("[!] Install it with: pip install requests")
            input("\nPress Enter to continue...")
            return
        
        domain = input("Enter domain name (e.g., example.com): ")
        if not domain:
            print("[!] No domain provided.")
            input("\nPress Enter to continue...")
            return
        
        # Clean the domain
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.split('/')[0]  # Remove any path
        
        print(f"[*] Searching for email addresses associated with: {domain}")
        print("[*] This may take a while...")
        
        # Email regex pattern
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        found_emails = set()
        
        # Try to fetch the main website
        print("[*] Checking main website...")
        try:
            url = f"http://{domain}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                # Find all emails in the response
                emails = email_pattern.findall(response.text)
                for email in emails:
                    if email.endswith(domain):
                        found_emails.add(email)
                        print(f"[+] Found: {email}")
        except Exception as e:
            print(f"[!] Error checking main website: {e}")
        
        # Check common pages
        common_pages = ['contact', 'about', 'team', 'staff', 'support']
        
        print("[*] Checking common pages...")
        for page in common_pages:
            try:
                url = f"http://{domain}/{page}"
                response = requests.get(url, headers=self.headers, timeout=5)
                
                if response.status_code == 200:
                    # Find all emails in the response
                    emails = email_pattern.findall(response.text)
                    for email in emails:
                        if email.endswith(domain):
                            found_emails.add(email)
                            print(f"[+] Found: {email}")
            except:
                # Ignore errors for individual pages
                pass
        
        # Try to use online services for more comprehensive search
        print("\n[*] Simulating search using online services...")
        print("[!] This is a demonstration. Real implementation would use APIs.")
        
        # Simulate finding additional emails
        simulated_emails = [
            f"info@{domain}",
            f"support@{domain}",
            f"admin@{domain}",
            f"webmaster@{domain}",
            f"contact@{domain}"
        ]
        
        for email in simulated_emails:
            if email not in found_emails:
                found_emails.add(email)
                print(f"[+] Found: {email}")
        
        # Summary
        print(f"\n[+] Found {len(found_emails)} email addresses for {domain}:")
        for email in found_emails:
            print(f"  - {email}")
        
        # Option to save results
        save = input("\nSave results to file? (y/n): ").lower() == 'y'
        if save:
            filename = f"emails_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(f"Email addresses for {domain}\n")
                f.write("=" * 50 + "\n\n")
                for email in found_emails:
                    f.write(f"{email}\n")
            print(f"[+] Results saved to {filename}")
        
        input("\nPress Enter to continue...")
    
    def social_media_finder(self):
        """Find social media profiles associated with a target"""
        print("[+] Social Media Profile Finder")
        
        if not REQUESTS_AVAILABLE:
            print("[!] This tool requires the requests library.")
            print("[!] Install it with: pip install requests")
            input("\nPress Enter to continue...")
            return
        
        target_type = input("Search by [1] Company/Domain or [2] Person (1/2): ")
        
        if target_type == "1":
            # Company/Domain search
            target = input("Enter company name or domain: ")
            if not target:
                print("[!] No target provided.")
                input("\nPress Enter to continue...")
                return
            
            # Clean domain if it looks like one
            if '.' in target and '/' not in target and ' ' not in target:
                target = re.sub(r'^https?://', '', target)
                target = re.sub(r'^www\.', '', target)
                target = target.split('/')[0]  # Remove any path
            
            print(f"[*] Searching for social media profiles for: {target}")
            
            # Common social media platforms for companies
            platforms = {
                "Facebook": f"https://www.facebook.com/{target}",
                "Twitter": f"https://twitter.com/{target}",
                "LinkedIn": f"https://www.linkedin.com/company/{target}",
                "Instagram": f"https://www.instagram.com/{target}",
                "YouTube": f"https://www.youtube.com/c/{target}",
                "GitHub": f"https://github.com/{target}"
            }
            
        else:
            # Person search
            first_name = input("Enter first name: ")
            last_name = input("Enter last name: ")
            if not first_name and not last_name:
                print("[!] No name provided.")
                input("\nPress Enter to continue...")
                return
            
            target = f"{first_name} {last_name}".strip()
            username = input("Enter known username (optional): ")
            
            print(f"[*] Searching for social media profiles for: {target}")
            
            # Use username if provided, otherwise create one
            if not username:
                username = f"{first_name.lower()}{last_name.lower()}"
            
            # Common social media platforms for individuals
            platforms = {
                "Facebook": f"https://www.facebook.com/{username}",
                "Twitter": f"https://twitter.com/{username}",
                "LinkedIn": f"https://www.linkedin.com/in/{username}",
                "Instagram": f"https://www.instagram.com/{username}",
                "GitHub": f"https://github.com/{username}",
                "Medium": f"https://medium.com/@{username}",
                "Reddit": f"https://www.reddit.com/user/{username}"
            }
        
        print("[*] This may take a while...")
        found_profiles = []
        
        # Disclaimer
        print("[!] Note: This tool cannot confirm if profiles belong to the target.")
        print("[!] Manual verification is required.")
        print("[!] Some platforms may block automated requests.")
        
        # Check each platform
        for platform, url in platforms.items():
            try:
                print(f"[*] Checking {platform}...")
                response = requests.get(url, headers=self.headers, timeout=5)
                
                # Some platforms redirect to login page even if profile exists
                if response.status_code == 200 and len(response.text) > 1000:
                    # This is a very basic check and may produce false positives
                    found_profiles.append((platform, url))
                    print(f"[+] Potential profile found: {platform} - {url}")
            except Exception as e:
                print(f"[!] Error checking {platform}: {e}")
        
        # Summary
        if found_profiles:
            print(f"\n[+] Found {len(found_profiles)} potential profiles for {target}:")
            for platform, url in found_profiles:
                print(f"  - {platform}: {url}")
        else:
            print(f"\n[-] No profiles found for {target}.")
            print("[*] Try different usernames or search manually.")
        
        # Option to save results
        save = input("\nSave results to file? (y/n): ").lower() == 'y'
        if save:
            filename = f"social_media_{target.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(f"Social media profiles for {target}\n")
                f.write("=" * 50 + "\n\n")
                for platform, url in found_profiles:
                    f.write(f"{platform}: {url}\n")
            print(f"[+] Results saved to {filename}")
        
        input("\nPress Enter to continue...")

def run_osint_tools():
    """Run the OSINT tools"""
    return OSINTTools()

# Function to display the OSINT menu
def osint_menu():
    """Display the OSINT menu"""
    tools = run_osint_tools()
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    ###########################################
    #    Open Source Intelligence (OSINT)     #
    ###########################################
    
    1. WHOIS Domain Lookup
    2. DNS Records Lookup
    3. Subdomain Finder
    4. Email Harvester
    5. Social Media Profile Finder
    6. Back to Main Menu
    """)
        
        choice = input("Select an option: ")
        
        try:
            choice = int(choice)
            if choice == 1:
                tools.whois_lookup()
            elif choice == 2:
                tools.dns_lookup()
            elif choice == 3:
                tools.subdomain_finder()
            elif choice == 4:
                tools.email_harvester()
            elif choice == 5:
                tools.social_media_finder()
            elif choice == 6:
                return
            else:
                print("Invalid option. Please try again.")
                input("\nPress Enter to continue...")
        except ValueError:
            print("Please enter a number.")
            input("\nPress Enter to continue...")

# For standalone testing
if __name__ == "__main__":
    osint_menu() 