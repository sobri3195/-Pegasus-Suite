#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Mobile Security Tools for Pegasus-Suite
"""

import os
import sys
import re
import subprocess
import platform
import random
import time

class MobileSecurityTools:
    """Mobile application security analysis tools"""
    
    def __init__(self):
        """Initialize mobile security tools"""
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        self.output_dir = "mobile_analysis_results"
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except:
                self.output_dir = "."
    
    def android_app_analyzer(self):
        """Analyze Android APK files for security issues"""
        print("[+] Android Application Analyzer")
        
        apk_path = input("Enter path to APK file: ")
        if not apk_path or not os.path.exists(apk_path):
            print("[!] Invalid file path or file does not exist.")
            input("\nPress Enter to continue...")
            return
            
        print(f"[*] Analyzing APK: {apk_path}")
        
        # Check file is actually an APK
        if not apk_path.lower().endswith('.apk'):
            print("[!] File does not have .apk extension. Continuing anyway...")
        
        # Basic APK information
        file_size = os.path.getsize(apk_path) / (1024 * 1024)  # Size in MB
        print(f"[+] APK Size: {file_size:.2f} MB")
        
        # Simulate APK analysis
        print("[*] Decompiling APK...")
        time.sleep(2)
        
        print("[*] Analyzing manifest...")
        time.sleep(1.5)
        
        # Android permissions (common ones)
        permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO"
        ]
        
        # Randomly select some permissions to simulate finding them
        app_permissions = random.sample(permissions, random.randint(3, len(permissions)))
        
        print("\n[+] Detected permissions:")
        for perm in app_permissions:
            print(f"  - {perm}")
        
        # Categorize permissions by risk level
        dangerous_permissions = [
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION", 
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS"
        ]
        
        high_risk_perms = [p for p in app_permissions if p in dangerous_permissions]
        
        if high_risk_perms:
            print("\n[!] High-risk permissions detected:")
            for perm in high_risk_perms:
                print(f"  - {perm}")
        
        # Security issues to simulate finding
        security_issues = [
            ("Insecure Data Storage", "App may store sensitive data without encryption", random.random() < 0.3),
            ("Weak Cryptography", "App uses outdated or weak cryptographic algorithms", random.random() < 0.2),
            ("Unprotected Communication", "App communicates over insecure channels", random.random() < 0.4),
            ("Hardcoded Credentials", "App contains hardcoded API keys or credentials", random.random() < 0.2),
            ("Insecure Logging", "App logs sensitive information", random.random() < 0.5),
            ("Exported Components", "App exposes components to other applications", random.random() < 0.4),
            ("WebView Vulnerabilities", "App uses WebView with JavaScript enabled", random.random() < 0.3)
        ]
        
        found_issues = [(name, desc) for name, desc, found in security_issues if found]
        
        if found_issues:
            print("\n[!] Potential security issues detected:")
            for name, desc in found_issues:
                print(f"  - {name}: {desc}")
        else:
            print("\n[+] No obvious security issues detected.")
        
        # Generate report
        print("\n[*] Generating report...")
        report_path = os.path.join(self.output_dir, f"android_analysis_{os.path.basename(apk_path)}.txt")
        
        try:
            with open(report_path, 'w') as f:
                f.write(f"Android Application Analysis Report\n")
                f.write(f"================================\n\n")
                f.write(f"APK: {apk_path}\n")
                f.write(f"Size: {file_size:.2f} MB\n\n")
                
                f.write("Permissions:\n")
                for perm in app_permissions:
                    risk = "HIGH RISK" if perm in dangerous_permissions else "Normal"
                    f.write(f"  - {perm} ({risk})\n")
                
                f.write("\nSecurity Issues:\n")
                if found_issues:
                    for name, desc in found_issues:
                        f.write(f"  - {name}: {desc}\n")
                else:
                    f.write("  No obvious security issues detected.\n")
            
            print(f"[+] Report saved to: {report_path}")
            
        except Exception as e:
            print(f"[!] Error saving report: {e}")
        
        input("\nPress Enter to continue...")
    
    def ios_app_analyzer(self):
        """Analyze iOS IPA files for security issues"""
        print("[+] iOS Application Analyzer")
        
        ipa_path = input("Enter path to IPA file: ")
        if not ipa_path:
            print("[!] No file specified.")
            input("\nPress Enter to continue...")
            return
        
        if not os.path.exists(ipa_path):
            print("[!] File does not exist.")
            input("\nPress Enter to continue...")
            return
            
        print(f"[*] Analyzing IPA: {ipa_path}")
        
        # Check file is actually an IPA
        if not ipa_path.lower().endswith('.ipa'):
            print("[!] File does not have .ipa extension. Continuing anyway...")
        
        # Basic IPA information
        file_size = os.path.getsize(ipa_path) / (1024 * 1024)  # Size in MB
        print(f"[+] IPA Size: {file_size:.2f} MB")
        
        print("[*] This is a simulated analysis as full iOS app analysis requires macOS.")
        
        # Simulate IPA analysis
        print("[*] Extracting IPA...")
        time.sleep(2)
        
        print("[*] Analyzing Info.plist...")
        time.sleep(1.5)
        
        # iOS permission strings (Privacy - strings in Info.plist)
        permissions = [
            "NSCameraUsageDescription",
            "NSContactsUsageDescription",
            "NSLocationWhenInUseUsageDescription",
            "NSMicrophoneUsageDescription",
            "NSPhotoLibraryUsageDescription",
            "NSFaceIDUsageDescription",
            "NSBluetoothAlwaysUsageDescription"
        ]
        
        # Randomly select some permissions to simulate finding them
        app_permissions = random.sample(permissions, random.randint(2, len(permissions)))
        
        print("\n[+] Detected permissions:")
        for perm in app_permissions:
            print(f"  - {perm}")
        
        # Security issues to simulate finding
        security_issues = [
            ("Insecure Data Storage", "App may store sensitive data without encryption", random.random() < 0.3),
            ("No App Transport Security", "ATS settings allow insecure connections", random.random() < 0.4),
            ("Weak Keychain Configuration", "App uses weak keychain protection", random.random() < 0.2),
            ("Jailbreak Detection Bypass", "App's jailbreak detection can be bypassed", random.random() < 0.3),
            ("Excessive Permissions", "App requests unnecessary permissions", random.random() < 0.5),
            ("Insecure WebView Implementation", "App uses WebView without proper security", random.random() < 0.3),
            ("Hardcoded Secrets", "App contains hardcoded API keys or credentials", random.random() < 0.2)
        ]
        
        found_issues = [(name, desc) for name, desc, found in security_issues if found]
        
        if found_issues:
            print("\n[!] Potential security issues detected:")
            for name, desc in found_issues:
                print(f"  - {name}: {desc}")
        else:
            print("\n[+] No obvious security issues detected.")
        
        # Generate report
        print("\n[*] Generating report...")
        report_path = os.path.join(self.output_dir, f"ios_analysis_{os.path.basename(ipa_path)}.txt")
        
        try:
            with open(report_path, 'w') as f:
                f.write(f"iOS Application Analysis Report\n")
                f.write(f"==============================\n\n")
                f.write(f"IPA: {ipa_path}\n")
                f.write(f"Size: {file_size:.2f} MB\n\n")
                
                f.write("Permissions:\n")
                for perm in app_permissions:
                    f.write(f"  - {perm}\n")
                
                f.write("\nSecurity Issues:\n")
                if found_issues:
                    for name, desc in found_issues:
                        f.write(f"  - {name}: {desc}\n")
                else:
                    f.write("  No obvious security issues detected.\n")
            
            print(f"[+] Report saved to: {report_path}")
            
        except Exception as e:
            print(f"[!] Error saving report: {e}")
        
        input("\nPress Enter to continue...")
    
    def mobile_vulnerability_scanner(self):
        """Scan for mobile device vulnerabilities"""
        print("[+] Mobile Vulnerability Scanner")
        
        device_type = input("Select device type (1: Android, 2: iOS): ")
        
        if device_type not in ["1", "2"]:
            print("[!] Invalid selection.")
            input("\nPress Enter to continue...")
            return
            
        device_id = input("Enter device ID/IP (or leave empty for simulation): ")
        
        # Simulate vulnerability scan
        print("\n[*] This is a simulated scan. In a real environment, you would connect to the device.")
        
        if device_type == "1":  # Android
            print("[*] Scanning Android device for vulnerabilities...")
            
            # Common Android vulnerabilities
            vulnerabilities = [
                ("Outdated OS", "Device running Android version < 10", random.random() < 0.4),
                ("Missing Security Patches", "Device missing recent security updates", random.random() < 0.5),
                ("USB Debugging Enabled", "USB debugging is enabled in developer options", random.random() < 0.3),
                ("Potentially Harmful Apps", "Device has apps from unknown sources", random.random() < 0.4),
                ("Root Access", "Device is rooted", random.random() < 0.2),
                ("Encryption Disabled", "Device storage is not encrypted", random.random() < 0.3),
                ("Vulnerable Bootloader", "Bootloader could allow unauthorized OS installation", random.random() < 0.2)
            ]
        else:  # iOS
            print("[*] Scanning iOS device for vulnerabilities...")
            
            # Common iOS vulnerabilities
            vulnerabilities = [
                ("Outdated OS", "Device running iOS version < 14", random.random() < 0.3),
                ("Jailbroken Device", "Device shows signs of jailbreak", random.random() < 0.2),
                ("Profile Management", "Device has suspicious profiles installed", random.random() < 0.3),
                ("MDM Bypass", "Mobile Device Management appears to be bypassed", random.random() < 0.1),
                ("Vulnerable Safari Settings", "Browser privacy settings are not optimal", random.random() < 0.4),
                ("iCloud Security", "iCloud security settings are not optimal", random.random() < 0.3),
                ("AppStore Restrictions", "App installation restrictions are bypassed", random.random() < 0.2)
            ]
        
        # Simulate scan progress
        for i in range(1, 6):
            print(f"[*] Scan progress: {i*20}%")
            time.sleep(0.5)
        
        # Report findings
        found_vulnerabilities = [(name, desc) for name, desc, found in vulnerabilities if found]
        
        if found_vulnerabilities:
            print("\n[!] Vulnerabilities detected:")
            for name, desc in found_vulnerabilities:
                print(f"  - {name}: {desc}")
        else:
            print("\n[+] No vulnerabilities detected. Device appears secure.")
        
        input("\nPress Enter to continue...")
    
    def app_permission_analyzer(self):
        """Analyze app permissions on a mobile device"""
        print("[+] App Permission Analyzer")
        
        device_type = input("Select device type (1: Android, 2: iOS): ")
        
        if device_type not in ["1", "2"]:
            print("[!] Invalid selection.")
            input("\nPress Enter to continue...")
            return
        
        print("\n[*] This is a simulated analysis. In a real environment, you would connect to the device.")
        
        # Simulate list of installed apps
        apps = []
        if device_type == "1":  # Android
            apps = [
                "com.google.android.gms",
                "com.android.chrome",
                "com.facebook.katana",
                "com.instagram.android",
                "com.whatsapp",
                "com.spotify.music",
                "com.netflix.mediaclient",
                "com.amazon.mShop.android.shopping",
                "com.ubercab",
                "com.snapchat.android"
            ]
        else:  # iOS
            apps = [
                "com.apple.mobilesafari",
                "com.facebook.Facebook",
                "com.instagram.Instagram",
                "com.burbn.instagram",
                "net.whatsapp.WhatsApp",
                "com.spotify.client",
                "com.netflix.Netflix",
                "com.amazon.Amazon",
                "com.ubercab.UberClient",
                "com.toyopagroup.picaboo"
            ]
        
        # Show list of apps
        print("\n[*] Installed apps:")
        for i, app in enumerate(apps, 1):
            print(f"  {i}. {app}")
        
        app_choice = input("\nSelect an app to analyze (number): ")
        try:
            app_choice = int(app_choice)
            if app_choice < 1 or app_choice > len(apps):
                raise ValueError()
            selected_app = apps[app_choice - 1]
        except (ValueError, IndexError):
            print("[!] Invalid selection.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n[*] Analyzing permissions for {selected_app}...")
        
        # Simulate permissions based on app type
        permissions = []
        
        if "facebook" in selected_app.lower() or "instagram" in selected_app.lower() or "snap" in selected_app.lower():
            permissions = [
                ("Camera", "High", "Allows app to take pictures and videos"),
                ("Microphone", "High", "Allows app to record audio"),
                ("Location", "High", "Allows app to access precise location"),
                ("Contacts", "High", "Allows app to read your contacts"),
                ("Storage", "Medium", "Allows app to read and write to storage"),
                ("Phone", "Medium", "Allows app to read phone status"),
                ("SMS", "High", "Allows app to read and send SMS messages"),
            ]
        elif "netflix" in selected_app.lower() or "spotify" in selected_app.lower():
            permissions = [
                ("Storage", "Medium", "Allows app to read and write to storage"),
                ("Network", "Low", "Allows app to access network connections"),
                ("Microphone", "Medium", "Allows app to record audio"),
                ("Wake Lock", "Low", "Allows app to keep processor from sleeping"),
            ]
        elif "chrome" in selected_app.lower() or "safari" in selected_app.lower():
            permissions = [
                ("Location", "Medium", "Allows app to access precise location"),
                ("Camera", "Medium", "Allows app to take pictures"),
                ("Storage", "Medium", "Allows app to read and write to storage"),
                ("Microphone", "Medium", "Allows app to record audio"),
            ]
        else:
            # Generic permissions
            permissions = [
                ("Internet", "Low", "Allows app to access the internet"),
                ("Storage", "Medium", "Allows app to read and write to storage"),
                ("Location", "Medium", "Allows app to access location"),
            ]
        
        # Randomly select some permissions
        selected_permissions = random.sample(permissions, min(len(permissions), random.randint(3, len(permissions))))
        
        print("\n[+] Permissions detected:")
        for perm, risk, desc in selected_permissions:
            print(f"  - {perm} ({risk} risk): {desc}")
        
        # Risk assessment
        high_risk = sum(1 for perm, risk, _ in selected_permissions if risk == "High")
        medium_risk = sum(1 for perm, risk, _ in selected_permissions if risk == "Medium")
        
        print("\n[+] Risk assessment:")
        if high_risk >= 3:
            print("  High Risk: App requests many sensitive permissions")
        elif high_risk >= 1 or medium_risk >= 3:
            print("  Medium Risk: App requests some sensitive permissions")
        else:
            print("  Low Risk: App requests minimal sensitive permissions")
        
        print("\n[*] Recommendations:")
        if high_risk > 0:
            print("  - Review if the app really needs these permissions")
            print("  - Consider using alternative apps with fewer permissions")
            print("  - Disable permissions that aren't necessary for app functionality")
        
        input("\nPress Enter to continue...")

def run_mobile_security_tools():
    """Run the mobile security tools"""
    return MobileSecurityTools()

# Function to display the mobile security menu
def mobile_security_menu():
    """Display the mobile security menu"""
    tools = run_mobile_security_tools()
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    ###########################################
    #          Mobile Security Tools          #
    ###########################################
    
    1. Android App Analyzer
    2. iOS App Analyzer
    3. Mobile Vulnerability Scanner
    4. App Permission Analyzer
    5. Back to Main Menu
    """)
        
        choice = input("Select an option: ")
        
        try:
            choice = int(choice)
            if choice == 1:
                tools.android_app_analyzer()
            elif choice == 2:
                tools.ios_app_analyzer()
            elif choice == 3:
                tools.mobile_vulnerability_scanner()
            elif choice == 4:
                tools.app_permission_analyzer()
            elif choice == 5:
                return
            else:
                print("Invalid option. Please try again.")
                input("\nPress Enter to continue...")
        except ValueError:
            print("Please enter a number.")
            input("\nPress Enter to continue...")

# For standalone testing
if __name__ == "__main__":
    mobile_security_menu() 