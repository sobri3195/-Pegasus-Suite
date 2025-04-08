#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Wireless security tools for Pegasus-Suite
"""

import os
import sys
import time
import random
import string
import socket
from platform import system

class WirelessTools:
    """Wireless security scanning and testing tools"""
    
    def __init__(self):
        """Initialize wireless tools"""
        self.is_windows = system() == 'Windows'
        self.is_linux = system() == 'Linux'
    
    def wifi_scanner(self):
        """Scan for nearby WiFi networks"""
        print("[+] WiFi Network Scanner")
        
        if self.is_windows:
            print("[*] Scanning for WiFi networks using Windows tools...")
            # Use netsh on Windows
            try:
                os.system("netsh wlan show networks mode=bssid")
                print("\n[*] Scan complete")
            except Exception as e:
                print(f"[!] Error scanning: {e}")
                print("[!] Make sure you have admin privileges")
        
        elif self.is_linux:
            print("[*] Scanning for WiFi networks using Linux tools...")
            # Check for iwlist on Linux
            try:
                print("[*] Checking for WiFi interface...")
                os.system("iwconfig | grep IEEE")
                
                print("\n[*] Enter WiFi interface to use:")
                interface = input("Interface (e.g., wlan0): ")
                
                if not interface:
                    print("[!] No interface provided.")
                    return
                
                print(f"[*] Scanning with {interface}...")
                os.system(f"sudo iwlist {interface} scan | grep -E 'ESSID|Quality|Encryption'")
                print("\n[*] Scan complete")
            except Exception as e:
                print(f"[!] Error scanning: {e}")
                print("[!] Make sure you have the wireless-tools package installed")
                print("[!] You may need to run as root or with sudo")
        
        else:
            # Simulate scan on other platforms
            print("[*] Simulating WiFi scan (unsupported platform)...")
            time.sleep(2)
            
            # Generate random networks
            security = ["WEP", "WPA", "WPA2", "WPA3", "Open"]
            channels = [1, 6, 11, 36, 40, 44, 48]
            
            for i in range(5):
                ssid = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                sec = random.choice(security)
                channel = random.choice(channels)
                signal = random.randint(50, 95)
                
                print(f"Network {i+1}:")
                print(f"  SSID: {ssid}")
                print(f"  Security: {sec}")
                print(f"  Signal: {signal}%")
                print(f"  Channel: {channel}")
                print("  -------------")
            
            print("[*] Scan complete (simulated)")
    
    def wep_attack(self):
        """WEP cracking simulation"""
        print("[+] WEP Cracking Tool")
        print("[!] This is a simulation - no actual attacks are performed")
        
        ssid = input("Enter target SSID: ")
        if not ssid:
            print("[!] No SSID provided.")
            return
        
        print(f"[*] Targeting WEP network: {ssid}")
        print("[*] Checking for compatible wireless adapter...")
        print("[+] Compatible adapter found")
        
        print("[*] Starting packet capture...")
        for i in range(5):
            print(f"[*] Capturing data packets ({i+1}/5)...")
            progress = 0
            while progress < 100:
                progress += random.randint(5, 15)
                if progress > 100:
                    progress = 100
                print(f"\r[*] Progress: {progress}%", end="")
                time.sleep(0.3)
            print("")
            
            # Show fake IVs
            iv_count = random.randint(10000 * (i+1), 20000 * (i+1))
            print(f"[+] Collected {iv_count} unique IVs")
        
        print("\n[*] Analyzing collected data...")
        time.sleep(2)
        
        print("[*] Attempting to crack WEP key...")
        time.sleep(3)
        
        # Generate a random key
        key = ''.join(random.choices('0123456789ABCDEF', k=10))
        print(f"\n[+] WEP Key found: {key}")
        print("[*] This is a simulated result - no actual cracking was performed")
    
    def wpa_attack(self):
        """WPA handshake capture and cracking simulation"""
        print("[+] WPA Handshake Capture and Cracking")
        print("[!] This is a simulation - no actual attacks are performed")
        
        ssid = input("Enter target SSID: ")
        if not ssid:
            print("[!] No SSID provided.")
            return
        
        print(f"[*] Targeting WPA/WPA2 network: {ssid}")
        print("[*] Checking for compatible wireless adapter...")
        print("[+] Compatible adapter found")
        
        print("[*] Starting monitor mode...")
        print("[+] Monitor mode activated")
        
        print("[*] Waiting for WPA handshake...")
        time.sleep(random.uniform(3, 8))
        
        # Simulate finding a handshake
        print(f"\n[+] WPA handshake captured for {ssid}!")
        
        # Ask for wordlist
        wordlist = input("\nEnter path to wordlist for cracking: ")
        if not wordlist:
            print("[!] No wordlist provided. Using built-in small wordlist.")
            wordlist = "built-in"
        
        print(f"[*] Starting dictionary attack using {wordlist}...")
        
        # Simulate dictionary attack
        words_tried = 0
        start_time = time.time()
        found = random.random() < 0.3  # 30% chance of finding password
        
        max_words = random.randint(1000, 10000)
        
        for i in range(max_words):
            words_tried += 1
            
            # Show progress
            if words_tried % 100 == 0:
                elapsed = time.time() - start_time
                rate = words_tried / elapsed if elapsed > 0 else 0
                print(f"\r[*] Tried {words_tried} passwords... ({rate:.2f} p/s)", end="")
            
            # Simulate finding password
            if found and words_tried > max_words * 0.7:
                break
            
            time.sleep(0.01)  # Slow down simulation a bit
        
        print("")
        
        if found:
            # Generate a random password
            passwords = ["password123", "iloveyou", "sunshine", "qwerty123", 
                         "letmein", "football", "welcome", "monkey123"]
            password = random.choice(passwords)
            
            print(f"\n[+] Password found: {password}")
            print(f"[*] Time elapsed: {time.time() - start_time:.2f} seconds")
            print(f"[*] Passwords tried: {words_tried}")
        else:
            print("\n[-] Password not found in dictionary.")
            print(f"[*] Time elapsed: {time.time() - start_time:.2f} seconds")
            print(f"[*] Passwords tried: {words_tried}")
        
        print("[*] This is a simulated result - no actual cracking was performed")
    
    def bluetooth_scanner(self):
        """Bluetooth device scanner simulation"""
        print("[+] Bluetooth Device Scanner")
        
        print("[*] Checking Bluetooth adapter...")
        print("[+] Bluetooth adapter found")
        
        print("[*] Scanning for Bluetooth devices...")
        
        # Simulate scanning
        for i in range(3):
            print(f"\n[*] Scan {i+1}/3...")
            time.sleep(random.uniform(1.5, 3.0))
            
            # Generate random devices
            num_devices = random.randint(0, 5)
            
            if num_devices == 0:
                print("[-] No devices found in this scan")
                continue
            
            print(f"[+] Found {num_devices} devices:")
            
            for j in range(num_devices):
                # Generate random MAC and name
                mac = ':'.join(['{:02X}'.format(random.randint(0, 255)) for _ in range(6)])
                
                device_types = ["Phone", "Headphones", "Speaker", "Keyboard", "Mouse", "Unknown"]
                device_type = random.choice(device_types)
                
                if device_type == "Phone":
                    names = ["iPhone", "Galaxy", "Pixel", "OnePlus", "Xiaomi"]
                    name = f"{random.choice(names)} {random.randint(1, 13)}"
                elif device_type == "Headphones":
                    names = ["AirPods", "Galaxy Buds", "Sony WH", "Bose QC", "Beats"]
                    name = f"{random.choice(names)}"
                else:
                    name = f"{device_type} {chr(65+j)}"
                
                rssi = random.randint(-90, -30)
                
                print(f"  Device {j+1}:")
                print(f"    Name: {name}")
                print(f"    MAC: {mac}")
                print(f"    RSSI: {rssi} dBm")
                print(f"    Type: {device_type}")
        
        print("\n[*] Scan complete")
        print("[*] This is a simulated scan - results are generated for demonstration")

# Main function to run the tools
def run_wireless_tools():
    """Run the wireless security tools"""
    tools = WirelessTools()
    return tools 