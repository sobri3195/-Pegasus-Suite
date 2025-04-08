#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ICS/SCADA Security Module for Pegasus-Suite
# Author: Dr. Muhammad Sobri Maulana, CEH

import os
import sys
import platform
import socket
import re
import json
import time
import random
import threading
from datetime import datetime

# Import from pegabox_imports instead of directly
try:
    from pegabox_imports import (
        Fore, Style, COLORAMA_AVAILABLE, requests, 
        REQUESTS_AVAILABLE, raw_input, input_func
    )  # type: ignore
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
    
    # Handle requests
    try:
        import requests
        REQUESTS_AVAILABLE = True
    except ImportError:
        REQUESTS_AVAILABLE = False
        print("[!] Warning: requests module not available. Some features will be limited.")
    
    # Handle input functions
    if sys.version_info[0] >= 3:
        input_func = input
        raw_input = input
    else:
        input_func = raw_input  # type: ignore
        raw_input = raw_input  # type: ignore

# Helper functions
def clear_screen():
    """Clear the screen based on the operating system."""
    os.system('cls' if os.name == 'nt' else 'clear')

def create_dir_if_not_exists(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

class ICSSecurityTools:
    """Collection of ICS/SCADA security assessment tools."""
    
    def __init__(self):
        """Initialize the ICS security tools."""
        self.results_dir = "ics_security_results"
        create_dir_if_not_exists(self.results_dir)
        
    def scada_system_assessment(self, target_ip, port_range="102,502,2222,20000,44818,47808"):
        """
        Perform a SCADA system assessment.
        
        Args:
            target_ip (str): Target IP address
            port_range (str): Comma-separated list of ports to scan
        
        Returns:
            dict: Assessment results
        """
        print(f"[*] Starting SCADA system assessment on {target_ip}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results = {
            "timestamp": timestamp,
            "target_ip": target_ip,
            "scan_type": "SCADA System Assessment",
            "findings": []
        }
        
        # Simulate scanning SCADA-specific ports
        ports = [int(p) for p in port_range.split(',')]
        print(f"[*] Scanning SCADA-specific ports: {ports}")
        
        # Simulate findings
        scada_protocols = {
            102: "Siemens S7 (ISO-TSAP)",
            502: "Modbus TCP",
            2222: "EtherNet/IP",
            20000: "DNP3",
            44818: "EtherNet/IP",
            47808: "BACnet"
        }
        
        # Simulate open ports and vulnerabilities
        for port in ports:
            is_open = random.choice([True, False])
            if is_open:
                protocol = scada_protocols.get(port, "Unknown SCADA Protocol")
                print(f"[+] Port {port} is open: {protocol}")
                
                # Simulate vulnerabilities
                vulnerabilities = []
                if random.random() < 0.7:  # 70% chance to find vulnerabilities
                    vuln_types = [
                        "Default credentials",
                        "Missing authentication",
                        "Outdated firmware",
                        "Clear-text communication",
                        "Weak encryption",
                        "Missing input validation"
                    ]
                    
                    for _ in range(random.randint(1, 3)):
                        vuln = random.choice(vuln_types)
                        vulnerabilities.append({
                            "type": vuln,
                            "severity": random.choice(["Low", "Medium", "High", "Critical"]),
                            "description": f"Potential {vuln.lower()} vulnerability detected"
                        })
                
                results["findings"].append({
                    "port": port,
                    "protocol": protocol,
                    "is_open": is_open,
                    "vulnerabilities": vulnerabilities
                })
            else:
                print(f"[-] Port {port} is closed")
        
        # Save results
        filename = f"{self.results_dir}/scada_assessment_{target_ip.replace('.', '_')}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"[+] SCADA assessment complete. Results saved to {filename}")
        return results

    def plc_security_scan(self, target_ip, plc_type="siemens"):
        """
        Perform security scan on specific PLC types.
        
        Args:
            target_ip (str): Target IP address
            plc_type (str): Type of PLC (siemens, allen_bradley, modicon, etc.)
        
        Returns:
            dict: Scan results
        """
        print(f"[*] Starting PLC security scan on {target_ip}")
        print(f"[*] PLC type: {plc_type}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # PLC-specific checks based on type
        plc_checks = {
            "siemens": ["S7Comm", "Memory protection", "CPU mode", "Password protection"],
            "allen_bradley": ["CIP Security", "Controller mode", "Authentication"],
            "modicon": ["Modbus", "Memory access", "Authentication"],
            "mitsubishi": ["MELSEC", "Password protection", "Access control"],
            "omron": ["FINS", "CPU mode", "Memory protection"]
        }
        
        # Default to siemens if type not found
        checks = plc_checks.get(plc_type.lower(), plc_checks["siemens"])
        
        results = {
            "timestamp": timestamp,
            "target_ip": target_ip,
            "plc_type": plc_type,
            "scan_type": "PLC Security Scan",
            "findings": []
        }
        
        # Simulate checking each security aspect
        for check in checks:
            print(f"[*] Checking {check}...")
            time.sleep(0.5)  # Simulate processing time
            
            # Simulate finding
            is_vulnerable = random.choice([True, False])
            severity = random.choice(["Low", "Medium", "High", "Critical"])
            
            if is_vulnerable:
                print(f"[!] {check} vulnerability found! Severity: {severity}")
                recommendation = f"Secure the {check.lower()} configuration based on vendor recommendations"
                
                results["findings"].append({
                    "check": check,
                    "vulnerable": True,
                    "severity": severity,
                    "recommendation": recommendation
                })
            else:
                print(f"[+] {check} is secure")
                results["findings"].append({
                    "check": check,
                    "vulnerable": False
                })
        
        # Save results
        filename = f"{self.results_dir}/plc_scan_{plc_type}_{target_ip.replace('.', '_')}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"[+] PLC security scan complete. Results saved to {filename}")
        return results

    def industrial_protocol_analyzer(self, target_ip, protocol="modbus"):
        """
        Analyze industrial protocols for security issues.
        
        Args:
            target_ip (str): Target IP address
            protocol (str): Protocol to analyze (modbus, dnp3, s7comm, etc.)
        
        Returns:
            dict: Analysis results
        """
        print(f"[*] Starting industrial protocol analysis on {target_ip}")
        print(f"[*] Protocol: {protocol}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        protocol_ports = {
            "modbus": 502,
            "dnp3": 20000,
            "s7comm": 102,
            "ethernet/ip": 44818,
            "bacnet": 47808,
            "opc_ua": 4840,
            "iec61850": 102
        }
        
        # Get the port for the specified protocol
        port = protocol_ports.get(protocol.lower(), 502)  # Default to Modbus port if not found
        
        results = {
            "timestamp": timestamp,
            "target_ip": target_ip,
            "protocol": protocol,
            "port": port,
            "scan_type": "Industrial Protocol Analysis",
            "findings": []
        }
        
        # Define protocol-specific checks
        protocol_checks = {
            "modbus": ["Function code access", "Read/Write permissions", "Exception handling"],
            "dnp3": ["Authentication", "Encryption", "Master-slave validation"],
            "s7comm": ["Authentication", "Authorization", "Function code access"],
            "ethernet/ip": ["CIP Security", "Authentication", "Session handling"],
            "bacnet": ["Authentication", "Authorization", "Service access"],
            "opc_ua": ["Certificate validation", "Encryption", "Authentication"],
            "iec61850": ["Authentication", "Authorization", "GOOSE security"]
        }
        
        checks = protocol_checks.get(protocol.lower(), protocol_checks["modbus"])
        
        # Simulate protocol analysis
        print(f"[*] Connecting to {target_ip}:{port} using {protocol} protocol...")
        time.sleep(1)  # Simulate connection time
        
        # Simulate protocol confirmation
        print(f"[+] {protocol.upper()} protocol confirmed on port {port}")
        
        # Analyze security aspects
        for check in checks:
            print(f"[*] Analyzing {check}...")
            time.sleep(0.5)  # Simulate analysis time
            
            # Simulate findings
            issue_found = random.choice([True, False])
            if issue_found:
                severity = random.choice(["Low", "Medium", "High", "Critical"])
                issue_type = random.choice([
                    "Missing authentication",
                    "Weak encryption",
                    "Improper access control",
                    "Default configuration",
                    "Insecure function code handling"
                ])
                
                print(f"[!] {check} issue found: {issue_type} (Severity: {severity})")
                
                results["findings"].append({
                    "check": check,
                    "issue_found": True,
                    "issue_type": issue_type,
                    "severity": severity,
                    "recommendation": f"Implement secure {check.lower()} mechanisms"
                })
            else:
                print(f"[+] {check} is secure")
                results["findings"].append({
                    "check": check,
                    "issue_found": False
                })
        
        # Save results
        filename = f"{self.results_dir}/{protocol}_analysis_{target_ip.replace('.', '_')}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"[+] Industrial protocol analysis complete. Results saved to {filename}")
        return results

    def industrial_network_monitor(self, interface="eth0", duration=30):
        """
        Monitor industrial network traffic for suspicious activities.
        
        Args:
            interface (str): Network interface to monitor
            duration (int): Duration in seconds to monitor
        
        Returns:
            dict: Monitoring results
        """
        print(f"[*] Starting industrial network monitoring on {interface}")
        print(f"[*] Monitoring for {duration} seconds...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        results = {
            "timestamp": timestamp,
            "interface": interface,
            "duration": duration,
            "scan_type": "Industrial Network Monitoring",
            "device_activities": [],
            "suspicious_activities": []
        }
        
        # Simulate device discovery
        device_count = random.randint(3, 10)
        print(f"[*] Discovering devices on network...")
        
        # Create simulated device list
        device_types = [
            "Siemens S7-1200 PLC", 
            "Allen Bradley CompactLogix", 
            "Schneider Modicon M340",
            "ABB AC800M Controller",
            "Honeywell C300 Controller",
            "Emerson Delta V Controller",
            "Yokogawa CENTUM VP Controller",
            "HMI Terminal",
            "Engineering Workstation"
        ]
        
        discovered_devices = []
        for i in range(device_count):
            ip = f"192.168.1.{random.randint(2, 254)}"
            device_type = random.choice(device_types)
            mac = ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
            
            discovered_devices.append({
                "ip": ip,
                "mac": mac,
                "type": device_type
            })
            print(f"[+] Discovered: {device_type} at {ip} ({mac})")
        
        results["device_activities"] = discovered_devices
        
        print(f"[*] Monitoring traffic for {duration} seconds...")
        
        # Simulate monitoring progress
        for i in range(5):
            print(f"[*] Monitoring... {i*25}%")
            time.sleep(duration/5)  # Divide duration into chunks
            
            # Randomly generate suspicious activities
            if random.random() < 0.3:  # 30% chance of finding something suspicious
                device = random.choice(discovered_devices)
                activity_types = [
                    "Unauthorized read request",
                    "Unauthorized write request",
                    "Unusual command sequence",
                    "Protocol violation",
                    "Unauthorized firmware upload attempt",
                    "Unusual scan pattern",
                    "Potential DoS attempt"
                ]
                
                activity = random.choice(activity_types)
                severity = random.choice(["Low", "Medium", "High", "Critical"])
                
                suspicious = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "device_ip": device["ip"],
                    "device_type": device["type"],
                    "activity": activity,
                    "severity": severity,
                    "details": f"Potential {activity.lower()} detected from/to {device['ip']}"
                }
                
                results["suspicious_activities"].append(suspicious)
                print(f"[!] ALERT: {activity} detected on {device['type']} ({device['ip']}) - Severity: {severity}")
        
        # Provide summary
        print(f"[+] Monitoring complete: {len(discovered_devices)} devices discovered")
        print(f"[+] Suspicious activities detected: {len(results['suspicious_activities'])}")
        
        # Save results
        filename = f"{self.results_dir}/network_monitor_{interface}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"[+] Industrial network monitoring complete. Results saved to {filename}")
        return results

    def air_gap_analyzer(self, facility_name, system_description):
        """
        Analyze air gap implementation and provide recommendations.
        
        Args:
            facility_name (str): Name of the facility
            system_description (str): Description of the air-gapped system
        
        Returns:
            dict: Analysis results with recommendations
        """
        print(f"[*] Starting air gap analysis for {facility_name}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        results = {
            "timestamp": timestamp,
            "facility_name": facility_name,
            "system_description": system_description,
            "scan_type": "Air Gap Analysis",
            "checklist": [],
            "recommendations": []
        }
        
        # Define air gap checklist
        checklist_items = [
            "Physical separation",
            "Network isolation",
            "USB/Removable media controls",
            "Data diode implementation",
            "Controlled file transfer",
            "Strict access controls",
            "Multi-factor authentication",
            "Security awareness training",
            "Physical security measures",
            "Regular security audits"
        ]
        
        # Evaluate each checklist item
        for item in checklist_items:
            print(f"[*] Evaluating: {item}")
            
            # Simulate evaluation
            implemented = random.choice([
                "Not implemented", 
                "Partially implemented", 
                "Fully implemented"
            ])
            
            risk_level = {
                "Not implemented": "High",
                "Partially implemented": "Medium",
                "Fully implemented": "Low"
            }[implemented]
            
            results["checklist"].append({
                "control": item,
                "status": implemented,
                "risk_level": risk_level
            })
            
            print(f"[*] {item}: {implemented} (Risk: {risk_level})")
            
            # Generate recommendations for items not fully implemented
            if implemented != "Fully implemented":
                recommendation = f"Strengthen {item.lower()} controls"
                
                # More detailed recommendations based on control type
                if "physical" in item.lower():
                    recommendation += " by implementing mantraps, biometric access, and CCTV monitoring"
                elif "usb" in item.lower() or "media" in item.lower():
                    recommendation += " by deploying media control software, USB port disablement, and content verification"
                elif "network" in item.lower():
                    recommendation += " by implementing VLANs, firewall rules, and network monitoring"
                elif "authentication" in item.lower() or "access" in item.lower():
                    recommendation += " by implementing role-based access control and time-limited credentials"
                
                results["recommendations"].append({
                    "control": item,
                    "recommendation": recommendation,
                    "priority": "High" if risk_level == "High" else "Medium"
                })
        
        # Overall risk assessment
        high_risks = sum(1 for item in results["checklist"] if item["risk_level"] == "High")
        medium_risks = sum(1 for item in results["checklist"] if item["risk_level"] == "Medium")
        
        if high_risks >= 3:
            overall_risk = "Critical"
        elif high_risks >= 1 or medium_risks >= 3:
            overall_risk = "High"
        elif medium_risks >= 1:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"
        
        results["overall_risk"] = overall_risk
        print(f"[+] Overall air gap risk assessment: {overall_risk}")
        
        # Save results
        filename = f"{self.results_dir}/air_gap_analysis_{facility_name.replace(' ', '_').lower()}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"[+] Air gap analysis complete. Results saved to {filename}")
        return results

def run_ics_security_tools():
    """Return an instance of the ICS security tools class."""
    return ICSSecurityTools()

def ics_security_menu():
    """Display the ICS/SCADA security tools menu."""
    clear_screen()
    ics_tools = run_ics_security_tools()
    
    while True:
        clear_screen()
        print("\n==== ICS/SCADA Security Tools ====")
        print("1. SCADA System Assessment")
        print("2. PLC Security Scan")
        print("3. Industrial Protocol Analyzer")
        print("4. Industrial Network Monitor")
        print("5. Air Gap Analysis")
        print("0. Return to Main Menu")
        
        choice = raw_input("\nSelect an option: ")
        
        if choice == '1':
            target_ip = raw_input("Enter target IP address: ")
            port_range = raw_input("Enter SCADA port range (default: 102,502,2222,20000,44818,47808): ") or "102,502,2222,20000,44818,47808"
            ics_tools.scada_system_assessment(target_ip, port_range)
            raw_input("\nPress Enter to continue...")
            
        elif choice == '2':
            target_ip = raw_input("Enter target IP address: ")
            print("\nAvailable PLC types:")
            print("1. Siemens")
            print("2. Allen Bradley")
            print("3. Modicon")
            print("4. Mitsubishi")
            print("5. Omron")
            plc_choice = raw_input("Select PLC type (1-5, default: 1): ") or "1"
            
            plc_types = {
                "1": "siemens",
                "2": "allen_bradley",
                "3": "modicon",
                "4": "mitsubishi",
                "5": "omron"
            }
            
            plc_type = plc_types.get(plc_choice, "siemens")
            ics_tools.plc_security_scan(target_ip, plc_type)
            raw_input("\nPress Enter to continue...")
            
        elif choice == '3':
            target_ip = raw_input("Enter target IP address: ")
            print("\nAvailable protocols:")
            print("1. Modbus")
            print("2. DNP3")
            print("3. S7Comm (Siemens)")
            print("4. EtherNet/IP")
            print("5. BACnet")
            print("6. OPC UA")
            print("7. IEC 61850")
            protocol_choice = raw_input("Select protocol (1-7, default: 1): ") or "1"
            
            protocols = {
                "1": "modbus",
                "2": "dnp3",
                "3": "s7comm",
                "4": "ethernet/ip",
                "5": "bacnet",
                "6": "opc_ua",
                "7": "iec61850"
            }
            
            protocol = protocols.get(protocol_choice, "modbus")
            ics_tools.industrial_protocol_analyzer(target_ip, protocol)
            raw_input("\nPress Enter to continue...")
            
        elif choice == '4':
            interface = raw_input("Enter network interface (default: eth0): ") or "eth0"
            try:
                duration = int(raw_input("Enter monitoring duration in seconds (default: 30): ") or "30")
            except ValueError:
                duration = 30
                
            ics_tools.industrial_network_monitor(interface, duration)
            raw_input("\nPress Enter to continue...")
            
        elif choice == '5':
            facility_name = raw_input("Enter facility name: ")
            print("Describe the air-gapped system (infrastructure components, purpose, etc.): ")
            system_description = raw_input("> ")
            
            ics_tools.air_gap_analyzer(facility_name, system_description)
            raw_input("\nPress Enter to continue...")
            
        elif choice == '0':
            break
        
        else:
            print("Invalid option. Please try again.")
            time.sleep(1)

if __name__ == "__main__":
    ics_security_menu() 