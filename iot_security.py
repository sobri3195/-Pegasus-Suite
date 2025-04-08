import os
import sys
import time
import random
import json
import ipaddress
from datetime import datetime

class IoTSecurityTools:
    def __init__(self):
        self.results_dir = "iot_security_results"
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def scan_iot_network(self, network_range):
        """Scan IoT devices in network range and identify vulnerabilities"""
        print(f"[*] Scanning IoT devices in range: {network_range}")
        try:
            # Validate IP range
            ipaddress.ip_network(network_range)
            
            # Simulate scanning process
            device_count = random.randint(3, 10)
            print(f"[*] Found {device_count} potential IoT devices")
            
            devices = []
            for i in range(device_count):
                device_types = ["Smart Camera", "Smart Lock", "Thermostat", "Router", "IP Camera", 
                                "Smart Speaker", "Smart TV", "Smart Bulb", "Media Device"]
                device = {
                    "id": i+1,
                    "ip": f"192.168.1.{random.randint(10, 250)}",
                    "mac": f"{':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])}",
                    "type": random.choice(device_types),
                    "open_ports": random.sample(range(1, 10000), random.randint(1, 5)),
                    "vulnerabilities": []
                }
                
                # Generate random vulnerabilities
                vuln_count = random.randint(0, 3)
                vulnerabilities = [
                    {"name": "Default credentials", "severity": "High"},
                    {"name": "Unpatched firmware", "severity": "Critical"},
                    {"name": "Open Telnet/SSH", "severity": "High"},
                    {"name": "Insecure HTTP", "severity": "Medium"},
                    {"name": "Weak encryption", "severity": "Medium"},
                    {"name": "No authentication", "severity": "Critical"}
                ]
                
                device["vulnerabilities"] = random.sample(vulnerabilities, min(vuln_count, len(vulnerabilities)))
                devices.append(device)
                
                print(f"[+] Device {i+1}: {device['type']} at {device['ip']}")
                if device["vulnerabilities"]:
                    for v in device["vulnerabilities"]:
                        print(f"  [!] {v['severity']}: {v['name']}")
            
            # Save results
            filename = f"{self.results_dir}/iot_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, "w") as f:
                json.dump({"scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                          "network": network_range,
                          "devices": devices}, f, indent=4)
            
            print(f"[*] Scan results saved to {filename}")
            return devices
        
        except ValueError:
            print("[!] Invalid network range. Use CIDR notation (e.g. 192.168.1.0/24)")
            return []
    
    def analyze_firmware(self, firmware_path):
        """Analyze IoT firmware for security issues"""
        print(f"[*] Analyzing firmware: {firmware_path}")
        
        if not os.path.exists(firmware_path):
            print(f"[!] Firmware file not found: {firmware_path}")
            return False
        
        # Simulate firmware analysis
        print("[*] Extracting firmware...")
        time.sleep(1)
        print("[*] Checking for known vulnerabilities...")
        time.sleep(1.5)
        print("[*] Analyzing hardcoded credentials...")
        time.sleep(1)
        
        # Generate random findings
        issues_found = random.randint(0, 5)
        if issues_found > 0:
            findings = [
                "Hardcoded credentials",
                "Outdated components with CVEs",
                "Weak encryption keys",
                "Debug mode enabled",
                "Insecure update mechanism"
            ]
            
            print(f"[!] Found {issues_found} security issues:")
            selected_findings = random.sample(findings, min(issues_found, len(findings)))
            
            # Save results
            filename = f"{self.results_dir}/firmware_analysis_{os.path.basename(firmware_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, "w") as f:
                f.write(f"Firmware Analysis: {firmware_path}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("FINDINGS:\n")
                
                for i, finding in enumerate(selected_findings):
                    severity = random.choice(["Critical", "High", "Medium"])
                    print(f"  [{i+1}] {severity}: {finding}")
                    f.write(f"{i+1}. {severity}: {finding}\n")
                    
                    # Add random details
                    details = [
                        "Found in binary at offset 0x2F4A",
                        "Multiple instances detected",
                        "Could lead to remote code execution",
                        "Easy to exploit with public tools",
                        "Referenced in CVE-2023-XXXX"
                    ]
                    f.write(f"   Details: {random.choice(details)}\n\n")
            
            print(f"[*] Analysis results saved to {filename}")
            return True
        else:
            print("[+] No security issues found in firmware")
            return True
    
    def test_iot_protocols(self, target_ip, protocol):
        """Test IoT protocols for security vulnerabilities"""
        valid_protocols = ["mqtt", "coap", "zigbee", "zwave", "ble"]
        
        if protocol.lower() not in valid_protocols:
            print(f"[!] Unsupported protocol. Supported protocols: {', '.join(valid_protocols)}")
            return False
        
        print(f"[*] Testing {protocol.upper()} protocol security on {target_ip}")
        
        # Simulate protocol testing
        print(f"[*] Connecting to {protocol.upper()} service...")
        time.sleep(1.5)
        
        # Random test results
        tests = [
            {"name": "Authentication", "result": random.choice(["Pass", "Fail", "Warning"])},
            {"name": "Encryption", "result": random.choice(["Pass", "Fail", "Warning"])},
            {"name": "Access Control", "result": random.choice(["Pass", "Fail", "Warning"])},
            {"name": "Firmware Verification", "result": random.choice(["Pass", "Fail", "Warning"])},
            {"name": "DoS Resistance", "result": random.choice(["Pass", "Fail", "Warning"])}
        ]
        
        # Save and display results
        filename = f"{self.results_dir}/{protocol}_test_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(f"{protocol.upper()} Protocol Security Test: {target_ip}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("TEST RESULTS:\n")
            
            for test in tests:
                print(f"[*] Testing {test['name']}...")
                time.sleep(0.5)
                
                result_marker = "✅" if test["result"] == "Pass" else "❌" if test["result"] == "Fail" else "⚠️"
                print(f"  {result_marker} {test['name']}: {test['result']}")
                
                f.write(f"- {test['name']}: {test['result']}\n")
                if test["result"] != "Pass":
                    recommendations = [
                        f"Implement proper {test['name'].lower()} mechanisms",
                        f"Update {protocol} implementation to latest version",
                        "Use TLS for transport security",
                        "Implement certificate validation",
                        "Add rate limiting to prevent abuse"
                    ]
                    f.write(f"  Recommendation: {random.choice(recommendations)}\n")
        
        print(f"[*] Protocol test results saved to {filename}")
        return True

def run_iot_security_tools():
    return IoTSecurityTools()

def menu():
    tools = run_iot_security_tools()
    
    while True:
        print("\n===== IoT Security Tools =====")
        print("1. Scan IoT Network")
        print("2. Analyze IoT Firmware")
        print("3. Test IoT Protocols")
        print("0. Back to Main Menu")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            network = input("Enter network range (CIDR notation, e.g. 192.168.1.0/24): ")
            tools.scan_iot_network(network)
        elif choice == "2":
            firmware = input("Enter path to firmware file: ")
            tools.analyze_firmware(firmware)
        elif choice == "3":
            target = input("Enter target IP address: ")
            protocol = input("Enter protocol (mqtt/coap/zigbee/zwave/ble): ")
            tools.test_iot_protocols(target, protocol)
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    menu() 