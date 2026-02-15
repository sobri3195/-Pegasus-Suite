#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Reverse Engineering Tools for Pegasus-Suite
"""

import os
import sys
import time
import platform
import subprocess
import math


def prompt_user(prompt, on_interrupt=None):
    """Read user input safely and handle non-interactive execution environments."""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Input interrupted. Returning to menu.")
        return on_interrupt

class ReverseEngineeringTools:
    """Reverse engineering tools for binary analysis"""
    
    def __init__(self):
        """Initialize reverse engineering tools"""
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
    
    def binary_analysis(self):
        """Basic binary file analysis"""
        print("[+] Binary Analysis Tool")
        
        binary_path = prompt_user("Enter path to binary file: ", on_interrupt="")
        if not binary_path or not os.path.exists(binary_path):
            print("[!] Invalid file path or file does not exist.")
            return
            
        print(f"[*] Analyzing binary: {binary_path}")
        
        # Basic file information
        file_size = os.path.getsize(binary_path)
        print(f"[+] File size: {file_size} bytes")
        
        # Check file type
        try:
            if self.is_windows:
                result = subprocess.check_output(f"file {binary_path}", shell=True).decode()
            else:
                result = subprocess.check_output(["file", binary_path]).decode()
            print(f"[+] File type: {result}")
        except:
            print("[!] Unable to determine file type. Make sure 'file' utility is installed.")
        
        # Try to identify strings in binary
        print("[*] Extracting strings from binary...")
        try:
            if self.is_windows:
                # On Windows we might need alternative tools
                print("[!] Advanced string extraction not available on Windows.")
                # Use simple Python-based string extraction
                with open(binary_path, 'rb') as f:
                    content = f.read()
                    
                strings = []
                current_string = ""
                for byte in content:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string += chr(byte)
                    else:
                        if len(current_string) >= 4:  # Only keep strings of 4+ chars
                            strings.append(current_string)
                        current_string = ""
                
                print(f"[+] Found {len(strings)} strings in binary")
                print("[+] Sample strings:")
                for s in strings[:10]:  # Show first 10 strings
                    print(f"  - {s}")
            else:
                # On Linux/Unix, use the strings command
                result = subprocess.check_output(["strings", binary_path]).decode()
                strings = result.split('\n')
                print(f"[+] Found {len(strings)} strings in binary")
                print("[+] Sample strings:")
                for s in strings[:10]:  # Show first 10 strings
                    print(f"  - {s}")
        except:
            print("[!] Unable to extract strings. Try installing 'strings' utility.")
        
        prompt_user("\nPress Enter to continue...", on_interrupt="")
    
    def disassembler(self):
        """Simple disassembler functionality"""
        print("[+] Disassembler Tool")
        
        if not self.is_linux:
            print("[!] This functionality is currently only available on Linux systems.")
            print("[!] Consider using tools like Ghidra, IDA Pro, or Radare2 for disassembly.")
            prompt_user("\nPress Enter to continue...", on_interrupt="")
            return
            
        binary_path = prompt_user("Enter path to binary file: ", on_interrupt="")
        if not binary_path or not os.path.exists(binary_path):
            print("[!] Invalid file path or file does not exist.")
            return
        
        # Check if objdump is available
        try:
            subprocess.check_output(["which", "objdump"])
        except:
            print("[!] objdump not found. Please install binutils package.")
            prompt_user("\nPress Enter to continue...", on_interrupt="")
            return
        
        print(f"[*] Disassembling binary: {binary_path}")
        try:
            # Get file headers
            print("[*] File headers:")
            result = subprocess.check_output(["objdump", "-f", binary_path]).decode()
            print(result)
            
            # Get section headers
            print("[*] Section headers:")
            result = subprocess.check_output(["objdump", "-h", binary_path]).decode()
            print(result)
            
            # Ask user if they want to see the full disassembly (it could be large)
            show_full = (prompt_user("Show full disassembly? This might be large (y/n): ", on_interrupt="n") or "n").lower() == 'y'
            
            if show_full:
                print("[*] Full disassembly (main function if available):")
                try:
                    result = subprocess.check_output(["objdump", "-d", "--disassemble=main", binary_path]).decode()
                    print(result)
                except:
                    result = subprocess.check_output(["objdump", "-d", binary_path]).decode()
                    # Only show first few lines as it could be very large
                    lines = result.split('\n')[:100]
                    print('\n'.join(lines))
                    print("... [output truncated] ...")
        except Exception as e:
            print(f"[!] Error during disassembly: {e}")
        
        prompt_user("\nPress Enter to continue...", on_interrupt="")
    
    def hex_viewer(self):
        """Simple hex viewer"""
        print("[+] Hex Viewer")
        
        file_path = prompt_user("Enter path to file: ", on_interrupt="")
        if not file_path or not os.path.exists(file_path):
            print("[!] Invalid file path or file does not exist.")
            return
            
        print(f"[*] Opening file in hex view: {file_path}")
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            offset = 0
            while offset < len(content):
                # Read 16 bytes at a time
                chunk = content[offset:offset+16]
                
                # Format as hex
                hex_values = ' '.join([f"{b:02x}" for b in chunk])
                
                # Format as ASCII (replace non-printable with dots)
                ascii_values = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
                
                # Print the line
                print(f"{offset:08x}:  {hex_values:<47}  |{ascii_values}|")
                
                offset += 16
                
                # Add paging for large files
                if offset % 256 == 0 and offset < len(content):
                    choice = (prompt_user("\nContinue viewing? (y/n): ", on_interrupt="n") or "n").lower()
                    if choice != 'y':
                        break
                        
        except Exception as e:
            print(f"[!] Error viewing file: {e}")
        
        prompt_user("\nPress Enter to continue...", on_interrupt="")
    
    def executable_packer_detector(self):
        """Detect if an executable is packed"""
        print("[+] Executable Packer Detector")
        
        binary_path = prompt_user("Enter path to executable: ", on_interrupt="")
        if not binary_path or not os.path.exists(binary_path):
            print("[!] Invalid file path or file does not exist.")
            return
            
        print(f"[*] Analyzing executable: {binary_path}")
        
        # Check for common packer signatures
        packer_signatures = {
            "UPX": [b"UPX", b"UPX!"],
            "MPRESS": [b"MPRESS", b"MPress"],
            "ASPack": [b"ASPack", b"ASPack"],
            "PECompact": [b"PECompact", b"PEC2"],
            "NSIS": [b"Nullsoft", b"NSIS"],
            "Themida": [b"Themida", b"WinLicense"],
            "Armadillo": [b"Armadillo", b".ARMD"],
            "MoleBox": [b"MoleBox", b"MBox"],
            "VMProtect": [b"VMProtect", b"VMP"],
            "Enigma": [b"Enigma", b"VB5!"]
        }
        
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
                
            detected_packers = []
            
            for packer, signatures in packer_signatures.items():
                for sig in signatures:
                    if sig in content:
                        detected_packers.append(packer)
                        break
            
            if detected_packers:
                print("[+] Executable appears to be packed!")
                print(f"[+] Detected packers: {', '.join(detected_packers)}")
                print("[*] Packed executables may be hiding malicious code")
                print("[*] Consider using a dedicated unpacker before analysis")
            else:
                # Check for entropy (high entropy often indicates packing/encryption)
                total = 0
                byte_counts = {}
                
                for byte in content:
                    if byte in byte_counts:
                        byte_counts[byte] += 1
                    else:
                        byte_counts[byte] = 1
                    total += 1
                
                entropy = 0
                for count in byte_counts.values():
                    probability = count / total
                    entropy -= probability * (math.log(probability) / math.log(2))
                
                if entropy > 7.0:
                    print(f"[!] File has high entropy ({entropy:.2f}/8.0)")
                    print("[!] This may indicate packing or encryption")
                else:
                    print(f"[+] File appears to be unpacked (entropy: {entropy:.2f}/8.0)")
                    print("[+] No known packer signatures detected")
        
        except Exception as e:
            print(f"[!] Error analyzing file: {e}")
        
        prompt_user("\nPress Enter to continue...", on_interrupt="")

def run_reverse_engineering_tools():
    """Run the reverse engineering tools"""
    return ReverseEngineeringTools()

# Function to display the reverse engineering menu
def reverse_engineering_menu():
    """Display the reverse engineering menu"""
    tools = run_reverse_engineering_tools()
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    ###########################################
    #        Reverse Engineering Tools        #
    ###########################################
    
    1. Binary Analysis
    2. Disassembler
    3. Hex Viewer
    4. Executable Packer Detector
    5. Back to Main Menu
    """)
        
        choice = prompt_user("Select an option: ", on_interrupt="5")
        if choice is None:
            return
        
        try:
            choice = int(choice)
            if choice == 1:
                tools.binary_analysis()
            elif choice == 2:
                tools.disassembler()
            elif choice == 3:
                tools.hex_viewer()
            elif choice == 4:
                tools.executable_packer_detector()
            elif choice == 5:
                return
            else:
                print("Invalid option. Please try again.")
                prompt_user("\nPress Enter to continue...", on_interrupt="")
        except ValueError:
            print("Please enter a number.")
            prompt_user("\nPress Enter to continue...", on_interrupt="")

# For standalone testing
if __name__ == "__main__":
    reverse_engineering_menu() 
