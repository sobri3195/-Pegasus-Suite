#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Digital Forensics Tools for Pegasus-Suite
"""

import os
import sys
import time
import hashlib
import platform
import datetime
import subprocess
from shutil import copyfile

class ForensicsTools:
    """Digital forensics analysis tools"""
    
    def __init__(self):
        """Initialize forensics tools"""
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        self.case_folder = "pegasus_case_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def file_hashing(self):
        """Generate hashes for a file to verify integrity"""
        print("[+] File Hashing Tool")
        
        file_path = input("Enter path to file: ")
        if not file_path or not os.path.exists(file_path):
            print("[!] Invalid file path or file does not exist.")
            return
            
        print(f"[*] Calculating hashes for: {file_path}")
        print("[*] This may take a while for large files...")
        
        try:
            # Calculate various hashes
            with open(file_path, 'rb') as f:
                content = f.read()
                
                # MD5 hash
                md5_hash = hashlib.md5(content).hexdigest()
                print(f"[+] MD5: {md5_hash}")
                
                # SHA-1 hash
                sha1_hash = hashlib.sha1(content).hexdigest()
                print(f"[+] SHA-1: {sha1_hash}")
                
                # SHA-256 hash
                sha256_hash = hashlib.sha256(content).hexdigest()
                print(f"[+] SHA-256: {sha256_hash}")
                
            # Get file metadata
            file_stat = os.stat(file_path)
            print(f"\n[+] File size: {file_stat.st_size} bytes")
            print(f"[+] Created: {datetime.datetime.fromtimestamp(file_stat.st_ctime)}")
            print(f"[+] Last modified: {datetime.datetime.fromtimestamp(file_stat.st_mtime)}")
            print(f"[+] Last accessed: {datetime.datetime.fromtimestamp(file_stat.st_atime)}")
            
            # Option to save report
            save_report = input("\nSave hash report to file? (y/n): ").lower() == 'y'
            if save_report:
                # Create case folder if it doesn't exist
                if not os.path.exists(self.case_folder):
                    os.makedirs(self.case_folder)
                
                report_name = os.path.join(self.case_folder, f"hash_report_{os.path.basename(file_path)}.txt")
                with open(report_name, 'w') as report:
                    report.write(f"File Integrity Report\n")
                    report.write(f"===================\n\n")
                    report.write(f"Filename: {os.path.basename(file_path)}\n")
                    report.write(f"Path: {os.path.abspath(file_path)}\n")
                    report.write(f"Size: {file_stat.st_size} bytes\n")
                    report.write(f"Created: {datetime.datetime.fromtimestamp(file_stat.st_ctime)}\n")
                    report.write(f"Last modified: {datetime.datetime.fromtimestamp(file_stat.st_mtime)}\n")
                    report.write(f"Last accessed: {datetime.datetime.fromtimestamp(file_stat.st_atime)}\n\n")
                    report.write(f"MD5: {md5_hash}\n")
                    report.write(f"SHA-1: {sha1_hash}\n")
                    report.write(f"SHA-256: {sha256_hash}\n")
                    
                print(f"[+] Report saved to {report_name}")
                
        except Exception as e:
            print(f"[!] Error calculating hashes: {e}")
        
        input("\nPress Enter to continue...")
    
    def data_carving(self):
        """Carve data from files to recover deleted content"""
        print("[+] Basic Data Carving Tool")
        
        file_path = input("Enter path to file or disk image: ")
        if not file_path or not os.path.exists(file_path):
            print("[!] Invalid file path or file does not exist.")
            return
            
        print(f"[*] Initializing data carving on: {file_path}")
        
        # Define common file signatures (magic numbers)
        signatures = {
            "JPEG": [b"\xFF\xD8\xFF\xE0", b"\xFF\xD8\xFF\xE1"],
            "PNG": [b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"],
            "GIF": [b"\x47\x49\x46\x38\x37\x61", b"\x47\x49\x46\x38\x39\x61"],
            "PDF": [b"\x25\x50\x44\x46"],
            "ZIP": [b"\x50\x4B\x03\x04"],
            "Office": [b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"],
            "DOCX": [b"\x50\x4B\x03\x04\x14\x00\x06\x00"],
            "Executable": [b"\x4D\x5A"]
        }
        
        # Create case folder if it doesn't exist
        if not os.path.exists(self.case_folder):
            os.makedirs(self.case_folder)
            
        print("[*] Starting file carving process...")
        print("[*] This may take a while for large files...")
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            recovered_files = {}
            
            # Search for file signatures
            for file_type, sigs in signatures.items():
                recovered_files[file_type] = []
                print(f"[*] Searching for {file_type} files...")
                
                for sig in sigs:
                    offset = 0
                    while True:
                        offset = content.find(sig, offset)
                        if offset == -1:
                            break
                            
                        print(f"[+] Found potential {file_type} file at offset {offset}")
                        recovered_files[file_type].append(offset)
                        offset += 1
            
            # Check if any files were found
            total_files = sum(len(offsets) for offsets in recovered_files.values())
            if total_files == 0:
                print("[!] No files found with known signatures.")
                input("\nPress Enter to continue...")
                return
                
            print(f"[+] Found {total_files} potential files")
            
            # Ask if user wants to extract files
            extract = input("\nExtract found files? (y/n): ").lower() == 'y'
            if extract:
                recovery_dir = os.path.join(self.case_folder, "recovered_files")
                if not os.path.exists(recovery_dir):
                    os.makedirs(recovery_dir)
                
                for file_type, offsets in recovered_files.items():
                    if not offsets:
                        continue
                        
                    # Create subdirectory for this file type
                    type_dir = os.path.join(recovery_dir, file_type)
                    if not os.path.exists(type_dir):
                        os.makedirs(type_dir)
                    
                    # Extract each file
                    for i, offset in enumerate(offsets):
                        # Determine a reasonable file size (this is simplistic)
                        # For real carving, you'd need to know file format specifics
                        if file_type == "JPEG":
                            # Look for JPEG end marker
                            end_offset = content.find(b"\xFF\xD9", offset)
                            if end_offset > offset:
                                file_data = content[offset:end_offset+2]
                            else:
                                file_data = content[offset:offset+50000]  # Arbitrary size
                        else:
                            # Just take a chunk of data
                            file_data = content[offset:offset+100000]  # Arbitrary size
                        
                        # Save the file
                        file_name = os.path.join(type_dir, f"{file_type}_{i+1}.{file_type.lower()}")
                        with open(file_name, 'wb') as f:
                            f.write(file_data)
                            
                        print(f"[+] Saved potential {file_type} file to {file_name}")
                
                print(f"[+] All files extracted to {recovery_dir}")
                
        except Exception as e:
            print(f"[!] Error during data carving: {e}")
        
        input("\nPress Enter to continue...")
    
    def disk_imaging(self):
        """Create a forensic image of a drive"""
        print("[+] Disk Imaging Tool")
        
        if self.is_windows:
            print("[!] Disk imaging on Windows requires administrative privileges.")
        else:
            print("[!] Disk imaging on Linux/Unix requires root privileges.")
        
        print("[*] Available drives:")
        
        # List available drives
        if self.is_windows:
            os.system("wmic diskdrive list brief")
        else:
            os.system("lsblk")
        
        source = input("\nEnter source drive path (e.g., /dev/sdb or \\\\.\\PhysicalDrive1): ")
        if not source:
            print("[!] No source drive specified.")
            input("\nPress Enter to continue...")
            return
            
        target = input("Enter target file path for the image: ")
        if not target:
            # Create default target in case folder
            if not os.path.exists(self.case_folder):
                os.makedirs(self.case_folder)
            target = os.path.join(self.case_folder, "disk_image.dd")
        
        print(f"[*] Source: {source}")
        print(f"[*] Target: {target}")
        print("[!] WARNING: This operation may take a long time.")
        print("[!] WARNING: Ensure you have sufficient disk space.")
        
        confirm = input("\nAre you sure you want to continue? (y/n): ").lower()
        if confirm != 'y':
            print("[*] Disk imaging canceled.")
            input("\nPress Enter to continue...")
            return
        
        # Create the image
        print("[*] Starting disk imaging. This may take a long time...")
        
        try:
            if self.is_windows:
                # Windows doesn't have dd by default, so simulate the process
                print("[!] Direct disk imaging not available in this version.")
                print("[!] Consider using professional forensic tools for actual cases.")
                print("[*] Simulating disk imaging process...")
                
                # Simulate progress
                for i in range(0, 101, 10):
                    print(f"\r[*] Progress: {i}%", end="")
                    time.sleep(1)
                print("\r[*] Progress: 100%")
                
                print("[+] Simulated disk image created.")
            else:
                # On Linux, we can use dd
                command = f"sudo dd if={source} of={target} bs=4M status=progress"
                print(f"[*] Running command: {command}")
                os.system(command)
                
                # Create a hash of the image for verification
                print("[*] Creating MD5 hash of the image for verification...")
                os.system(f"md5sum {target} > {target}.md5")
                
                print(f"[+] Disk image created: {target}")
                print(f"[+] MD5 hash saved: {target}.md5")
        
        except Exception as e:
            print(f"[!] Error during disk imaging: {e}")
        
        input("\nPress Enter to continue...")
    
    def metadata_analysis(self):
        """Extract and analyze metadata from files"""
        print("[+] Metadata Analysis Tool")
        
        file_path = input("Enter path to file: ")
        if not file_path or not os.path.exists(file_path):
            print("[!] Invalid file path or file does not exist.")
            return
            
        print(f"[*] Analyzing metadata for: {file_path}")
        
        # Get basic file information
        try:
            file_stat = os.stat(file_path)
            print(f"[+] File size: {file_stat.st_size} bytes")
            print(f"[+] Created: {datetime.datetime.fromtimestamp(file_stat.st_ctime)}")
            print(f"[+] Last modified: {datetime.datetime.fromtimestamp(file_stat.st_mtime)}")
            print(f"[+] Last accessed: {datetime.datetime.fromtimestamp(file_stat.st_atime)}")
            
            # Determine file type
            if self.is_windows:
                file_type = os.path.splitext(file_path)[1].lower()
            else:
                try:
                    file_type = subprocess.check_output(["file", "-b", file_path]).decode().strip()
                except:
                    file_type = os.path.splitext(file_path)[1].lower()
            
            print(f"[+] File type: {file_type}")
            
            # Extract specific metadata based on file type
            if file_type.endswith(('jpg', 'jpeg', 'png', 'gif', 'bmp')) or "image" in file_type.lower():
                print("[*] Extracting image metadata...")
                
                if self.is_windows:
                    print("[!] Advanced image metadata extraction not available on Windows.")
                else:
                    try:
                        # Try to use exiftool if available
                        exif_data = subprocess.check_output(["exiftool", file_path]).decode()
                        print("\n[+] EXIF Metadata:")
                        print(exif_data)
                    except:
                        print("[!] ExifTool not found. Install it for better metadata extraction.")
            
            elif file_type.endswith(('doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx')) or "document" in file_type.lower():
                print("[*] Extracting document metadata...")
                print("[!] For detailed document metadata, consider installing specialized tools.")
                
                # Basic document analysis - look for strings that might be metadata
                with open(file_path, 'rb') as f:
                    content = f.read()
                    
                # Look for potential author/creator information
                author_patterns = [b"Author", b"Creator", b"Last Modified By", b"Microsoft Office"]
                for pattern in author_patterns:
                    pos = content.find(pattern)
                    if pos != -1:
                        # Extract a chunk around the found text
                        start = max(0, pos - 10)
                        end = min(len(content), pos + 50)
                        chunk = content[start:end]
                        try:
                            print(f"[+] Found potential metadata: {chunk.decode('utf-8', errors='ignore')}")
                        except:
                            pass
            
            # Option to save report
            save_report = input("\nSave metadata report to file? (y/n): ").lower() == 'y'
            if save_report:
                # Create case folder if it doesn't exist
                if not os.path.exists(self.case_folder):
                    os.makedirs(self.case_folder)
                
                report_name = os.path.join(self.case_folder, f"metadata_{os.path.basename(file_path)}.txt")
                with open(report_name, 'w') as report:
                    report.write(f"File Metadata Report\n")
                    report.write(f"===================\n\n")
                    report.write(f"Filename: {os.path.basename(file_path)}\n")
                    report.write(f"Path: {os.path.abspath(file_path)}\n")
                    report.write(f"Size: {file_stat.st_size} bytes\n")
                    report.write(f"Created: {datetime.datetime.fromtimestamp(file_stat.st_ctime)}\n")
                    report.write(f"Last modified: {datetime.datetime.fromtimestamp(file_stat.st_mtime)}\n")
                    report.write(f"Last accessed: {datetime.datetime.fromtimestamp(file_stat.st_atime)}\n")
                    report.write(f"File type: {file_type}\n")
                    
                print(f"[+] Report saved to {report_name}")
        
        except Exception as e:
            print(f"[!] Error analyzing metadata: {e}")
        
        input("\nPress Enter to continue...")
    
    def memory_analysis(self):
        """Basic memory dump analysis"""
        print("[+] Memory Analysis Tools")
        
        print("[*] Memory analysis capabilities:")
        print("1. Analyze an existing memory dump")
        print("2. Create a memory dump (requires admin/root)")
        
        option = input("\nSelect an option: ")
        
        if option == "1":
            # Analyze existing dump
            dump_path = input("Enter path to memory dump file: ")
            if not dump_path or not os.path.exists(dump_path):
                print("[!] Invalid file path or file does not exist.")
                input("\nPress Enter to continue...")
                return
                
            print(f"[*] Analyzing memory dump: {dump_path}")
            print("[*] Basic analysis capabilities:")
            print("1. Search for strings")
            print("2. Search for patterns (e.g., email, IP, URL)")
            
            analysis_option = input("\nSelect analysis type: ")
            
            if analysis_option == "1":
                search_term = input("Enter string to search for: ")
                if not search_term:
                    print("[!] No search term provided.")
                    input("\nPress Enter to continue...")
                    return
                    
                print(f"[*] Searching for '{search_term}' in memory dump...")
                
                try:
                    # Use grep to search the dump
                    if self.is_windows:
                        print("[!] Advanced string search not available on Windows.")
                        # Basic Python search
                        with open(dump_path, 'rb') as f:
                            content = f.read()
                        
                        term_bytes = search_term.encode()
                        positions = []
                        pos = -1
                        
                        while True:
                            pos = content.find(term_bytes, pos + 1)
                            if pos == -1:
                                break
                            positions.append(pos)
                        
                        if positions:
                            print(f"[+] Found {len(positions)} occurrences of '{search_term}'")
                            print("[+] Showing context for first 5 occurrences:")
                            
                            for i, pos in enumerate(positions[:5]):
                                start = max(0, pos - 20)
                                end = min(len(content), pos + len(term_bytes) + 20)
                                context = content[start:end]
                                print(f"\n[+] Occurrence {i+1} at offset {pos}:")
                                print(f"    ...{context.decode('ascii', errors='ignore')}...")
                        else:
                            print(f"[!] No occurrences of '{search_term}' found.")
                    else:
                        # Use grep on Linux
                        os.system(f"grep -a -b -o '.{{0,20}}{search_term}.{{0,20}}' {dump_path} | head -n 10")
                except Exception as e:
                    print(f"[!] Error searching memory dump: {e}")
            
            elif analysis_option == "2":
                print("[*] Select pattern to search for:")
                print("1. Email addresses")
                print("2. IP addresses")
                print("3. URLs")
                
                pattern_option = input("\nSelect pattern: ")
                
                pattern = ""
                if pattern_option == "1":
                    pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}'
                    print("[*] Searching for email addresses...")
                elif pattern_option == "2":
                    pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                    print("[*] Searching for IP addresses...")
                elif pattern_option == "3":
                    pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+\.[^\s<>"]+'
                    print("[*] Searching for URLs...")
                else:
                    print("[!] Invalid option.")
                    input("\nPress Enter to continue...")
                    return
                
                try:
                    if self.is_windows:
                        print("[!] Advanced pattern search not available on Windows.")
                    else:
                        # Use grep with regex on Linux
                        os.system(f"grep -a -E -o '{pattern}' {dump_path} | sort | uniq -c | sort -nr | head -n 20")
                except Exception as e:
                    print(f"[!] Error searching for patterns: {e}")
            
            else:
                print("[!] Invalid option.")
        
        elif option == "2":
            # Create memory dump
            print("[!] Creating a memory dump requires administrative/root privileges.")
            print("[!] For proper forensic memory acquisition, specialized tools are recommended.")
            
            if self.is_windows:
                print("[!] Memory dump creation not available in this version for Windows.")
                print("[!] Consider using tools like FTK Imager or DumpIt.")
            else:
                try:
                    # Check if LiME is available (Linux Memory Extractor)
                    lime_check = subprocess.call(["which", "insmod"], 
                                               stdout=subprocess.DEVNULL, 
                                               stderr=subprocess.DEVNULL)
                    
                    if lime_check == 0:
                        print("[+] System appears to support kernel modules.")
                        print("[!] Memory acquisition with LiME requires the module to be built.")
                        print("[!] This is beyond the scope of this tool.")
                    else:
                        print("[!] Kernel module support not detected.")
                    
                    print("[!] For Linux memory acquisition, consider using LiME or other specialized tools.")
                except:
                    print("[!] Unable to check for memory acquisition capabilities.")
        
        else:
            print("[!] Invalid option.")
        
        input("\nPress Enter to continue...")

def run_forensics_tools():
    """Run the forensics tools"""
    return ForensicsTools()

# Function to display the forensics menu
def forensics_menu():
    """Display the forensics menu"""
    tools = run_forensics_tools()
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    ###########################################
    #        Digital Forensics Tools          #
    ###########################################
    
    1. File Hashing & Integrity
    2. Data Carving
    3. Disk Imaging
    4. Metadata Analysis
    5. Memory Analysis
    6. Back to Main Menu
    """)
        
        choice = input("Select an option: ")
        
        try:
            choice = int(choice)
            if choice == 1:
                tools.file_hashing()
            elif choice == 2:
                tools.data_carving()
            elif choice == 3:
                tools.disk_imaging()
            elif choice == 4:
                tools.metadata_analysis()
            elif choice == 5:
                tools.memory_analysis()
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
    forensics_menu() 