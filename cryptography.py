#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Cryptography Tools for Pegasus-Suite
"""

import os
import sys
import hashlib
import base64
import secrets
import string
import platform
from datetime import datetime

# Try to import cryptography module
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class CryptographyTools:
    """Cryptography tools for encryption, hashing, etc."""
    
    def __init__(self):
        """Initialize cryptography tools"""
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
    
    def hash_generator(self):
        """Generate various hash types"""
        print("[+] Hash Generator Tool")
        
        text = input("Enter text to hash: ")
        if not text:
            print("[!] No text provided.")
            return
        
        # Convert to bytes if it's not already
        if isinstance(text, str):
            text_bytes = text.encode('utf-8')
        else:
            text_bytes = text
        
        print(f"\n[*] Generating hashes for: {text}")
        
        # Generate various hash types
        print(f"[+] MD5: {hashlib.md5(text_bytes).hexdigest()}")
        print(f"[+] SHA-1: {hashlib.sha1(text_bytes).hexdigest()}")
        print(f"[+] SHA-224: {hashlib.sha224(text_bytes).hexdigest()}")
        print(f"[+] SHA-256: {hashlib.sha256(text_bytes).hexdigest()}")
        print(f"[+] SHA-384: {hashlib.sha384(text_bytes).hexdigest()}")
        print(f"[+] SHA-512: {hashlib.sha512(text_bytes).hexdigest()}")
        
        # Base64 encoding (not a hash, but useful)
        print(f"[+] Base64: {base64.b64encode(text_bytes).decode('utf-8')}")
        
        input("\nPress Enter to continue...")
    
    def password_generator(self):
        """Generate secure random passwords"""
        print("[+] Secure Password Generator")
        
        try:
            length = int(input("Enter password length (8-64): "))
            if length < 8:
                print("[!] Password too short. Using minimum length of 8.")
                length = 8
            elif length > 64:
                print("[!] Password too long. Using maximum length of 64.")
                length = 64
        except ValueError:
            print("[!] Invalid input. Using default length of 16.")
            length = 16
        
        print("[*] Select character sets to include:")
        use_lowercase = input("Include lowercase letters? (y/n): ").lower() == 'y'
        use_uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
        use_digits = input("Include digits? (y/n): ").lower() == 'y'
        use_symbols = input("Include symbols? (y/n): ").lower() == 'y'
        
        # Ensure at least one character set is selected
        if not any([use_lowercase, use_uppercase, use_digits, use_symbols]):
            print("[!] No character sets selected. Using all character sets.")
            use_lowercase = use_uppercase = use_digits = use_symbols = True
        
        # Create character pool
        chars = ""
        if use_lowercase:
            chars += string.ascii_lowercase
        if use_uppercase:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += string.punctuation
        
        # Generate passwords
        num_passwords = int(input("How many passwords to generate? (1-10): ") or "1")
        num_passwords = max(1, min(10, num_passwords))
        
        print(f"\n[+] Generating {num_passwords} password(s) of length {length}:")
        
        for i in range(num_passwords):
            password = ''.join(secrets.choice(chars) for _ in range(length))
            print(f"[+] Password {i+1}: {password}")
        
        input("\nPress Enter to continue...")
    
    def file_encryption(self):
        """Encrypt/decrypt files using symmetric encryption"""
        if not CRYPTO_AVAILABLE:
            print("[!] The 'cryptography' library is required for file encryption.")
            print("[!] Install it with: pip install cryptography")
            input("\nPress Enter to continue...")
            return
        
        print("[+] File Encryption/Decryption Tool")
        print("[*] Select operation:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            # Encrypt a file
            file_path = input("Enter path to file to encrypt: ")
            if not file_path or not os.path.exists(file_path):
                print("[!] Invalid file path or file does not exist.")
                input("\nPress Enter to continue...")
                return
            
            password = input("Enter encryption password: ")
            if not password:
                print("[!] No password provided.")
                input("\nPress Enter to continue...")
                return
            
            # Derive encryption key from password
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Create Fernet cipher
            cipher = Fernet(key)
            
            try:
                # Read file content
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                # Encrypt data
                encrypted_data = cipher.encrypt(data)
                
                # Write encrypted file
                encrypted_file = file_path + ".encrypted"
                with open(encrypted_file, 'wb') as f:
                    # Write salt at the beginning of the file
                    f.write(salt)
                    f.write(encrypted_data)
                
                print(f"[+] File encrypted successfully: {encrypted_file}")
            except Exception as e:
                print(f"[!] Error encrypting file: {e}")
        
        elif choice == "2":
            # Decrypt a file
            file_path = input("Enter path to encrypted file: ")
            if not file_path or not os.path.exists(file_path):
                print("[!] Invalid file path or file does not exist.")
                input("\nPress Enter to continue...")
                return
            
            password = input("Enter decryption password: ")
            if not password:
                print("[!] No password provided.")
                input("\nPress Enter to continue...")
                return
            
            try:
                # Read file content
                with open(file_path, 'rb') as f:
                    # Read salt (first 16 bytes)
                    salt = f.read(16)
                    encrypted_data = f.read()
                
                # Derive decryption key from password and salt
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                
                # Create Fernet cipher
                cipher = Fernet(key)
                
                # Decrypt data
                decrypted_data = cipher.decrypt(encrypted_data)
                
                # Write decrypted file
                if file_path.endswith('.encrypted'):
                    decrypted_file = file_path[:-10]
                else:
                    decrypted_file = file_path + ".decrypted"
                
                with open(decrypted_file, 'wb') as f:
                    f.write(decrypted_data)
                
                print(f"[+] File decrypted successfully: {decrypted_file}")
            except Exception as e:
                print(f"[!] Error decrypting file: {e}")
                print("[!] This could be due to an incorrect password or corrupted file.")
        
        else:
            print("[!] Invalid option.")
        
        input("\nPress Enter to continue...")
    
    def hash_cracker(self):
        """Basic hash cracking using dictionary attack"""
        print("[+] Hash Cracking Tool")
        print("[!] This is a basic demonstration and is limited in capability.")
        print("[!] For serious hash cracking, consider using specialized tools.")
        
        hash_value = input("Enter hash to crack: ").lower()
        if not hash_value:
            print("[!] No hash provided.")
            input("\nPress Enter to continue...")
            return
        
        # Try to determine hash type based on length
        hash_type = None
        if len(hash_value) == 32:
            hash_type = "md5"
            hash_func = hashlib.md5
        elif len(hash_value) == 40:
            hash_type = "sha1"
            hash_func = hashlib.sha1
        elif len(hash_value) == 64:
            hash_type = "sha256"
            hash_func = hashlib.sha256
        else:
            print("[!] Unable to determine hash type from length.")
            print("[*] Select hash type:")
            print("1. MD5")
            print("2. SHA-1")
            print("3. SHA-256")
            
            type_choice = input("\nSelect hash type: ")
            
            if type_choice == "1":
                hash_type = "md5"
                hash_func = hashlib.md5
            elif type_choice == "2":
                hash_type = "sha1"
                hash_func = hashlib.sha1
            elif type_choice == "3":
                hash_type = "sha256"
                hash_func = hashlib.sha256
            else:
                print("[!] Invalid option. Using MD5.")
                hash_type = "md5"
                hash_func = hashlib.md5
        
        print(f"[*] Using hash type: {hash_type.upper()}")
        
        # Ask for dictionary file
        dict_path = input("Enter path to dictionary file: ")
        if not dict_path or not os.path.exists(dict_path):
            print("[!] Invalid dictionary path or file does not exist.")
            print("[*] Using built-in small dictionary.")
            
            # Built-in small dictionary
            dictionary = [
                "password", "123456", "12345678", "qwerty", "abc123",
                "monkey", "letmein", "dragon", "111111", "baseball",
                "iloveyou", "trustno1", "sunshine", "master", "welcome",
                "shadow", "ashley", "football", "jesus", "michael",
                "ninja", "mustang", "password1", "admin", "test"
            ]
        else:
            try:
                # Read dictionary file
                with open(dict_path, 'r', errors='ignore') as f:
                    dictionary = [line.strip() for line in f]
                print(f"[+] Loaded {len(dictionary)} words from dictionary.")
            except Exception as e:
                print(f"[!] Error reading dictionary file: {e}")
                input("\nPress Enter to continue...")
                return
        
        print("[*] Starting dictionary attack...")
        start_time = datetime.now()
        
        found = False
        tested = 0
        
        for word in dictionary:
            tested += 1
            
            # Calculate hash of the word
            word_hash = hash_func(word.encode()).hexdigest()
            
            # Check if it matches the target hash
            if word_hash == hash_value:
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                print(f"\n[+] Hash cracked!")
                print(f"[+] Original text: {word}")
                print(f"[+] Time taken: {duration:.2f} seconds")
                print(f"[+] Words tested: {tested}")
                
                found = True
                break
            
            # Show progress every 1000 words
            if tested % 1000 == 0:
                print(f"\r[*] Tested {tested} words...", end="")
        
        if not found:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            print(f"\n[-] Hash not found in dictionary.")
            print(f"[*] Time taken: {duration:.2f} seconds")
            print(f"[*] Words tested: {tested}")
        
        input("\nPress Enter to continue...")
    
    def encoding_tools(self):
        """Various encoding/decoding tools"""
        print("[+] Encoding/Decoding Tools")
        
        print("[*] Select operation:")
        print("1. Base64 Encode")
        print("2. Base64 Decode")
        print("3. URL Encode")
        print("4. URL Decode")
        print("5. Hex Encode")
        print("6. Hex Decode")
        
        choice = input("\nSelect an option: ")
        
        text = input("Enter text: ")
        if not text:
            print("[!] No text provided.")
            input("\nPress Enter to continue...")
            return
        
        result = ""
        
        try:
            if choice == "1":
                # Base64 Encode
                result = base64.b64encode(text.encode()).decode()
                print(f"[+] Base64 Encoded: {result}")
            
            elif choice == "2":
                # Base64 Decode
                result = base64.b64decode(text.encode()).decode()
                print(f"[+] Base64 Decoded: {result}")
            
            elif choice == "3":
                # URL Encode
                import urllib.parse
                result = urllib.parse.quote(text)
                print(f"[+] URL Encoded: {result}")
            
            elif choice == "4":
                # URL Decode
                import urllib.parse
                result = urllib.parse.unquote(text)
                print(f"[+] URL Decoded: {result}")
            
            elif choice == "5":
                # Hex Encode
                result = text.encode().hex()
                print(f"[+] Hex Encoded: {result}")
            
            elif choice == "6":
                # Hex Decode
                result = bytes.fromhex(text).decode()
                print(f"[+] Hex Decoded: {result}")
            
            else:
                print("[!] Invalid option.")
        
        except Exception as e:
            print(f"[!] Error during encoding/decoding: {e}")
        
        input("\nPress Enter to continue...")

def run_crypto_tools():
    """Run the cryptography tools"""
    return CryptographyTools()

# Function to display the cryptography menu
def crypto_menu():
    """Display the cryptography menu"""
    tools = run_crypto_tools()
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    ###########################################
    #           Cryptography Tools            #
    ###########################################
    
    1. Hash Generator
    2. Password Generator
    3. File Encryption/Decryption
    4. Hash Cracker
    5. Encoding/Decoding Tools
    6. Back to Main Menu
    """)
        
        choice = input("Select an option: ")
        
        try:
            choice = int(choice)
            if choice == 1:
                tools.hash_generator()
            elif choice == 2:
                tools.password_generator()
            elif choice == 3:
                tools.file_encryption()
            elif choice == 4:
                tools.hash_cracker()
            elif choice == 5:
                tools.encoding_tools()
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
    crypto_menu() 