#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Dictionary attack and password cracking tools for Pegasus-Suite
"""

import os
import sys
import time
import hashlib
import string
import random
import itertools
from getpass import getpass

class DictionaryAttack:
    """Dictionary attack tools for password cracking"""
    
    def __init__(self):
        """Initialize the dictionary attack tools"""
        self.wordlists = {
            "common": os.path.join(os.path.dirname(__file__), "wordlists", "common.txt"),
            "rockyou-sample": os.path.join(os.path.dirname(__file__), "wordlists", "rockyou-sample.txt")
        }
        
        # Create wordlists directory if it doesn't exist
        os.makedirs(os.path.join(os.path.dirname(__file__), "wordlists"), exist_ok=True)
        
        # Create sample wordlist if it doesn't exist
        common_path = self.wordlists["common"]
        if not os.path.exists(common_path):
            with open(common_path, "w") as f:
                f.write("\n".join([
                    "password", "123456", "12345678", "qwerty", "abc123",
                    "monkey", "1234567", "letmein", "trustno1", "dragon",
                    "baseball", "111111", "iloveyou", "master", "sunshine",
                    "ashley", "bailey", "passw0rd", "shadow", "123123",
                    "654321", "superman", "qazwsx", "michael", "football"
                ]))
    
    def hash_cracker(self):
        """Crack password hashes using dictionary attack"""
        print("[+] Hash Cracker Tool")
        
        hash_value = input("Enter the hash to crack: ").strip()
        
        # Identify hash type
        hash_types = {
            32: "MD5",
            40: "SHA1",
            64: "SHA256",
            128: "SHA512"
        }
        
        hash_type = hash_types.get(len(hash_value), "Unknown")
        print(f"[*] Detected hash type: {hash_type}")
        
        if hash_type == "Unknown":
            print("[!] Hash length not recognized. Supported types: MD5, SHA1, SHA256, SHA512")
            hash_type = input("Specify hash type (MD5, SHA1, SHA256, SHA512): ").strip().upper()
            if hash_type not in ["MD5", "SHA1", "SHA256", "SHA512"]:
                print("[!] Invalid hash type.")
                return
        
        # Select wordlist
        print("\n[*] Available wordlists:")
        for i, name in enumerate(self.wordlists.keys(), 1):
            print(f"{i}. {name}")
        
        wordlist_choice = input("\nSelect wordlist or enter custom path: ")
        
        try:
            wordlist_choice = int(wordlist_choice)
            wordlist_names = list(self.wordlists.keys())
            if 1 <= wordlist_choice <= len(wordlist_names):
                wordlist_path = self.wordlists[wordlist_names[wordlist_choice-1]]
            else:
                print("[!] Invalid choice. Using common wordlist.")
                wordlist_path = self.wordlists["common"]
        except ValueError:
            # Assume it's a custom path
            wordlist_path = wordlist_choice
        
        if not os.path.exists(wordlist_path):
            print(f"[!] Wordlist not found: {wordlist_path}")
            print("[*] Using built-in common passwords list.")
            wordlist_path = self.wordlists["common"]
        
        # Start the attack
        print(f"\n[*] Starting dictionary attack against {hash_type} hash...")
        print(f"[*] Using wordlist: {wordlist_path}")
        
        start_time = time.time()
        password_found = False
        words_checked = 0
        
        try:
            with open(wordlist_path, "r", errors="ignore") as wordlist:
                for line in wordlist:
                    password = line.strip()
                    words_checked += 1
                    
                    # Generate hash based on type
                    if hash_type == "MD5":
                        generated_hash = hashlib.md5(password.encode()).hexdigest()
                    elif hash_type == "SHA1":
                        generated_hash = hashlib.sha1(password.encode()).hexdigest()
                    elif hash_type == "SHA256":
                        generated_hash = hashlib.sha256(password.encode()).hexdigest()
                    elif hash_type == "SHA512":
                        generated_hash = hashlib.sha512(password.encode()).hexdigest()
                    
                    # Check if hash matches
                    if generated_hash.lower() == hash_value.lower():
                        elapsed_time = time.time() - start_time
                        print(f"\n[+] Password found! {password}")
                        print(f"[*] Time elapsed: {elapsed_time:.2f} seconds")
                        print(f"[*] Passwords checked: {words_checked}")
                        password_found = True
                        break
                    
                    # Display progress every 1000 words
                    if words_checked % 1000 == 0:
                        elapsed_time = time.time() - start_time
                        if elapsed_time > 0:
                            rate = words_checked / elapsed_time
                            print(f"\r[*] Progress: {words_checked} passwords checked ({rate:.2f} p/s)", end="")
        
        except Exception as e:
            print(f"\n[!] Error: {e}")
        
        if not password_found:
            elapsed_time = time.time() - start_time
            print(f"\n[-] Password not found after checking {words_checked} passwords.")
            print(f"[*] Time elapsed: {elapsed_time:.2f} seconds")
    
    def password_strength_analyzer(self):
        """Analyze password strength"""
        print("[+] Password Strength Analyzer")
        
        password = getpass("Enter a password to analyze: ")
        
        if not password:
            print("[!] No password provided.")
            return
        
        # Calculate entropy and score
        length = len(password)
        
        # Check character sets used
        has_lowercase = any(c.islower() for c in password)
        has_uppercase = any(c.isupper() for c in password)
        has_digits = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        charset_size = 0
        if has_lowercase:
            charset_size += 26
        if has_uppercase:
            charset_size += 26
        if has_digits:
            charset_size += 10
        if has_special:
            charset_size += 33  # Approximate count of special chars
        
        # Calculate entropy (information content)
        import math
        if charset_size > 0:
            entropy = length * math.log2(charset_size)
        else:
            entropy = 0
        
        # Score from 0-100
        score = min(100, entropy * 4)
        
        # Common patterns and weaknesses
        weaknesses = []
        
        # Check for dictionary words
        common_words = ["password", "admin", "user", "login", "welcome", "qwerty", "123456"]
        for word in common_words:
            if word in password.lower():
                weaknesses.append(f"Contains common word: '{word}'")
        
        # Check for keyboard patterns
        keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "1234", "4321"]
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                weaknesses.append(f"Contains keyboard pattern: '{pattern}'")
        
        # Check for repetitions
        if any(password.count(c) > 2 for c in password):
            weaknesses.append("Contains repeated characters")
        
        # Check for sequences
        for i in range(len(password) - 2):
            if (ord(password[i]) + 1 == ord(password[i+1]) and 
                ord(password[i+1]) + 1 == ord(password[i+2])):
                weaknesses.append("Contains sequential characters")
                break
        
        # Result
        print("\n--- Password Analysis Results ---")
        print(f"Length: {length} characters")
        print(f"Character sets used:")
        print(f"  - Lowercase letters: {'Yes' if has_lowercase else 'No'}")
        print(f"  - Uppercase letters: {'Yes' if has_uppercase else 'No'}")
        print(f"  - Numbers: {'Yes' if has_digits else 'No'}")
        print(f"  - Special characters: {'Yes' if has_special else 'No'}")
        print(f"Entropy: {entropy:.2f} bits")
        print(f"Strength score: {score:.2f}/100")
        
        # Rating
        if score < 30:
            rating = "Very Weak"
        elif score < 50:
            rating = "Weak"
        elif score < 70:
            rating = "Moderate"
        elif score < 90:
            rating = "Strong"
        else:
            rating = "Very Strong"
        
        print(f"Rating: {rating}")
        
        if weaknesses:
            print("\nWeaknesses found:")
            for weakness in weaknesses:
                print(f"  - {weakness}")
        
        # Time to crack estimates
        print("\nEstimated time to crack:")
        rates = {
            "Online attack (limited attempts)": 100,  # 100 guesses/second
            "Offline attack (basic computer)": 1000000,  # 1M guesses/second
            "Offline attack (GPU)": 1000000000,  # 1B guesses/second
            "Offline attack (specialized hardware)": 100000000000  # 100B guesses/second
        }
        
        if charset_size > 0:
            combinations = charset_size ** length
            for name, rate in rates.items():
                seconds = combinations / rate
                
                if seconds < 60:
                    time_str = f"{seconds:.2f} seconds"
                elif seconds < 3600:
                    time_str = f"{seconds/60:.2f} minutes"
                elif seconds < 86400:
                    time_str = f"{seconds/3600:.2f} hours"
                elif seconds < 31536000:
                    time_str = f"{seconds/86400:.2f} days"
                elif seconds < 315360000:
                    time_str = f"{seconds/31536000:.2f} years"
                else:
                    time_str = "centuries"
                
                print(f"  - {name}: {time_str}")

# Main function
def run_dictionary_attack():
    """Run the dictionary attack module"""
    tools = DictionaryAttack()
    return tools 