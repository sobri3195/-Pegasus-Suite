#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Password cracking and analysis tools for Pegasus-Suite
"""

import os
import sys
import time
import hashlib
import string
import random
import itertools
import threading
import queue as queue_module
from getpass import getpass

class PasswordTools:
    """Collection of password analysis and cracking tools"""
    
    def __init__(self):
        """Initialize the password tools"""
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
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def dictionary_attack_menu(self):
        """Display the dictionary attack menu"""
        self.clear_screen()
        print("""
        ###########################################
        #         Dictionary Attack Tools         #
        ###########################################
        
        1. Hash Cracker
        2. Password File Generator
        3. Password Strength Analyzer
        4. Custom Wordlist Creator
        5. Back to Main Menu
        """)
        
        choice = input("Select an option: ")
        
        try:
            choice = int(choice)
            if choice == 1:
                self.hash_cracker()
            elif choice == 2:
                self.password_file_generator()
            elif choice == 3:
                self.password_strength_analyzer()
            elif choice == 4:
                self.custom_wordlist_creator()
            elif choice == 5:
                return
            else:
                print("Invalid option. Please try again.")
                input("\nPress Enter to continue...")
                self.dictionary_attack_menu()
        except ValueError:
            print("Please enter a number.")
            input("\nPress Enter to continue...")
            self.dictionary_attack_menu()
    
    def hash_cracker(self):
        """Crack password hashes using dictionary attack"""
        self.clear_screen()
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
                input("\nPress Enter to continue...")
                self.dictionary_attack_menu()
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
        
        input("\nPress Enter to continue...")
        self.dictionary_attack_menu()
    
    def password_file_generator(self):
        """Generate password lists for cracking"""
        self.clear_screen()
        print("[+] Password File Generator")
        
        output_file = input("Enter output file name [passwords.txt]: ") or "passwords.txt"
        
        print("\n[*] Password generation methods:")
        print("1. Character set combination")
        print("2. Word mangling (variations of base words)")
        print("3. Pattern-based")
        
        method = input("\nSelect method [1]: ") or "1"
        
        try:
            method = int(method)
            
            if method == 1:
                # Character set combination
                print("\n[*] Define character sets to use:")
                print("1. Lowercase letters (a-z)")
                print("2. Uppercase letters (A-Z)")
                print("3. Numbers (0-9)")
                print("4. Special characters (!@#$%^&*)")
                
                char_sets = input("Enter set numbers (e.g., 123 for lowercase, uppercase, and numbers): ")
                
                charset = ""
                if "1" in char_sets:
                    charset += string.ascii_lowercase
                if "2" in char_sets:
                    charset += string.ascii_uppercase
                if "3" in char_sets:
                    charset += string.digits
                if "4" in char_sets:
                    charset += "!@#$%^&*()_+-=[]{}|;:,.<>?/"
                
                if not charset:
                    print("[!] No character sets selected. Using lowercase letters.")
                    charset = string.ascii_lowercase
                
                min_length = int(input("Enter minimum password length [4]: ") or "4")
                max_length = int(input("Enter maximum password length [6]: ") or "6")
                
                if min_length < 1:
                    min_length = 1
                if max_length > 12:
                    print("[!] Maximum length limited to 12 to avoid excessive file size.")
                    max_length = 12
                if max_length < min_length:
                    max_length = min_length
                
                count = 0
                max_passwords = 1000000  # Limit to prevent massive files
                
                print(f"\n[*] Generating passwords (length {min_length}-{max_length}) using: {charset}")
                print(f"[*] This may take some time. Limited to {max_passwords} passwords.")
                
                with open(output_file, "w") as f:
                    for length in range(min_length, max_length + 1):
                        for password in itertools.islice(itertools.product(charset, repeat=length), max_passwords // (max_length - min_length + 1)):
                            f.write("".join(password) + "\n")
                            count += 1
                            
                            if count % 10000 == 0:
                                print(f"\r[*] Generated {count} passwords...", end="")
                            
                            if count >= max_passwords:
                                break
                        
                        if count >= max_passwords:
                            break
                
                print(f"\n[+] Generated {count} passwords and saved to {output_file}")
            
            elif method == 2:
                # Word mangling
                base_words = input("Enter base words (comma separated): ").split(",")
                base_words = [word.strip() for word in base_words if word.strip()]
                
                if not base_words:
                    print("[!] No base words provided. Using default words.")
                    base_words = ["password", "admin", "user", "login"]
                
                print("\n[*] Select transformations:")
                print("1. Case variations (password, Password, PASSWORD)")
                print("2. Add numbers (password1, password123)")
                print("3. Replace letters with numbers (p4ssw0rd)")
                print("4. Add special characters (password!, password@)")
                print("5. All of the above")
                
                transforms = input("Enter transformation numbers (e.g., 124): ")
                
                do_case = "1" in transforms or "5" in transforms
                do_numbers = "2" in transforms or "5" in transforms
                do_leet = "3" in transforms or "5" in transforms
                do_special = "4" in transforms or "5" in transforms
                
                # Leet speak replacements
                leet_map = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1"}
                
                passwords = set()
                
                print(f"\n[*] Generating variations for {len(base_words)} base words...")
                
                for word in base_words:
                    variations = [word]
                    
                    if do_case:
                        variations.extend([
                            word.upper(),
                            word.capitalize(),
                            word.title(),
                        ])
                    
                    if do_leet:
                        leet_word = word
                        for letter, replacement in leet_map.items():
                            leet_word = leet_word.replace(letter, replacement)
                        variations.append(leet_word)
                    
                    expanded_variations = list(variations)  # Copy to avoid modification during iteration
                    
                    if do_numbers:
                        for var in variations:
                            expanded_variations.extend([
                                var + "1",
                                var + "123",
                                var + "2023",
                                var + "12345"
                            ])
                    
                    if do_special:
                        for var in variations:
                            expanded_variations.extend([
                                var + "!",
                                var + "@",
                                var + "#",
                                var + "$"
                            ])
                    
                    passwords.update(expanded_variations)
                
                with open(output_file, "w") as f:
                    for password in passwords:
                        f.write(password + "\n")
                
                print(f"[+] Generated {len(passwords)} variations and saved to {output_file}")
            
            elif method == 3:
                # Pattern-based
                patterns = []
                print("\n[*] Pattern symbols:")
                print("  %L - Uppercase letter")
                print("  %l - Lowercase letter")
                print("  %d - Digit")
                print("  %s - Special character")
                print("  Any other characters will be used as-is")
                print("Example: %L%l%l%l%d%d = Abcd12")
                
                num_patterns = int(input("\nHow many patterns to create? [1]: ") or "1")
                
                for i in range(num_patterns):
                    pattern = input(f"Enter pattern {i+1}: ")
                    if pattern:
                        patterns.append(pattern)
                
                if not patterns:
                    print("[!] No valid patterns provided. Using default patterns.")
                    patterns = ["%L%l%l%l%d%d", "%l%l%l%l%d%d%d", "%L%l%l%l%s%d"]
                
                # Define character sets for patterns
                uppercase = string.ascii_uppercase
                lowercase = string.ascii_lowercase
                digits = string.digits
                special = "!@#$%^&*"
                
                count = 0
                max_passwords = 100000  # Limit to prevent massive files
                
                print(f"\n[*] Generating passwords based on {len(patterns)} patterns.")
                print(f"[*] This may take some time. Limited to {max_passwords} passwords.")
                
                with open(output_file, "w") as f:
                    for pattern in patterns:
                        # Calculate possible combinations (limit to reasonable numbers)
                        expansions = []
                        for char in pattern:
                            if char == '%':
                                continue
                            elif char == 'L':
                                expansions.append(uppercase)
                            elif char == 'l':
                                expansions.append(lowercase)
                            elif char == 'd':
                                expansions.append(digits)
                            elif char == 's':
                                expansions.append(special)
                            else:
                                expansions.append([char])
                        
                        # Skip patterns that would generate too many combinations
                        total_combinations = 1
                        for exp in expansions:
                            total_combinations *= len(exp)
                        
                        if total_combinations > max_passwords:
                            print(f"[!] Pattern '{pattern}' would generate too many combinations. Skipping.")
                            continue
                        
                        # Generate passwords based on pattern
                        i = 0
                        for combo in itertools.product(*expansions):
                            f.write("".join(combo) + "\n")
                            count += 1
                            i += 1
                            
                            if i % 10000 == 0:
                                print(f"\r[*] Generated {count} passwords...", end="")
                            
                            if count >= max_passwords:
                                break
                        
                        if count >= max_passwords:
                            break
                
                print(f"\n[+] Generated {count} passwords and saved to {output_file}")
            
            else:
                print("[!] Invalid method selected.")
        
        except Exception as e:
            print(f"[!] Error: {e}")
        
        input("\nPress Enter to continue...")
        self.dictionary_attack_menu()
    
    def password_strength_analyzer(self):
        """Analyze password strength"""
        self.clear_screen()
        print("[+] Password Strength Analyzer")
        
        password = getpass("Enter a password to analyze: ")
        
        if not password:
            print("[!] No password provided.")
            input("\nPress Enter to continue...")
            self.dictionary_attack_menu()
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
        
        # Recommendations
        print("\nRecommendations:")
        if length < 12:
            print("  - Increase password length to at least 12 characters")
        if not has_uppercase:
            print("  - Add uppercase letters")
        if not has_lowercase:
            print("  - Add lowercase letters")
        if not has_digits:
            print("  - Add numbers")
        if not has_special:
            print("  - Add special characters")
        if weaknesses:
            print("  - Avoid common words and patterns")
        
        input("\nPress Enter to continue...")
        self.dictionary_attack_menu()
    
    def custom_wordlist_creator(self):
        """Create custom wordlists for password cracking"""
        self.clear_screen()
        print("[+] Custom Wordlist Creator")
        
        output_file = input("Enter output filename [custom_wordlist.txt]: ") or "custom_wordlist.txt"
        
        print("\n[*] Wordlist creation methods:")
        print("1. Combine personal information")
        print("2. Extend existing wordlist")
        print("3. Generate from keywords")
        
        method = input("\nSelect method [1]: ") or "1"
        
        try:
            method = int(method)
            
            if method == 1:
                # Combine personal information
                print("\n[*] Enter information about the target (leave blank if unknown):")
                
                firstname = input("First name: ")
                lastname = input("Last name: ")
                nickname = input("Nickname: ")
                birthdate = input("Birth date (DDMMYYYY): ")
                
                print("\nOther significant information:")
                spouse = input("Spouse/Partner name: ")
                children = input("Children names (comma separated): ").split(",")
                children = [name.strip() for name in children if name.strip()]
                
                pets = input("Pet names (comma separated): ").split(",")
                pets = [name.strip() for name in pets if name.strip()]
                
                keywords = input("Other keywords (comma separated): ").split(",")
                keywords = [word.strip() for word in keywords if word.strip()]
                
                # Gather all info
                all_words = []
                if firstname:
                    all_words.append(firstname)
                    all_words.append(firstname.lower())
                    all_words.append(firstname.capitalize())
                
                if lastname:
                    all_words.append(lastname)
                    all_words.append(lastname.lower())
                    all_words.append(lastname.capitalize())
                
                if firstname and lastname:
                    all_words.append(firstname + lastname)
                    all_words.append(firstname.lower() + lastname.lower())
                    all_words.append(firstname[0] + lastname)
                    all_words.append(firstname[0].lower() + lastname.lower())
                
                if nickname:
                    all_words.append(nickname)
                    all_words.append(nickname.lower())
                
                if birthdate:
                    all_words.append(birthdate)
                    if len(birthdate) >= 8:
                        all_words.append(birthdate[-4:])  # Year
                        all_words.append(birthdate[-2:])  # Last 2 digits of year
                        all_words.append(birthdate[:2])   # Day
                        all_words.append(birthdate[2:4])  # Month
                
                all_words.extend([spouse, *children, *pets, *keywords])
                all_words = [word for word in all_words if word]  # Remove empty strings
                
                # Generate combinations and variations
                variations = set(all_words)
                
                # Add common separators and suffixes
                for word in all_words:
                    # Add numbers
                    variations.add(word + "1")
                    variations.add(word + "123")
                    variations.add(word + "12345")
                    
                    if birthdate:
                        variations.add(word + birthdate[-4:])  # Year
                        variations.add(word + birthdate[-2:])  # Last 2 digits of year
                    
                    # Add special chars
                    variations.add(word + "!")
                    variations.add(word + "@")
                    variations.add(word + "#")
                    
                    # Common patterns
                    variations.add(word.capitalize() + "123")
                    if len(word) >= 2:
                        variations.add(word[0].upper() + word[1:] + "!")
                
                # Combine two words
                for i in range(len(all_words)):
                    for j in range(i+1, len(all_words)):
                        if all_words[i] and all_words[j]:
                            variations.add(all_words[i] + all_words[j])
                            variations.add(all_words[i].capitalize() + all_words[j])
                            variations.add(all_words[i] + all_words[j].capitalize())
                
                # Write to file
                with open(output_file, "w") as f:
                    for password in sorted(variations):
                        f.write(password + "\n")
                
                print(f"\n[+] Generated {len(variations)} passwords based on personal information.")
                print(f"[+] Saved to {output_file}")
            
            elif method == 2:
                # Extend existing wordlist
                existing_file = input("Enter path to existing wordlist: ")
                
                if not os.path.exists(existing_file):
                    print(f"[!] File not found: {existing_file}")
                    input("\nPress Enter to continue...")
                    self.dictionary_attack_menu()
                    return
                
                print("\n[*] Select transformation methods:")
                print("1. Add common prefixes/suffixes")
                print("2. Replace letters with numbers (l33t speak)")
                print("3. Toggle case variations")
                print("4. All of the above")
                
                transform_choice = input("Select option [4]: ") or "4"
                
                do_affix = "1" in transform_choice or "4" in transform_choice
                do_leet = "2" in transform_choice or "4" in transform_choice
                do_case = "3" in transform_choice or "4" in transform_choice
                
                # Read existing wordlist
                base_words = set()
                try:
                    with open(existing_file, "r", errors="ignore") as f:
                        for line in f:
                            word = line.strip()
                            if word:
                                base_words.add(word)
                except Exception as e:
                    print(f"[!] Error reading file: {e}")
                    input("\nPress Enter to continue...")
                    self.dictionary_attack_menu()
                    return
                
                print(f"[*] Read {len(base_words)} words from existing wordlist.")
                
                # Set up transformations
                variations = set(base_words)
                
                # Common prefixes and suffixes
                prefixes = ["", "The", "My", "A"]
                suffixes = ["1", "123", "2023", "!", "@", "#", "?"]
                
                # Leet speak replacements
                leet_map = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
                
                # Apply transformations
                print("[*] Applying transformations...")
                count = 0
                
                for word in base_words:
                    # Skip very short words
                    if len(word) < 3:
                        continue
                    
                    # Add prefixes and suffixes
                    if do_affix:
                        for prefix in prefixes:
                            for suffix in suffixes:
                                if prefix or suffix:  # Don't add empty prefix+suffix
                                    new_word = prefix + word + suffix
                                    variations.add(new_word)
                                    count += 1
                    
                    # Leet speak
                    if do_leet:
                        leet_word = word
                        for char, replacement in leet_map.items():
                            leet_word = leet_word.replace(char, replacement)
                        
                        if leet_word != word:
                            variations.add(leet_word)
                            count += 1
                    
                    # Case variations
                    if do_case and not word.isupper() and not word.islower():
                        variations.add(word.lower())
                        variations.add(word.upper())
                        variations.add(word.capitalize())
                        count += 3
                
                # Write to file
                with open(output_file, "w") as f:
                    for password in sorted(variations):
                        f.write(password + "\n")
                
                print(f"\n[+] Added {count} variations to original {len(base_words)} words.")
                print(f"[+] Total unique passwords: {len(variations)}")
                print(f"[+] Saved to {output_file}")
            
            elif method == 3:
                # Generate from keywords
                keywords = input("Enter keywords (comma separated): ").split(",")
                keywords = [word.strip() for word in keywords if word.strip()]
                
                if not keywords:
                    print("[!] No keywords provided.")
                    input("\nPress Enter to continue...")
                    self.dictionary_attack_menu()
                    return
                
                print(f"[*] Generating wordlist from {len(keywords)} keywords...")
                
                # Generate variations
                variations = set(keywords)
                
                # Add common variations
                for word in keywords:
                    # Case variations
                    variations.add(word.lower())
                    variations.add(word.upper())
                    variations.add(word.capitalize())
                    
                    # Add numbers
                    for num in ["1", "123", "2023", "12345"]:
                        variations.add(word + num)
                        variations.add(word.capitalize() + num)
                    
                    # Add special chars
                    for char in ["!", "@", "#", "$"]:
                        variations.add(word + char)
                        variations.add(word.capitalize() + char)
                    
                    # Leet speak
                    leet_word = word.lower()
                    leet_word = leet_word.replace("a", "4")
                    leet_word = leet_word.replace("e", "3")
                    leet_word = leet_word.replace("i", "1")
                    leet_word = leet_word.replace("o", "0")
                    leet_word = leet_word.replace("s", "5")
                    variations.add(leet_word)
                
                # Combine keywords
                for i in range(len(keywords)):
                    for j in range(len(keywords)):
                        if i != j:
                            variations.add(keywords[i] + keywords[j])
                
                # Write to file
                with open(output_file, "w") as f:
                    for password in sorted(variations):
                        f.write(password + "\n")
                
                print(f"\n[+] Generated {len(variations)} passwords from keywords.")
                print(f"[+] Saved to {output_file}")
            
            else:
                print("[!] Invalid method selected.")
        
        except Exception as e:
            print(f"[!] Error: {e}")
        
        input("\nPress Enter to continue...")
        self.dictionary_attack_menu()

# Main function
def run_password_tools():
    """Run the password tools module"""
    tools = PasswordTools()
    tools.dictionary_attack_menu()

if __name__ == "__main__":
    run_password_tools() 