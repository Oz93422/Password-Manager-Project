import json
import os
import random
import string
import hashlib
import argparse

# Incooperating Parser for command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="CAD Password Manager")
    parser.add_argument(
        '-a', '--action',
        choices=['register', 'get-encrypted', 'get-decrypted', 'view-sites', 'view-attempts', 'clear', 'exit'],
        help='Action to perform: register, get-encrypted, get-decrypted, view-sites, view-attempts, clear, exit',
        required=False,
        default='view-sites'  
    )
    parser.add_argument('-s', '--site', help='Site URL')
    parser.add_argument('-u', '--username', help='Username or Email for the site')
    parser.add_argument('-p', '--password', help='Password for the site')
    return parser.parse_args()



# Hash Admin Password
def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()
stored_hash = hash_password("h*90weOBq.2i")

class Password_Manager_Project:
    
    
    # Login User
    def login_user():
        print("Login to the CAD Password Manager")
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        if username == "admin" and hash_password(password) == stored_hash:
            print("Login successful!")
            return True
        else:
            print("Invalid username or password.")
            return False
        
    # Checks if site already registered
    
    def if_site_already_registered(site_url):
        try:
            with open("info.json", "r") as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return False  

        for site in data.get("sites", []):
            if site['site'] == site_url:
                print(f"Site {site['site']} is already registered.")
                overwrite = input("Do you want to overwrite the existing site information? (yes/no): ")
                if overwrite.lower() in ["yes", "y"]:
                    return False  
                else:
                    return True   
        return False 
            
    # Check Strength of Password
    def strong_password(password):
        if len(password) < 8:
            print("Password should be at least 8 characters long.")
            return False
        if not any(char.islower() for char in password):
            print("Password should contain at least one lowercase letter.")
            return False
        if not any(char.isupper() for char in password):
            print("Password should contain at least one uppercase letter.")
            return False
        if not any(char.isdigit() for char in password):
            print("Password should contain at least one digit.")
            return False
        if not any(char in '!@#$%^&*()' for char in password):
            print("Password should contain at least one special character.")
            return False
        print("Strong password!")
        return True

    # Checks if json file for passwords exists and if not, creates one
    def log_password_info(filename):
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            try:
                with open(filename, "r") as file:
                    data = json.load(file)
                    return data
            except:
                print("Warning: Couldn't read the log file. Making a new one.")
        return {"strong_attempts": [], "weak_attempts": []}

    # Logs password attempt
    def log_password_attempt(password, strong_password_flag):
        filename = "password.json"
        print(f"Logging password attempt...")
        data = Password_Manager_Project.log_password_info(filename)

        attempt = {
            "password": password,
            "strong_password": strong_password_flag
        }

        if strong_password_flag:
            data["strong_attempts"].append(attempt)
            print("Password logged into strong attempts.")
        else:
            data["weak_attempts"].append(attempt)
            print("Password logged into weak attempts.")

        with open(filename, "w") as file:
            json.dump(data, file, indent=5)

    # Password Encryption
    def encrypt_password(password):
        chars = " " + string.punctuation + string.digits + string.ascii_letters
        chars = list(chars)
        key = chars.copy()
        random.shuffle(key)

        ciphertext = ""
        for letter in password:
            index = chars.index(letter)
            ciphertext += key[index]

        print(f"Original Password: {password}")
        print(f"Encrypted Password: {ciphertext}")
        return ciphertext, key
    
    # Password Decryption
    def decrypt_password(ciphertext, chars, key):
        plaintext = ""
        for letter in ciphertext:
            index = key.index(letter)
            plaintext += chars[index]

        
        return plaintext

    
   
    
    # Checks if json file for sites exists and if not, creates one
    def log_site_info(filename):
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            try:
                with open(filename, "r") as file:
                    data = json.load(file)
                    return data
            except:
                    print("Warning: Couldn't read the log file. Making a new one.")
                    return {"sites": []}
        return {"sites": []}
            
    
    # Logs new site info
    def log_sites(site_url, username, password_data):
        filename = "info.json"
        encrypted_password, key = password_data
        print(f"Logging site info for {site_url}...")
        data = Password_Manager_Project.log_site_info(filename)

        site_info = {
            "site": site_url,
            "username": username,
            "password": encrypted_password,
            "key": key  
        }

        data["sites"].append(site_info)

        with open(filename, "w") as file:
            json.dump(data, file, indent=5)

        print("New site registered successfully.")

        

# Main Program
def main(args):
    if not Password_Manager_Project.login_user():
        return

    while True:
        print("\nChoose an action:")
        print("  register, get-encrypted, get-decrypted, view-sites, view-attempts, clear, exit")
        action = input("Action: ").strip().lower()

        if action == 'register':
            site = input("Site URL: ")
            username = input("Username or Email: ")
            password = input("Password: ")

            if Password_Manager_Project.if_site_already_registered(site):
                continue

            encrypted_password = Password_Manager_Project.encrypt_password(password)

            if not Password_Manager_Project.strong_password(password):
                choice = input("Password is weak. Register anyway? (yes/no): ").lower()
                if choice not in ['yes', 'y']:
                    Password_Manager_Project.log_password_attempt(password, False)
                    continue

            Password_Manager_Project.log_sites(site, username, encrypted_password)
            Password_Manager_Project.log_password_attempt(password, True)

        elif action == 'get-encrypted':
            site = input("Site URL: ")
            data = Password_Manager_Project.log_site_info("info.json")
            for s in data.get("sites", []):
                if s['site'] == site:
                    print(f"Encrypted Password: {s['password']}")
                    break
            else:
                print("Site not found.")

        elif action == 'get-decrypted':
            site = input("Site URL: ")
            data = Password_Manager_Project.log_site_info("info.json")
            for s in data.get("sites", []):
                if s['site'] == site:
                    chars = list(" " + string.punctuation + string.digits + string.ascii_letters)
                    decrypted = Password_Manager_Project.decrypt_password(s['password'], chars, s['key'])
                    print(f"Decrypted Password: {decrypted}")
                    break
            else:
                print("Site not found.")

        elif action == 'view-sites':
            data = Password_Manager_Project.log_site_info("info.json")
            if data["sites"]:
                print("Registered Sites:")
                for s in data["sites"]:
                    print(f"- {s['site']}")
            else:
                print("No sites registered.")

        elif action == 'view-attempts':
            data = Password_Manager_Project.log_password_info("password.json")
            print("Password Attempts Log:")
            print(json.dumps(data, indent=4))

        elif action == 'clear':
            confirm = input("Are you sure you want to clear all logs? (yes/no): ").lower()
            if confirm in ['yes', 'y']:
                if os.path.exists("info.json"):
                    os.remove("info.json")
                if os.path.exists("password.json"):
                    os.remove("password.json")
                print("Logs cleared.")
            else:
                print("Canceled.")

        elif action == 'exit':
            print("Goodbye.")
            break

        else:
            print("Invalid action. Try again.")

if __name__ == "__main__":
    args = parse_args()
    main(args)
