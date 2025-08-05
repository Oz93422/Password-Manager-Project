import json
import os
import random
import string


class Password_Manager_Project:
    
    # Login User
    def login_user():
        print("Login to the CAD Password Manager")
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        if username == "admin" and password == "h":
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
    def main():
        if not Password_Manager_Project.login_user():
            return

        while True:
            print("\nChoose an option:")
            print("1. Register a new site")                
            print("2. Retrieve password for a site (encrypted)")
            print("3. Retrieve password for a site (decrypted)")
            print("4. View all registered sites")
            print("5. View password attempts")
            print("6. Clear all password attempts and clear logs")
            print("7. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                site_url = input("Enter the site URL: ")
                username = input("Enter the username or email: ")
                password = input("Enter the password: ")

                if Password_Manager_Project.if_site_already_registered(site_url):
                    continue

                encrypted_password = Password_Manager_Project.encrypt_password(password)

                if not Password_Manager_Project.strong_password(password):
                    confirm = input("Password is not strong. Would you still like to register it? (yes/no): ")
                    if confirm.lower() not in ["yes", "y"]:
                        print("New site registration canceled.")
                        continue
                    else:
                        Password_Manager_Project.log_password_attempt(password, False)
                else:
                    Password_Manager_Project.log_password_attempt(password, True)

                Password_Manager_Project.log_sites(site_url, username, encrypted_password)

            elif choice == "2":
                site_url = input("Enter the site URL: ")
                info = Password_Manager_Project.log_site_info("info.json")
                found = False
                for site in info.get("sites", []):
                    if site["site"] == site_url:
                        print(f"\nSite: {site['site']}")
                        print(f"Username: {site['username']}")
                        print(f"Encrypted Password: {site['password']}")
                        found = True
                        break
                if not found:
                    print("Site not found in the registry.")

            elif choice == "3":
                site_url = input("Enter the site URL: ")
                info = Password_Manager_Project.log_site_info("info.json")
                found = False
                for site in info.get("sites", []):
                    if site["site"] == site_url:
                        print(f"\nSite: {site['site']}")
                        print(f"Username: {site['username']}")
                        if "key" not in site:
                            print("This site's password was stored before encryption keys were added and cannot be decrypted.")
                            found = True
                            break
                        key = site["key"]
                        chars = " " + string.punctuation + string.digits + string.ascii_letters
                        chars = list(chars)
                        decrypted = Password_Manager_Project.decrypt_password(site['password'], chars, key)
                        print(f"Decrypted Password: {decrypted}")
                        found = True
                        break
                if not found:
                    print("Site not found in the registry.")



            elif choice == "4":
                sites = Password_Manager_Project.log_site_info("info.json")
                print("\nRegistered Sites:")
                for site in sites.get("sites", []):
                    print(f"- {site['site']}")
                if len(sites["sites"]) == 0:
                    print("No sites registered.")

            elif choice == "5":
                attempts = Password_Manager_Project.log_password_info("password.json")
                print("\nPassword Attempts Log:")
                print(json.dumps(attempts, indent=4))
                if len(attempts["strong_attempts"]) == 0 and len(attempts["weak_attempts"]) == 0:
                    print("No password attempts recorded.")

            elif choice == "6":
                confirm = input("Are you sure you want to clear all password attempts and logs? (yes/no): ")
                if confirm.lower() in ["yes", "y"]:
                    if os.path.exists("password.json"):
                        os.remove("password.json")
                        print("Password attempts cleared successfully.")
                    if os.path.exists("info.json"):
                        os.remove("info.json")
                        print("Site registry cleared successfully.")
                    print("All logs and data cleared.")

            elif choice == "7":
                print("Exiting the program...")
                break

            else:
                print("Invalid choice. Please enter a number from 1 to 7.")


if __name__ == "__main__":
    Password_Manager_Project.main()
