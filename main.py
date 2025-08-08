import hashlib
import sys
import sqlite3
import os
from cryptography.fernet import Fernet


# Generate a key for encryption and decryption.
def key():
    key_file = "secret.key"
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key


Secret_key = key()
cipher_suite = Fernet(Secret_key)


#Hash a password using SHA-256.(security)
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
stored_hash = hash_password("h*90weOBq.2i")


class Password_Manager_Project:
    conn = None
    cursor = None

    # Create a SQL database
    def create_database():
        Password_Manager_Project.conn = sqlite3.connect('password_manager.db')
        Password_Manager_Project.cursor = Password_Manager_Project.conn.cursor()
        Password_Manager_Project.cursor.execute('''
            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        Password_Manager_Project.cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password TEXT NOT NULL,
                strong_password INTEGER NOT NULL
            )
        ''')
        Password_Manager_Project.conn.commit()

    #close the SQL database
    def close_database():
        if Password_Manager_Project.conn:
            Password_Manager_Project.conn.close()

    #users login to the Password Manager
    def login_user():
        #username = admin password = h*90weOBq.2i
        print("Login to the CAD Password Manager")
        max_attempts = 3
        attempts = 0
        while attempts < max_attempts:
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            if username == "admin" and hash_password(password) == stored_hash:
                print("Login successful!")
                return True
            else:
                attempts += 1
                if attempts < max_attempts:
                    print(f"Invalid credentials. You have {max_attempts - attempts} attempt(s) left.\n")
                else:
                    print("Maximum login attempts reached. Exiting...")
        return False

    #checks if a site is already registered in the database
    def if_site_already_registered(site_url):
        Password_Manager_Project.cursor.execute('SELECT site FROM sites WHERE site = ?', (site_url,))
        result = Password_Manager_Project.cursor.fetchone()
        if result:
            print(f"Site '{site_url}' is already registered.")
            overwrite = input("Do you want to overwrite the existing site information? (yes/no): ").strip().lower()
            while overwrite not in ["yes", "y", "no", "n"]:
                overwrite = input("Please answer 'yes' or 'no': ").strip().lower()
            if overwrite in ["yes", "y"]:
                print("Overwriting site info.")
                return False
            else:
                print("Not overwriting site info. Registration cancelled.")
                return True
        return False

    #detects if a password is strong or weak
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

    #encryption for password
    def encrypt_password(password):
        encrypted = cipher_suite.encrypt(password.encode())
        return encrypted

    #decryption for password
    def decrypt_password(encrypted_password):
        try:
            decrypted = cipher_suite.decrypt(encrypted_password.encode()).decode()
            return decrypted
        except Exception:
            return None

    #adds new sites to the SQL database
    def log_sites(site_url, username, encrypted_password):
        try:
            Password_Manager_Project.cursor.execute('''
                INSERT INTO sites (site, username, password) VALUES (?, ?, ?)
                ON CONFLICT(site) DO UPDATE SET
                    username=excluded.username,
                    password=excluded.password
            ''', (site_url, username, encrypted_password.decode()))
            Password_Manager_Project.conn.commit()
            print("Site info saved successfully.")
        except Exception as e:
            print(f"Error saving site info: {e}")

    # logs password attempts to the SQL database
    def log_password_attempt(password, strong_password_flag):
        try:
            Password_Manager_Project.cursor.execute('''
                INSERT INTO password_attempts (password, strong_password) VALUES (?, ?)
            ''', (password, int(strong_password_flag)))
            Password_Manager_Project.conn.commit()
            print("Password attempt logged.")
        except Exception as e:
            print(f"Error logging password attempt: {e}")

    #returns the encrypted password for a given site
    def get_encrypted_password(site_url):
        Password_Manager_Project.cursor.execute('SELECT password FROM sites WHERE site = ?', (site_url,))
        result = Password_Manager_Project.cursor.fetchone()
        return result[0] if result else None

    #returns the decrypted password for a given site
    def get_decrypted_password(site_url):
        encrypted = Password_Manager_Project.get_encrypted_password(site_url)
        if encrypted:
            return Password_Manager_Project.decrypt_password(encrypted)
        else:
            return None

    #lists all registered sites
    def list_registered_sites():
        Password_Manager_Project.cursor.execute('SELECT site FROM sites')
        rows = Password_Manager_Project.cursor.fetchall()
        if rows:
            print("Registered Sites:")
            for row in rows:
                print(f"- {row[0]}")
        else:
            print("No sites registered.")

    #lists all password attempts and declears them as weak or strong
    def list_password_attempts():
        Password_Manager_Project.cursor.execute('SELECT password, strong_password FROM password_attempts')
        rows = Password_Manager_Project.cursor.fetchall()
        if rows:
            print("Password Attempts Log:")
            for password, strong_flag in rows:
                strength = "Strong" if strong_flag else "Weak"
                print(f"- Password: {password} | Strength: {strength}")
        else:
            print("No password attempts logged.")


#main function 
def main():
    Password_Manager_Project.create_database()
    if not Password_Manager_Project.login_user():
        Password_Manager_Project.close_database()
        return
    while True:
        print("\nChoose an action:")
        print("register or r - Register new site")
        print("encrypted or e - Get encrypted password")
        print("decrypted or d - Get decrypted password")
        print("view register or vr - View registered sites")
        print("view passwords or vp - View password attempts")
        print("clear or c - Clear all logs")
        print("exit or x - Exit")
        choice = input("Enter choice: ").strip().lower()
        
        if choice in ['register', 'r']:
            site = input("Enter site name: ").strip()
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            if Password_Manager_Project.if_site_already_registered(site):
                continue
            if not Password_Manager_Project.strong_password(password):
                print("This password is not strong would you still like to use it? (yes/no): ")
                choice = input("Enter choice: ")
                if choice not in ['yes', 'y', 'Yes', 'Y', 'YES']:
                    print("Registration cancelled.")
                    continue
            encrypted_password = Password_Manager_Project.encrypt_password(password)
            Password_Manager_Project.log_sites(site, username, encrypted_password)
            Password_Manager_Project.log_password_attempt(password, Password_Manager_Project.strong_password(password))
            print("Registration successful!")
       
        elif choice in ['encrypted', 'e']:
            site = input("Enter site name: ").strip()
            encrypted = Password_Manager_Project.get_encrypted_password(site)
            if encrypted:
                print(f"Encrypted Password: {encrypted}")
            else:
                print("Site not found.")
       
        elif choice in ['decrypted', 'd']:
            site = input("Enter site name: ").strip()
            decrypted = Password_Manager_Project.get_decrypted_password(site)
            if decrypted:
                print(f"Decrypted Password: {decrypted}")
            else:
                print("Site not found.")
       
        elif choice in ['view register', 'vr']:
            Password_Manager_Project.list_registered_sites()
       
        elif choice in ['view passwords', 'vp']:
            Password_Manager_Project.list_password_attempts()
       
        elif choice in ['clear', 'c']:
            Password_Manager_Project.cursor.execute('DELETE FROM sites')
            Password_Manager_Project.cursor.execute('DELETE FROM password_attempts')
            Password_Manager_Project.conn.commit()
            print("Logs cleared.")
        
        elif choice in ['exit', 'x']:
            print("Exiting program...")
            Password_Manager_Project.close_database()
            sys.exit(0)
       
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
