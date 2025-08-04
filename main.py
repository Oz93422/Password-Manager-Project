import json
import os
import random
import string


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


# Password Logging
def load_log_file(filename):
   if os.path.exists(filename) and os.path.getsize(filename) > 0:
       try:
           with open(filename, "r") as file:
               data = json.load(file)
           return data
       except:
           print("Warning: Couldn't read the log file. Making a new one.")
   return {"strong_attempts": [], "weak_attempts": []}


def log_password_attempt(password, strong_password_flag):
   filename = "password.json"
   print(f"Logging password attempt...")
   data = load_log_file(filename)
  
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
  
   print("\n Current Log File:")
   print(json.dumps(data, indent=5))


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
   return ciphertext


# Store Info
def info_json():
   try:
       with open("info.json", "r") as file:
           data = json.load(file)
           return data
   except (FileNotFoundError, json.JSONDecodeError):
       return {"sites": []}


def info_for_site(encrypted_password):
   site = input("Enter the site name: ")
   username = input("Enter the username or email: ")
   return {
       "site": site,
       "username": username,
       "password": encrypted_password
   }


def save_info(info):
   with open("info.json", "w") as file:
       json.dump(info, file, indent=4)
       print("Info saved successfully!")




# Main Program
print("Welcome to the Password Manager")
while True:
   password = input("Please enter a password: ")


   if strong_password(password):
       log_password_attempt(password, True)
       encrypted = encrypt_password(password)
       info = info_json()
       site_info = info_for_site(encrypted)
       info["sites"].append(site_info)
       save_info(info)
       print(json.dumps(info, indent=4))
   else:
       log_password_attempt(password, False)


   again = input("Would you like to input another password? (yes/no) ").lower()
   if again not in ["yes", "y"]:
       print("Thanks for using the Password Manager!")
       break