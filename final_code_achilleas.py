import json
import re
import random
import string

# Caesar cipher encryption function (educational purpose only)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower() and shifted > ord('z'):
                shifted -= 26
            elif char.isupper() and shifted > ord('Z'):
                shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

# Caesar cipher decryption function
def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function
def is_strong_password(password):
    """
    Check if the password is strong.

    A strong password must have at least:
    - 8 characters
    - 1 uppercase letter
    - 1 lowercase letter
    - 1 digit
    - 1 special character

    Args:
        password (str): The password to check.

    Returns:
        bool: True if the password is strong, False otherwise.
    """
    return (len(password) >= 8 and
            any(char.isupper() for char in password) and
            any(char.islower() for char in password) and
            any(char.isdigit() for char in password) and
            any(char in string.punctuation for char in password))

# Password generator function
def generate_password(length):
    """
    Generate a random strong password of the specified length.

    Args:
        length (int): The desired length of the password.

    Returns:
        str: A random strong password.
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")
    
    all_chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(all_chars) for _ in range(length))

    while not is_strong_password(password):
        password = ''.join(random.choice(all_chars) for _ in range(length))

    return password

# Initialize password storage lists
encrypted_passwords = []
websites = []
usernames = []

# Function to add a new password
def add_password():
    """
    Add a new password to the password manager.

    This function prompts the user for the website, username, and password,
    and stores them in respective lists. Optionally, it checks password
    strength or generates a random strong password.
    """
    website = input("Enter the website: ")
    username = input("Enter the username: ")
    
    choice = input("Do you want to generate a random strong password? (yes/no): ").strip().lower()
    if choice == "yes":
        try:
            length = int(input("Enter the desired password length (minimum 8): "))
            password = generate_password(length)
            print(f"Generated password: {password}")
        except ValueError:
            print("Invalid input! Please enter a number.")
            return
    else:
        password = input("Enter the password: ")
        if not is_strong_password(password):
            print("Warning: The password is not strong.")

    encrypted_password = caesar_encrypt(password, 3)
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted_password)
    print("Password added successfully!")

# Function to retrieve a password
def get_password():
    """
    Retrieve a password for a given website.

    This function prompts the user for the website name and
    displays the username and decrypted password for that website.
    """
    website = input("Enter the website: ")
    if website in websites:
        index = websites.index(website)
        username = usernames[index]
        decrypted_password = caesar_decrypt(encrypted_passwords[index], 3)
        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
    else:
        print("Website not found.")

# Function to save passwords to a JSON file
def save_passwords():
    """
    Save the password vault to a file.

    This function saves passwords, websites, and usernames to a JSON file
    named "vault.json" in a structured format.
    """
    data = {
        "websites": websites,
        "usernames": usernames,
        "encrypted_passwords": encrypted_passwords
    }
    with open("vault.json", "w") as file:
        json.dump(data, file)
    print("Passwords saved successfully!")

# Function to load passwords from a JSON file
def load_passwords():
    """
    Load passwords from a file into the password vault.

    This function loads passwords, websites, and usernames from a JSON file
    named "vault.json" and populates the respective lists.
    """
    global websites, usernames, encrypted_passwords
    try:
        with open("vault.json", "r") as file:
            data = json.load(file)
            websites = data["websites"]
            usernames = data["usernames"]
            encrypted_passwords = data["encrypted_passwords"]
        print("Passwords loaded successfully!")
    except FileNotFoundError:
        print("No saved passwords found.")

# Main method for user interface
def main():
    """
    Implement the user interface for the password manager.
    """
    while True:
        print("\nPassword Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Load Passwords")
        print("5. Quit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()

