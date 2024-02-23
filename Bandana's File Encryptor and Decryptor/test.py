import os
import json
import datetime
import getpass
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Function to derive a cryptographic key from a user-provided password
def derive_key(user_key):
    # Using a static salt for simplicity; in real applications, a unique salt should be used
    salt = b'\x00'*16  
    # Key derivation function setup with SHA256, a key length of 32 bytes, and 100,000 iterations
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    # Deriving the key from the user-provided password
    return kdf.derive(user_key.encode())

# Function to encrypt a file
def encrypt_file(file_path, key, user_name):
    # Deriving the key from the user-provided password
    derived_key = derive_key(key)
    # Generating a random Initialization Vector (IV) for encryption
    iv = os.urandom(16)
    # Setting up the AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Creating a folder to store encrypted files
    encrypted_folder = 'encrypted_data'
    os.makedirs(encrypted_folder, exist_ok=True)
    # Constructing the path for the encrypted file
    encrypted_file_path = os.path.join(encrypted_folder, f"{user_name}_{os.path.basename(file_path)}.enc")

    # Reading the original file content
    with open(file_path, 'rb') as file:
        original = file.read()

    # Padding the data to fit the block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(original) + padder.finalize()
    # Encrypting the data
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Writing the IV followed by the encrypted data to the output file
    with open(encrypted_file_path, 'wb') as file:
        file.write(iv + encrypted)

    # Updating the database with the encryption information
    update_database(user_name, file_path, encrypted_file_path, "encrypt")

# Function to decrypt a file
def decrypt_file(file_path, key, user_name):
    # Deriving the key from the user-provided password
    derived_key = derive_key(key)

    # Reading the IV and encrypted data from the file
    with open(file_path, 'rb') as file:
        iv = file.read(16)
        encrypted = file.read()

    # Setting up the AES cipher in CBC mode for decryption
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Decrypting the data
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

    # Removing padding from the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    # Creating a folder to store decrypted files
    decrypted_folder = 'decrypted_data'
    os.makedirs(decrypted_folder, exist_ok=True)
    # Constructing the path for the decrypted file
    decrypted_file_path = os.path.join(decrypted_folder, f"{user_name}_{os.path.basename(file_path).replace('.enc', '')}")

    # Writing the decrypted data to the output file
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted)

    # Updating the database with the decryption information
    update_database(user_name, file_path, decrypted_file_path, "decrypt")

    # Return the path to the decrypted file
    return decrypted_file_path

# Function to update a JSON database with file processing information
def update_database(user_name, original_path, new_path, action):
    db_path = 'file_data.json'
    # Load existing data if the database file exists
    if os.path.exists(db_path):
        with open(db_path, 'r') as file:
            data = json.load(file)
    else:
        data = {}

    # Initialize the user's data structure if not present
    if user_name not in data:
        data[user_name] = {"encrypt": [], "decrypt": []}

    # Creating an entry with the file paths and timestamp
    entry = {
        "original": original_path,
        "processed": new_path,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Adding the entry to the appropriate action list
    data[user_name][action].append(entry)
    
    # Writing the updated data back to the database file
    with open(db_path, 'w') as file:
        json.dump(data, file, indent=4)

# Main program entry point
def main():
    # User input to choose between encryption and decryption
    choice = input("Do you want to encrypt (e) or decrypt (d) a file? (e/d): ")
    if choice.lower() == "e":
        # Collecting necessary information for encryption
        user_name = input("Enter your username: ")
        key = getpass.getpass("Enter the encryption key (hidden): ")
        file_path = input("Enter the path of the file to encrypt: ").strip('"')
        encrypt_file(file_path, key, user_name)
        print(f"File encrypted as {user_name}_{os.path.basename(file_path)}.enc in the 'encrypted_data' folder.")
    elif choice.lower() == "d":
        # Collecting necessary information for decryption
        user_name = input("Enter your username: ")
        file_path = input("Enter the path of the file to decrypt: ").strip('"')
        key = getpass.getpass("Enter the decryption key (hidden): ")
        decrypted_file_path = decrypt_file(file_path, key, user_name)
        print(f"File decrypted and saved as {os.path.basename(decrypted_file_path)} in the 'decrypted_data' folder.")
    else:
        print("Invalid choice. Please enter 'e' for encrypt or 'd' for decrypt.")

if __name__ == "__main__":
    main()
