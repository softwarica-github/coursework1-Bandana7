import os
import json
from test import derive_key, encrypt_file, decrypt_file, update_database

# Test for derive_key function
def test_derive_key():
    key = "test_password"
    derived = derive_key(key)
    assert len(derived) == 32, "Derived key must be 32 bytes long"
    assert derive_key(key) == derived, "Derived key should be consistent for the same input"

# Test for encrypt_file and decrypt_file functions
def test_encrypt_decrypt():
    user_name = "test_user"
    key = "test_key"
    original_file_path = "test.txt"

    # Create a sample file to encrypt
    with open(original_file_path, 'w') as file:
        file.write("This is a test file.")

    # Encrypt the file
    encrypt_file(original_file_path, key, user_name)
    encrypted_file_path = os.path.join('encrypted_data', f"{user_name}_test.txt.enc")
    assert os.path.exists(encrypted_file_path), "Encrypted file does not exist"

    # Decrypt the file
    decrypted_file_path = decrypt_file(encrypted_file_path, key, user_name)
    assert os.path.exists(decrypted_file_path), "Decrypted file does not exist"

    # Compare the original and decrypted files
    with open(original_file_path, 'r') as file:
        original_content = file.read()
    with open(decrypted_file_path, 'r') as file:
        decrypted_content = file.read()
    assert original_content == decrypted_content, "Decrypted content does not match original"

    # Cleanup
    os.remove(original_file_path)
    os.remove(encrypted_file_path)
    os.remove(decrypted_file_path)

# Test for update_database function
def test_update_database():
    user_name = "test_user"
    original_path = "test.txt"
    processed_path = "test_processed.txt"
    action = "encrypt"

    update_database(user_name, original_path, processed_path, action)
    db_path = 'file_data.json'

    # Check if the database file exists and contains the correct information
    assert os.path.exists(db_path), "Database file does not exist"
    with open(db_path, 'r') as file:
        data = json.load(file)
    assert user_name in data, "User not found in database"
    assert data[user_name][action][-1]["original"] == original_path, "Original path not recorded correctly"
    assert data[user_name][action][-1]["processed"] == processed_path, "Processed path not recorded correctly"

    # Cleanup
    os.remove(db_path)

# Running the tests
if __name__ == "__main__":
    test_derive_key()
    test_encrypt_decrypt()
    test_update_database()
    print("All tests passed.")
