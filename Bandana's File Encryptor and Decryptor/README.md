# Overview
Bandana's Encryption/Decryption App is a Python application with a Graphical User Interface (GUI) that allows users to encrypt and decrypt files securely using AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode. It's designed to be user-friendly, requiring minimal technical knowledge to operate.

# Features
1. Encrypt Files: Users can select any file on their system to encrypt. The encrypted file is saved in a designated folder with the user's name as a prefix.
2. Decrypt Files: Users can also decrypt previously encrypted files, provided they have the correct key.
User Credentials: The app requires a username and a key for encryption and decryption, ensuring personalized security.
3. File Processing Database: The app maintains a JSON database (file_data.json) recording details of the encryption and decryption processes for each user.

# Notes
1. Security: For enhanced security, the app uses a static salt for key derivation. In a more advanced application, a unique salt for each user would be preferable.
2. File Storage: Encrypted files are stored in the 'encrypted_data' folder, and decrypted files in the 'decrypted_data' folder.
3. Data Handling: User-specific encryption and decryption records are stored in file_data.json.