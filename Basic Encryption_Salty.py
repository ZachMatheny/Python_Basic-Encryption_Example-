import bcrypt
from cryptography.fernet import Fernet

# Secure password hashing
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# Encryption and decryption
def generate_key():
    return Fernet.generate_key()

def encrypt_message(key, message):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode('utf-8'))
    return encrypted_message

def decrypt_message(key, encrypted_message):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')

# Main function to demonstrate the features
def main():
    # Password hashing
    password = "SuperSecretPassword123"
    hashed_password = hash_password(password)
    print(f"Original password: {password}")
    print(f"Hashed password: {hashed_password}")

    # Password verification
    is_correct = check_password(hashed_password, "SuperSecretPassword123")
    print(f"Password verification (correct): {is_correct}")

    is_incorrect = check_password(hashed_password, "WrongPassword")
    print(f"Password verification (incorrect): {is_incorrect}")

    # Encryption and decryption
    key = generate_key()
    message = "This is a confidential message."
    encrypted_message = encrypt_message(key, message)
    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted_message}")

    decrypted_message = decrypt_message(key, encrypted_message)
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()
