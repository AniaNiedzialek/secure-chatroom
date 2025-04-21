from cryptography.fernet import Fernet

# Hardcoded shared key (generate once with Fernet.generate_key())
SHARED_KEY = b'yCoKQY9jAq3aNwvMlP_NG1eaLEyqVHV3zRAojUM97mk='

cipher = Fernet(SHARED_KEY)

def encrypt_message(message: str) -> bytes:
    return cipher.encrypt(message.encode())

def decrypt_message(token: bytes) -> str:
    return cipher.decrypt(token).decode()