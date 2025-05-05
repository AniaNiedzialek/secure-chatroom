from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_key_from_password(password: str) -> bytes:
    """Generate a Fernet key from a user password"""
    # Convert password to bytes
    password_bytes = password.encode()
    
    # Generate a salt (in a real app, this would be stored securely)
    salt = b'secure_chat_salt'  # In production, use a unique salt per user
    
    # Use PBKDF2 to derive a key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def create_cipher(key: bytes) -> Fernet:
    """Create a Fernet cipher instance with the given key"""
    return Fernet(key)

def encrypt_message(message: str, cipher: Fernet) -> bytes:
    """Encrypt a message using the provided cipher"""
    return cipher.encrypt(message.encode())

def decrypt_message(token: bytes, cipher: Fernet) -> str:
    """Decrypt a message using the provided cipher"""
    return cipher.decrypt(token).decode()