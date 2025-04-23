from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend 
import base64
import os
import getpass

def derive_master_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from master password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def initialize_vault():
    """Initialize new encrypted vault"""
    salt = os.urandom(16)
    master_pwd = getpass.getpass("Set master password: ")
    confirm_pwd = getpass.getpass("Confirm master password: ")
    
    if master_pwd != confirm_pwd:
        raise ValueError("Passwords do not match")
    
    if len(master_pwd) < 8:
        raise ValueError("Master password must be at least 8 characters")
    
    key = derive_master_key(master_pwd, salt)
    cipher = Fernet(key)
    
    # Store only the salt, not the derived key
    return cipher, salt

def unlock_vault(salt: bytes) -> Fernet:
    """Unlock existing vault with master password"""
    master_pwd = getpass.getpass("Enter master password: ")
    key = derive_master_key(master_pwd, salt)
    return Fernet(key)

def generate_key(key_path: str) -> bytes:
    """Génère ou charge une clé de chiffrement"""
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(key)
    else:
        with open(key_path, "rb") as key_file:
            key = key_file.read()
    return key

def initialize_cipher(key: bytes) -> Fernet:
    """Initialise le chiffreur Fernet"""
    return Fernet(key)

def encrypt(cipher: Fernet, plaintext: str) -> str:
    """Chiffre un texte en base64"""
    encrypted = cipher.encrypt(plaintext.encode())
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt(cipher: Fernet, encrypted_text: str) -> str:
    """Déchiffre un texte depuis base64"""
    encrypted = base64.b64decode(encrypted_text.encode('utf-8'))
    return cipher.decrypt(encrypted).decode('utf-8')