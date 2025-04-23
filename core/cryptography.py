from cryptography.fernet import Fernet
import base64
import os

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