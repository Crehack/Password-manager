from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import getpass
from typing import Tuple, Optional

class CryptoManager:
    """Centralized cryptographic operations for both CLI and GUI"""
    
    @staticmethod
    def derive_master_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def initialize_vault(password: Optional[str] = None) -> Tuple[Fernet, bytes]:
        """Initialize new encrypted vault
        
        Args:
            password: Optional password (for GUI). If None, prompts via CLI.
            
        Returns:
            Tuple of (cipher, salt)
        """
        salt = os.urandom(16)
        
        if password is None:  # CLI mode
            master_pwd = getpass.getpass("Set master password: ")
            confirm_pwd = getpass.getpass("Confirm master password: ")
        else:  # GUI mode
            master_pwd = confirm_pwd = password
            
        if master_pwd != confirm_pwd:
            raise ValueError("Passwords do not match")
        
        if len(master_pwd) < 8:
            raise ValueError("Master password must be at least 8 characters")
        
        key = CryptoManager.derive_master_key(master_pwd, salt)
        return Fernet(key), salt

    @staticmethod
    def unlock_vault(salt: bytes, password: Optional[str] = None) -> Fernet:
        """Unlock existing vault with master password
        
        Args:
            salt: The salt from vault
            password: Optional password (for GUI). If None, prompts via CLI.
        """
        master_pwd = password if password is not None else getpass.getpass("Enter master password: ")
        key = CryptoManager.derive_master_key(master_pwd, salt)
        return Fernet(key)

    @staticmethod
    def encrypt(cipher: Fernet, plaintext: str) -> str:
        """Encrypt text and return as base64 string"""
        encrypted = cipher.encrypt(plaintext.encode())
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def decrypt(cipher: Fernet, encrypted_text: str) -> str:
        """Decrypt base64 encoded encrypted text"""
        encrypted = base64.b64decode(encrypted_text.encode('utf-8'))
        return cipher.decrypt(encrypted).decode('utf-8')

    # Legacy functions for CLI backward compatibility
    @staticmethod
    def generate_key(key_path: str) -> bytes:
        """Legacy: Generate or load encryption key (for CLI compatibility)"""
        if not os.path.exists(key_path):
            key = Fernet.generate_key()
            with open(key_path, "wb") as key_file:
                key_file.write(key)
        else:
            with open(key_path, "rb") as key_file:
                key = key_file.read()
        return key

    @staticmethod
    def initialize_cipher(key: bytes) -> Fernet:
        """Legacy: Initialize Fernet cipher (for CLI compatibility)"""
        return Fernet(key)