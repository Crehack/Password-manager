from pathlib import Path
from core import (
    initialize_vault,
    unlock_vault,
    save_vault,
    load_vault,
    InvalidToken,
    encrypt,
    decrypt
)

class VaultController:
    def __init__(self, vault_path):
        self.vault_path = Path(vault_path)
        self.cipher = None
    
    def create_vault(self, password):
        """Initialize new password vault"""
        self.cipher, salt = initialize_vault(password)
        vault_data = {
            "version": 1,
            "salt": salt.hex(),
            "entries": {}
        }
        save_vault(self.vault_path, vault_data, self.cipher)
        return True
    
    def unlock_vault(self, password):
        """Unlock existing vault"""
        vault_data = load_vault(self.vault_path)
        salt = bytes.fromhex(vault_data["salt"])
        self.cipher = unlock_vault(password, salt)
        return vault_data
    
    def add_entry(self, service, username, password):
        """Add new password entry"""
        vault_data = load_vault(self.vault_path)
        vault_data["entries"][service] = {
            "username": username,
            "password": encrypt(self.cipher, password)
        }
        save_vault(self.vault_path, vault_data, self.cipher)
    
    def get_entries(self):
        """Get all decrypted entries"""
        vault_data = load_vault(self.vault_path)
        return {
            service: {
                "username": entry["username"],
                "password": decrypt(self.cipher, entry["password"])
            }
            for service, entry in vault_data["entries"].items()
        }