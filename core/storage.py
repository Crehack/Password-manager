import json
import os
from pathlib import Path
from typing import Dict, Any
from cryptography.fernet import Fernet  # Added missing import

VAULT_HEADER = {
    "version": 1,
    "salt": None,  # Will be populated
    "entries": {}
}

def create_new_vault(vault_path: Path, salt: bytes):
    """Initialize new vault file with salt"""
    vault_data = VAULT_HEADER.copy()
    vault_data["salt"] = salt.hex()
    
    with open(vault_path, 'w') as f:
        json.dump(vault_data, f, indent=2)

def load_vault(vault_path: Path) -> Dict[str, Any]:
    """Load vault structure with validation"""
    if not vault_path.exists():
        raise FileNotFoundError("Vault file not found")
    
    with open(vault_path, 'r') as f:
        data = json.load(f)
    
    if not all(k in data for k in VAULT_HEADER.keys()):
        raise ValueError("Invalid vault structure")
    
    return data

def save_vault(vault_path: Path, data: Dict[str, Any], cipher: Fernet):
    """Save data to encrypted vault"""
    if "entries" not in data:
        raise ValueError("Invalid vault data structure")
    
    # Encrypt all passwords before saving
    encrypted_data = data.copy()
    for service, entry in encrypted_data["entries"].items():
        if "password" in entry:
            entry["password"] = cipher.encrypt(entry["password"].encode()).decode()
    
    with open(vault_path, 'w') as f:
        json.dump(encrypted_data, f, indent=2)