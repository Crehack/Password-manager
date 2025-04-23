import json
import os
from typing import Dict, Any

def load_vault(vault_path: str) -> Dict[str, Any]:
    """Charge les données depuis le coffre-fort"""
    if not os.path.exists(vault_path):
        return {}
    
    try:
        with open(vault_path, "r") as file:
            content = file.read()
            return json.loads(content) if content.strip() else {}
    except (json.JSONDecodeError, KeyError) as e:
        raise RuntimeError(f"Erreur de lecture du vault: {str(e)}")

def save_to_vault(vault_path: str, data: Dict[str, Any]):
    """Sauvegarde les données dans le coffre-fort"""
    with open(vault_path, "w") as file:
        json.dump(data, file, indent=4)