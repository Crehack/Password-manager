"""
Core package for the secure password manager.
Contains all cryptographic operations and vault storage management.
"""

from .cryptography import (
    derive_master_key,
    initialize_vault,
    unlock_vault,
    encrypt,
    decrypt,
    InvalidToken
)
from .storage import (
    create_new_vault,
    load_vault,
    save_vault,
    VAULT_HEADER
)

__all__ = [
    'derive_master_key',
    'initialize_vault',
    'unlock_vault',
    'encrypt',
    'decrypt',
    'InvalidToken',
    'create_new_vault',
    'load_vault',
    'save_vault',
    'VAULT_HEADER'
]

__version__ = '1.0.0'