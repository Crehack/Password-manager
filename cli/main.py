import argparse
from getpass import getpass
from pathlib import Path
import os
import sys
from core.cryptography import CryptoManager
from core.storage import load_vault, save_vault, create_new_vault
from utils.clipboard import copy_to_clipboard
from utils.passwordGenerator import generate_passphrase

# Configuration paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
VAULT_PATH = DATA_DIR / "vault.json"

def ensure_data_dir():
    """Creates data directory if it doesn't exist"""
    DATA_DIR.mkdir(exist_ok=True)
    if not DATA_DIR.exists():
        sys.exit("Error: Could not create data directory")

def validate_service_name(service: str) -> bool:
    """
    Validates service name format
    Args:
        service: Name of the service to validate
    Returns:
        bool: True if valid, False otherwise
    """
    if " " in service:
        print("Warning: Spaces in service names may cause issues")
    return 2 <= len(service) <= 50 and all(c.isalnum() or c in " -_" for c in service)

def cli_main():
    """Main entry point for the password manager CLI"""
    
    # Initialize directories
    ensure_data_dir()
    
    # Check if vault exists
    if not VAULT_PATH.exists():
        print("Initializing new password vault...")
        try:
            cipher, salt = CryptoManager.initialize_vault()
            create_new_vault(VAULT_PATH, salt)
            print("Vault created successfully")
            return
        except Exception as e:
            sys.exit(f"Error: {str(e)}")
    
    # Load existing vault
    try:
        vault_data = load_vault(VAULT_PATH)
        salt = bytes.fromhex(vault_data["salt"])
        cipher = CryptoManager.unlock_vault(salt)
        
       
        decrypted_data = vault_data.copy()
        for service, entry in decrypted_data["entries"].items():
            if "password" in entry:
                entry["password"] = CryptoManager.decrypt(cipher, entry["password"])
                
    except Exception as e:
        sys.exit(f"Error: {str(e)}")

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Secure password manager using Fernet encryption",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter  
    )
    
    main_group = parser.add_mutually_exclusive_group()
    main_group.add_argument("--add", "-a", 
                          action="store_true", 
                          help="Add new password entry")
    main_group.add_argument("--get", "-g", 
                          type=str, 
                          help="Retrieve password for specified service")
    main_group.add_argument("--list", "-l", 
                          action="store_true", 
                          help="List all stored services")
    
    # Optional arguments
    parser.add_argument(
        "--generate-passphrase", "-p",
        nargs='?',
        const=4,
        type=int,
        help="Generate passphrase with specified word count (default: 4)"
    )
    parser.add_argument(
        "--wordlist", "-w",
        type=Path,
        help="Path to custom wordlist file"
    )

    args = parser.parse_args()

    try:
        # Add new password entry
        if args.add:
            service = input("Service (e.g., GitHub): ").strip()
            if not validate_service_name(service):
                sys.exit("Error: Invalid service name (2-50 alphanumeric characters)")
            
            identifier = input("Identifier: ").strip()

            # Handle password generation or input
            if args.generate_passphrase is not None:
                num_words = max(3, args.generate_passphrase)  # Limit 3-6 words
                password = generate_passphrase(
                    num_words=num_words,
                    wordlist_path=args.wordlist
                )
                print(f"\nGenerated passphrase ({num_words} words):")
                print(f"  {password}\n")
            else:
                password = getpass("Password: ").strip()
            
            if not all([service, identifier, password]):
                sys.exit("Error: All fields are required")
            
            # Save to vault
            decrypted_data["entries"][service] = {
                "identifier": identifier,
                "password": CryptoManager.encrypt(cipher, password)
            }
            save_vault(VAULT_PATH, decrypted_data, cipher)
            print(f"Success: Credentials for '{service}' saved")

        # Retrieve password
        elif args.get:
            service = args.get.strip()
            
            if service not in decrypted_data["entries"]:
                sys.exit(f"Error: Service '{service}' not found")
                
            entry = decrypted_data["entries"][service]
            print(f"Service: {service}")
            print(f"Identifier: {entry['identifier']}")
            if copy_to_clipboard(entry["password"]):
                print("Password copied to clipboard")
            else:
                print(f"Password: {entry['password']}")

        # List services
        elif args.list:
            if not decrypted_data["entries"]:
                print("No services stored")
                return
                
            print("Stored services:")
            for service, entry in sorted(decrypted_data["entries"].items()):
                print(f" - {service:20} : {entry['identifier']}")

        # Generate passphrase only
        elif args.generate_passphrase is not None:
            num_words = max(3, args.generate_passphrase)
            try:
                passphrase = generate_passphrase(
                    num_words=num_words,
                    wordlist_path=args.wordlist
                )
                print(f"\nGenerated passphrase ({num_words} words):")
                print(f"  {passphrase}\n")
                
                if input("Copy to clipboard? (y/n) ").strip().lower() == 'y':
                    if copy_to_clipboard(passphrase):
                        print("Copied to clipboard")
            except Exception as e:
                sys.exit(f"Generation error: {str(e)}")

        # Show help if no arguments
        else:
            parser.print_help()

    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        sys.exit(f"Error: {str(e)}")

if __name__ == "__main__":
    cli_main()