import argparse
from getpass import getpass
from pathlib import Path
from core.cryptography import generate_key, initialize_cipher, encrypt, decrypt
from core.storage import load_vault, save_to_vault
from utils.passwordGenerator import generate_passphrase
from utils.clipboard import copy_to_clipboard
import sys

# Configuration paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
KEY_PATH = DATA_DIR / "key.key"
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

def main():
    """Main entry point for the password manager CLI"""
    
    # Initialize directories and cryptographic components
    ensure_data_dir()
    try:
        key = generate_key(KEY_PATH)
        cipher = initialize_cipher(key)
    except Exception as e:
        sys.exit(f"Initialization error: {str(e)}")
    
    # Argument parser setup
    parser = argparse.ArgumentParser(
        description="Secure password manager using Fernet encryption",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter  
    )
    
    # Main command group (mutually exclusive)
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
                num_words = max(3, min(args.generate_passphrase, 6))  # Limit 3-6 words
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
            data = load_vault(VAULT_PATH)
            data[service] = {
                "identifier": identifier,
                "password": encrypt(cipher, password)
            }
            save_to_vault(VAULT_PATH, data)
            print(f"Success: Credentials for '{service}' saved")

        # Retrieve password
        elif args.get:
            service = args.get.strip()
            data = load_vault(VAULT_PATH)
            
            if service not in data:
                sys.exit(f"Error: Service '{service}' not found")
                
            print(f"Service: {service}")
            print(f"Identifier: {data[service]['identifier']}")
            password = decrypt(cipher, data[service]['password'])
            if copy_to_clipboard(password):
                print("Password copied to clipboard")
            else:
                print(f"Password: {password}")

        # List services
        elif args.list:
            data = load_vault(VAULT_PATH)
            if not data:
                print("No services stored")
                return
                
            print("Stored services:")
            for service, details in sorted(data.items()):
                print(f" - {service:20} : {details['identifier']}")

        # Generate passphrase only
        elif args.generate_passphrase is not None:
            num_words = max(3, min(args.generate_passphrase, 6))
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
    main()