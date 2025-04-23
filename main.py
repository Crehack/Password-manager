from cryptography.fernet import Fernet
import os
import base64
import json
import argparse
import pyperclip 
from getpass import getpass
import string
import secrets

def genererCle():
    if not os.path.exists("cle.key"):
        key = Fernet.generate_key()
        with open("cle.key", "wb") as keyFile:
            keyFile.write(key)
    else:
        with open("cle.key", "rb") as keyFile:
            key = keyFile.read()
    return key

key = genererCle()
cipher = Fernet(key)

def cypher(password: str) -> str:
    """Chiffre le mot de passe et retourne une string base64"""
    encrypted = cipher.encrypt(password.encode())
    return base64.b64encode(encrypted).decode('utf-8')

def decipher(encryptedPassword: str) -> str:
    """Déchiffre un mot de passe depuis une string base64"""
    encrypted = base64.b64decode(encryptedPassword.encode('utf-8'))
    return cipher.decrypt(encrypted).decode('utf-8')

def load():
    """Charge les données depuis le fichier JSON"""
    if not os.path.exists("vault.json"):
        return {}
    
    try:
        with open("vault.json", "r") as file:
            content = file.read()
            if not content.strip():
                return {}
                
            data = json.loads(content)
            return data 
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Erreur de lecture du fichier: {str(e)}")
        return {}

def save(service: str, password: str, id: str):
    """Sauvegarde les données dans le fichier JSON"""
    data = load()
    data[service] = {
        "identifiant": id,
        "mdp": cypher(password)  
    }
    
    with open("vault.json", "w") as file:
        json.dump(data, file, indent=4)

def generatePassword(lenght = 16, Special = True):
    chars = string.ascii_letters + string.digits
    if Special:
        chars += "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(lenght))


def main():
    parser = argparse.ArgumentParser(description="fernet encrypted password manager")
    parser.add_argument("--add", action="store_true", help="add new password")
    parser.add_argument("--get", type=str, help="get service's password")
    parser.add_argument("--list", action="store_true", help="list all services already entered")
    

    args = parser.parse_args()

    if args.add:
        element = input("Service (Ex:GitHub, Google, etc.) : ")
        id = input("Identifier : ")
        password = getpass("Password : ")
        save(element, password, id)
        print(f"Password for {element} saved!")
    elif args.get:
        data = load()
        if args.get in data:
            print(f"Identifier: {data[args.get]['identifiant']}")
            pyperclip.copy(decipher(data[args.get]['mdp']))
            print('Password copied in clipboard')
        else:
            print(f"Service '{args.get}' not found!")
    elif args.list:
        services = list(load().keys())
        data = load()
        
        print("Saved services : ")
        for service in services:
            print(f" - {service} | id : {data[service]['identifiant']}")

if __name__ == "__main__":
    
    if not os.path.exists("vault.json"):
        with open("vault.json", "w") as f:
            f.write("{}")
    main() 
