from cryptography.fernet import Fernet
import os , base64
import json

def genererCle():
    if not os.path.exists("cle.key"):
        key = Fernet.generate_key()
        with open("cle.key" , "wb") as keyFile:
            keyFile.write(key)
    else:
        with open("cle.key" , "rb") as keyFile:
            key = keyFile.read()
    return key


def cipher(password : str) -> bytes:
    return cipher.encrypt(password.encode())

def decipher(encryptedPassword : bytes) -> str :
    return cipher.decrypt(encryptedPassword).decode()

def load():
    with open("vault.json" , "rb") as file:
        data = json.load(file)
    return {
        service: {
            "identifiant": infos["identifiant"],
            "mdp": decipher(base64.b64decode(infos["mdp"].encode())).decode()
        } for service, infos in data.items()
    }


def save(service : str  , password : str , id : str):
    data = load() if os.path.exists("vault.json") else {}
    data[service] = {
        "identifiant" : id,
        "password" : base64.b64encode(cipher(password)).decode
    }
    with open("vault.json" , "w") as file:
        json.dump(data, file)

while(True):
    
    print("bienvenue dans le gestionnaire de mots de passes")
    print("tapez help pour l'aide")
    commande = input(">>>>")
    if commande == "help":
        print("liste : afficher la liste des mots de passe")

        