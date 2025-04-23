import secrets
from pathlib import Path
from typing import List, Optional

DEFAULT_WORDLIST = Path(__file__).parent.parent / "data" / "wordlist.txt"

def load_wordlist(wordlist_path: Optional[str] = None) -> List[str]:
    """Charge une wordlist depuis un fichier"""
    path = Path(wordlist_path) if wordlist_path else DEFAULT_WORDLIST
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        raise ValueError(f"Wordlist introuvable : {path}")

def generate_passphrase(
    num_words: int = 4,
    wordlist_path: Optional[str] = None,
    separator: str = "-",
    capitalize: bool = True,
    add_number: bool = True,
    add_symbol: bool = True
) -> str:
    """
    Génère une passphrase aléatoire
    Args:
        num_words: Words number (4-n recommandé)
        wordlist_path: Custom wordlist path
        separator: Word separator
        capitalize: Capitalize any words
        add_number: Add random number
        add_symbol: Add random symbol
    """
    wordlist = load_wordlist(wordlist_path)
    

    if len(wordlist) < num_words:
        raise ValueError(f"La wordlist doit contenir au moins {num_words} mots")
    
    
    words = [secrets.choice(wordlist) for _ in range(num_words)]
    
    
    if capitalize:
        words = [word.capitalize() for word in words]
    
    passphrase = separator.join(words)
    
    
    if add_number:
        passphrase += str(secrets.randbelow(90) + 10)  # 10-99
    
    if add_symbol:
        symbols = ["!", "@", "#", "$", "%", "&"]
        passphrase += secrets.choice(symbols)
    
    return passphrase