import pyperclip

def copy_to_clipboard(text: str):
    """Copie du texte dans le presse-papier"""
    try:
        pyperclip.copy(text)
        return True
    except Exception as e:
        raise RuntimeError(f"Erreur de copie: {str(e)}")