import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from core import (
    CryptoManager,
    load_vault,
    save_vault,
    
    InvalidToken
)
from utils.passwordGenerator import generate_passphrase
from utils.clipboard import copy_to_clipboard
import os

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("900x650")
        self.setup_styles()
        self.vault_path = Path("data/vault.json")
        self.cipher = None
        
        self.create_widgets()
        self.check_vault_state()

    def setup_styles(self):
        """Configure les styles visuels"""
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=('Helvetica', 10))
        style.configure("TButton", font=('Helvetica', 10), padding=5)
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'))

    def create_widgets(self):
        """Crée les widgets principaux"""
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

    def check_vault_state(self):
        """Vérifie si le vault existe et affiche l'écran approprié"""
        if not self.vault_path.exists():
            self.show_setup_screen()
        else:
            self.show_unlock_screen()

    # Écrans principaux
    def show_setup_screen(self):
        """Affiche l'écran de configuration initiale"""
        self.clear_frame()
        
        title = ttk.Label(self.main_frame, text="Create New Vault", font=('Helvetica', 14, 'bold'))
        title.pack(pady=20)
        
        form_frame = ttk.Frame(self.main_frame)
        form_frame.pack(pady=10)
        
        ttk.Label(form_frame, text="Master Password:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.master_pwd = ttk.Entry(form_frame, show="•", width=30)
        self.master_pwd.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Confirm Password:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.confirm_pwd = ttk.Entry(form_frame, show="•", width=30)
        self.confirm_pwd.grid(row=1, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(
            btn_frame, 
            text="Create Vault", 
            command=self.create_vault,
            style="TButton"
        ).pack(side=tk.LEFT, padx=10)

    def show_unlock_screen(self):
        """Affiche l'écran de déverrouillage"""
        self.clear_frame()
        
        title = ttk.Label(self.main_frame, text="Unlock Vault", font=('Helvetica', 14, 'bold'))
        title.pack(pady=20)
        
        form_frame = ttk.Frame(self.main_frame)
        form_frame.pack(pady=10)
        
        ttk.Label(form_frame, text="Master Password:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.master_pwd = ttk.Entry(form_frame, show="•", width=30)
        self.master_pwd.grid(row=0, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(
            btn_frame, 
            text="Unlock", 
            command=self.unlock_vault,
            style="TButton"
        ).pack(side=tk.LEFT, padx=10)

    def show_main_interface(self):
        """Affiche l'interface principale"""
        self.clear_frame()
        
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(expand=True, fill=tk.BOTH)
        
        # Onglet Ajouter
        self.add_tab = ttk.Frame(self.notebook)
        self.setup_add_tab()
        self.notebook.add(self.add_tab, text="Add Entry")
        
        # Onglet Voir
        self.view_tab = ttk.Frame(self.notebook)
        self.setup_view_tab()
        self.notebook.add(self.view_tab, text="View Entries")
        
        # Onglet Générateur
        self.generate_tab = ttk.Frame(self.notebook)
        self.setup_generate_tab()
        self.notebook.add(self.generate_tab, text="Generator")

    # Configuration des onglets
    def setup_add_tab(self):
        """Configure l'onglet d'ajout d'entrées"""
        form_frame = ttk.Frame(self.add_tab)
        form_frame.pack(pady=20, padx=20, fill=tk.X)
        
        ttk.Label(form_frame, text="Service:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.service_entry = ttk.Entry(form_frame)
        self.service_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.username_entry = ttk.Entry(form_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(form_frame, show="•")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        btn_frame = ttk.Frame(form_frame)
        btn_frame.grid(row=3, columnspan=2, pady=10)
        
        ttk.Button(
            btn_frame, 
            text="Generate Password", 
            command=self.generate_for_entry
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="Save Entry", 
            command=self.save_entry
        ).pack(side=tk.RIGHT, padx=5)

    def setup_view_tab(self):
        """Configure l'onglet de visualisation"""
        self.tree_frame = ttk.Frame(self.view_tab)
        self.tree_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        # Treeview avec scrollbar
        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=("service", "username"),
            show="headings",
            selectmode="browse"
        )
        
        self.tree.heading("service", text="Service")
        self.tree.heading("username", text="Username")
        self.tree.column("service", width=200)
        self.tree.column("username", width=300)
        
        vsb = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)
        
        # Boutons
        btn_frame = ttk.Frame(self.view_tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(
            btn_frame, 
            text="Copy Password", 
            command=self.copy_password
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="Refresh", 
            command=self.load_entries
        ).pack(side=tk.RIGHT, padx=5)
        
        self.load_entries()

    def setup_generate_tab(self):
        """Configure l'onglet de génération de mots de passe"""
        form_frame = ttk.Frame(self.generate_tab)
        form_frame.pack(pady=20, padx=20, fill=tk.X)
        
        ttk.Label(form_frame, text="Length (words):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.length_var = tk.IntVar(value=4)
        ttk.Spinbox(
            form_frame,
            from_=3,
            to=8,
            textvariable=self.length_var,
            width=5
        ).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(form_frame, text="Generated Password:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.generated_pwd = tk.StringVar()
        ttk.Entry(
            form_frame,
            textvariable=self.generated_pwd,
            state="readonly",
            width=40
        ).grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        btn_frame = ttk.Frame(form_frame)
        btn_frame.grid(row=2, columnspan=2, pady=10)
        
        ttk.Button(
            btn_frame, 
            text="Generate", 
            command=self.generate_password
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="Copy", 
            command=self.copy_generated
        ).pack(side=tk.RIGHT, padx=5)

    # Méthodes fonctionnelles
    def clear_frame(self):
        """Vide le frame principal"""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def create_vault(self):
        """Crée un nouveau vault"""
        pwd = self.master_pwd.get()
        confirm = self.confirm_pwd.get()
        
        if not pwd or pwd != confirm:
            messagebox.showerror("Error", "Passwords don't match or are empty")
            return
        
        try:
            cipher, salt = CryptoManager.initialize_vault(pwd)
            vault_data = {
                "version": 1,
                "salt": salt.hex(),
                "entries": {}
            }
            save_vault(self.vault_path, vault_data, self.cipher)
            messagebox.showinfo("Success", "Vault created successfully")
            self.show_main_interface()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create vault: {str(e)}")

    def unlock_vault(self):
        """Déverrouille le vault existant"""
        pwd = self.master_pwd.get()
        
        try:
            vault_data = load_vault(self.vault_path)
            salt = bytes.fromhex(vault_data["salt"])
            self.cipher = CryptoManager.unlock_vault(salt , pwd)

            self.show_main_interface()
        except InvalidToken:
            messagebox.showerror("Error", "Incorrect master password")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock vault: {str(e)}")

    def save_entry(self):
        """Sauvegarde une nouvelle entrée"""
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not all([service, username, password]):
            messagebox.showerror("Error", "All fields are required")
            return
        
        try:
            vault_data = load_vault(self.vault_path)
            vault_data["entries"][service] = {
                "username": username,
                "password": CryptoManager.encrypt(self.cipher, password)
            }
            save_vault(self.vault_path, vault_data, self.cipher)
            
            messagebox.showinfo("Success", "Entry saved successfully")
            self.service_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.load_entries()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save entry: {str(e)}")

    def load_entries(self):
        """Charge les entrées dans le Treeview"""
        try:
            self.tree.delete(*self.tree.get_children())
            vault_data = load_vault(self.vault_path)
            
            for service, entry in vault_data["entries"].items():
                self.tree.insert("", tk.END, values=(service, entry["username"]))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load entries: {str(e)}")

    def copy_password(self):
        """Copie le mot de passe sélectionné"""
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "No entry selected")
            return
        
        service = self.tree.item(selected)["values"][0]
        try:
            vault_data = load_vault(self.vault_path)
            encrypted = vault_data["entries"][service]["password"]
            password = CryptoManager.decrypt(self.cipher, encrypted)
            copy_to_clipboard(password)
            messagebox.showinfo("Success", "Password copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy password: {str(e)}")

    def generate_password(self):
        """Génère un nouveau mot de passe"""
        try:
            length = self.length_var.get()
            passphrase = generate_passphrase(num_words=length)
            self.generated_pwd.set(passphrase)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")

    def copy_generated(self):
        """Copie le mot de passe généré"""
        pwd = self.generated_pwd.get()
        if not pwd:
            messagebox.showwarning("Warning", "No password generated")
            return
        
        try:
            copy_to_clipboard(pwd)
            messagebox.showinfo("Success", "Password copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy password: {str(e)}")

    def generate_for_entry(self):
        """Génère un mot de passe pour l'entrée en cours"""
        try:
            length = 4  # Valeur par défaut
            passphrase = generate_passphrase(num_words=length)
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, passphrase)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")

def run_gui():
    """Lance l'interface graphique"""
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()