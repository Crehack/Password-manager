import tkinter as tk
from tkinter import simpledialog

class PasswordDialog(simpledialog.Dialog):
    def __init__(self, parent, title=None, prompt=None):
        self.prompt = prompt or "Enter password:"
        super().__init__(parent, title=title)
    
    def body(self, master):
        tk.Label(master, text=self.prompt).pack()
        self.entry = tk.Entry(master, show="•")
        self.entry.pack()
        return self.entry
    
    def apply(self):
        self.result = self.entry.get()