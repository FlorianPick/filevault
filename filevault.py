import tkinter as tk
from tkinter import filedialog, messagebox
from authentication import Authentication
from encryption import Encryption

class FileVault:
    def __init__(self, root):
        self.root = root
        self.root.title("FileVault")
        self.root.geometry("400x300")

        # Instanzen der ausgelagerten Klassen
        self.auth = Authentication()
        self.encryption = Encryption()

        # Login/Register-Button
        self.login_register_button = tk.Button(self.root, text="Login / Register", command=self.open_login_register)
        self.login_register_button.pack(pady=10)

        # Datei auswählen-Button
        self.select_file_button = tk.Button(self.root, text="Datei Auswählen", command=self.select_file)
        self.select_file_button.pack(pady=10)

        # Verschlüsseln-Button
        self.encrypt_button = tk.Button(self.root, text="Verschlüsseln", command=self.encrypt_file)
        self.encrypt_button.pack(pady=10)

        # Entschlüsseln-Button
        self.decrypt_button = tk.Button(self.root, text="Entschlüsseln", command=self.decrypt_file)
        self.decrypt_button.pack(pady=10)

        self.selected_file = None  # Variable, um den Dateipfad zu speichern
        self.logged_in = False  # Um den Anmelde-Status zu speichern

    def open_login_register(self):
        # Öffnet den Login/Register-Dialog
        self.auth.open_login_register_dialog(self.root, self.on_login_success)

    def on_login_success(self):
        # Diese Funktion wird aufgerufen, wenn der Login erfolgreich war
        self.logged_in = True

    def select_file(self):
        # Öffnet einen Dialog zum Auswählen einer Datei
        self.selected_file = filedialog.askopenfilename(title="Datei auswählen")
        if self.selected_file:
            messagebox.showinfo("Datei Ausgewählt", f"Datei: {self.selected_file}")

    def encrypt_file(self):
        if not self.logged_in:
            messagebox.showwarning("Fehler", "Bitte melden Sie sich zuerst an.")
        elif not self.selected_file:
            messagebox.showwarning("Fehler", "Bitte wählen Sie zuerst eine Datei aus.")
        else:
            # Aufruf der Verschlüsselungslogik über die Encryption-Klasse
            self.encryption.encrypt(self.selected_file)
            messagebox.showinfo("Verschlüsseln", "Datei wird verschlüsselt...")

    def decrypt_file(self):
        if not self.logged_in:
            messagebox.showwarning("Fehler", "Bitte melden Sie sich zuerst an.")
        elif not self.selected_file:
            messagebox.showwarning("Fehler", "Bitte wählen Sie zuerst eine Datei aus.")
        else:
            # Aufruf der Entschlüsselungslogik über die Encryption-Klasse
            self.encryption.decrypt(self.selected_file)
            messagebox.showinfo("Entschlüsseln", "Datei wird entschlüsselt...")

# Start der Anwendung
if __name__ == "__main__":
    root = tk.Tk()
    app = FileVault(root)
    root.mainloop()
