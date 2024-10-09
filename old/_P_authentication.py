import sqlite3
import pyotp
from tkinter import Toplevel, Label, Entry, Button, messagebox
import tkinter as tk
import qrcode  # Importiere qrcode
from PIL import Image, ImageTk  # Importiere Pillow für die Bildbearbeitung


class Authentication:
    def __init__(self, root, master):
        self.conn = sqlite3.connect('../users.db')  # SQLite-Datenbank für Benutzerdaten
        self.cursor = self.conn.cursor()
        self.current_username = None
        self.root = root
        self.master = master  # Speichere eine Referenz auf das Hauptfenster
        self.is_2fa_prompted = False
        self.is_verifying = False  # Flag für die Überprüfung des 2FA-Codes

        # Tabelle erstellen, falls sie nicht existiert
        self.cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                secret TEXT
            )
        ''')
        self.conn.commit()

    def on_qr_window_close(self):
        """Aktion beim Schließen des QR-Code-Fensters."""
        self.qr_window.destroy()
        self.qr_window = None  # Setze das QR-Fenster zurück

    def open_login_dialog(self, root, on_success):
        """Öffnet das Login-Fenster."""
        self.login_window = Toplevel(root)
        self.login_window.title("Login")

        Label(self.login_window, text="Benutzername:").pack(pady=5)
        self.username_entry = Entry(self.login_window)
        self.username_entry.pack(pady=5)
        self.username_entry.focus_set()

        Label(self.login_window, text="Passwort:").pack(pady=5)
        self.password_entry = Entry(self.login_window, show="*")
        self.password_entry.pack(pady=5)

        self.show_password_var = tk.BooleanVar()  # Variable für die Checkbox
        self.show_password_checkbox = tk.Checkbutton(self.login_window, text="Passwort im Klartext anzeigen",
                                                     variable=self.show_password_var,
                                                     command=self.toggle_password_visibility)
        self.show_password_checkbox.pack(pady=10)

        Button(self.login_window, text="Anmelden",
               command=lambda: self.login(on_success)).pack(pady=10)

    def toggle_password_visibility(self):
        """Wechselt zwischen Passwort anzeigen und verstecken."""
        if self.show_password_var.get():
            self.password_entry.config(show='')  # Klartext anzeigen
        else:
            self.password_entry.config(show='*')  # Passwort verstecken

    def close_login_dialog(self):
        """Schließt das Login-Fenster."""
        if hasattr(self, 'login_window') and self.login_window.winfo_exists():
            self.login_window.destroy()

    def login(self, on_success):
        """Behandelt die Anmelde-Logik."""
        username = self.username_entry.get()
        password = self.password_entry.get()

        self.cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        row = self.cursor.fetchone()

        if row and row[0] == password:
            self.current_username = username
            print("Anmeldung erfolgreich")  # Debug-Ausgabe
            self.close_login_dialog()  # Schließt das Login-Fenster

            if self.is_2fa_linked(username):
                # Wenn 2FA verknüpft ist, 2FA-Code abfragen
                if not self.is_2fa_prompted:  # Überprüfen, ob 2FA bereits aufgefordert wurde
                    self.is_2fa_prompted = True  # Flag setzen
                    self.prompt_for_2fa_code(on_success)
            else:
                # Wenn 2FA nicht verknüpft ist, Benutzer auffordern, einen Authenticator zu verknüpfen
                self.prompt_link_authenticator(on_success)
        else:
            messagebox.showerror("Fehler", "Ungültiger Benutzername oder Passwort.")

    def prompt_link_authenticator(self, on_success):
        """Fordert den Benutzer auf, einen Authenticator zu verknüpfen."""
        secret = self.link_authenticator(self.current_username)  # Link den Authenticator
        self.show_authenticator_qr(secret)  # QR-Code anzeigen
        self.login_window.destroy()  # Fenster schließen, da kein Benutzer eingeloggt bleibt

    def prompt_for_2fa_code(self, on_code_entered):
        """Öffnet ein Fenster zur Eingabe des 2FA-Codes."""
        self.code_window = tk.Toplevel(self.root)
        self.code_window.title("2FA Code eingeben")

        tk.Label(self.code_window, text="Bitte geben Sie Ihren 2FA-Code ein:").pack(pady=5)

        self.code_entry = tk.Entry(self.code_window)
        self.code_entry.pack(pady=5)
        self.code_entry.focus_set()

        # Bindet die Return-Taste
        self.code_entry.bind('<Return>', lambda event: self.verify_code(on_code_entered))

        # Bestätigungsbutton
        tk.Button(self.code_window, text="Bestätigen", command=lambda: self.verify_code(on_code_entered)).pack(pady=10)

        # Bindet die Return-Taste hier richtig
        self.code_window.bind('<Return>', lambda event: self.verify_code(on_code_entered))  # Korrektur

        self.code_window.protocol("WM_DELETE_WINDOW", self.on_code_window_close)

    def verify_code(self, on_code_entered):
        """Überprüft den eingegebenen 2FA-Code."""
        if self.is_verifying:
            print("Bereits mit der Überprüfung beschäftigt.")
            return  # Verhindere mehrere Überprüfungen

        self.is_verifying = True  # Setze das Flag auf True
        if not self.code_window or not self.code_window.winfo_exists():
            print("Das Fenster existiert nicht oder wurde bereits geschlossen.")
            self.is_verifying = False  # Setze das Flag zurück
            return

        code = self.code_entry.get()
        print(f"Eingegebener Code: {code}")

        if self.check_code(code):
            print("Code erfolgreich verifiziert!")
            self.code_window.destroy()  # Schließe das 2FA-Fenster
            self.code_window = None  # Setze das Fenster-Referenz zurück

            self.is_2fa_prompted = False  # Reset-Flag für 2FA-Aufforderung
            self.master.enable_main_menu()  # Aufruf der Methode im Hauptfenster
        else:
            print("Ungültiger 2FA-Code.")
            messagebox.showerror("Fehler", "Ungültiger 2FA-Code. Bitte versuchen Sie es erneut.")

        self.is_verifying = False  # Setze das Flag zurück

    def check_code(self, code):
        """Überprüft den eingegebenen 2FA-Code mit dem gespeicherten Geheimnis."""
        self.cursor.execute("SELECT secret FROM users WHERE username=?", (self.current_username,))
        row = self.cursor.fetchone()

        if row and row[0]:
            secret = row[0]
            totp = pyotp.TOTP(secret)  # Stelle sicher, dass 'totp' hier initialisiert wird
            print(f"TOTP-Wert: {totp.now()}")  # Debug-Ausgabe für den aktuellen TOTP-Wert
            return totp.verify(code)  # Überprüft den 2FA-Code
        return False

    def open_register_dialog(self, master, callback):
        """Öffnet das Registrierungsfenster."""
        self.register_window = Toplevel(master)
        self.register_window.title("Registrierung")

        Label(self.register_window, text="Benutzername:").pack(pady=5)
        self.register_username_entry = Entry(self.register_window)
        self.register_username_entry.pack(pady=5)
        self.register_username_entry.focus_set()

        Label(self.register_window, text="Passwort:").pack(pady=5)
        self.register_password_entry = Entry(self.register_window, show="*")
        self.register_password_entry.pack(pady=5)

        self.show_register_password_var = tk.BooleanVar()  # Variable für die Checkbox
        self.show_register_password_checkbox = tk.Checkbutton(self.register_window,
                                                              text="Passwort im Klartext anzeigen",
                                                              variable=self.show_register_password_var,
                                                              command=self.toggle_register_password_visibility)
        self.show_register_password_checkbox.pack(pady=10)

        Button(self.register_window, text="Registrieren",
               command=lambda: self.register(callback)).pack(pady=10)

    def toggle_register_password_visibility(self):
        """Wechselt zwischen Passwort anzeigen und verstecken für die Registrierung."""
        if self.show_register_password_var.get():
            self.register_password_entry.config(show='')  # Klartext anzeigen
        else:
            self.register_password_entry.config(show='*')  # Passwort verstecken

    def register(self, callback):
        """Behandelt die Registrierungs-Logik."""
        username = self.register_username_entry.get()
        password = self.register_password_entry.get()

        if not username or not password:
            messagebox.showerror("Fehler", "Benutzername und Passwort sind erforderlich.")
            return

        try:
            self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            self.conn.commit()

            # Setze den Benutzernamen und zeige den QR-Code an
            self.current_username = username  # Setze den Benutzernamen
            secret = self.link_authenticator(username)  # Link Authenticator

            self.register_window.destroy()  # Schließt das Registrierungsfenster
            callback(username)  # Optional: Rückruf mit dem Benutzernamen
        except sqlite3.IntegrityError:
            messagebox.showerror("Fehler", "Benutzername bereits vorhanden.")

    def show_authenticator_qr(self, secret):
        """Zeigt den QR-Code zur Verknüpfung des Authenticators an."""
        if hasattr(self, 'qr_window') and self.qr_window is not None and self.qr_window.winfo_exists():
            return

        # Format für die URI anpassen
        account_name = f"{self.current_username}"
        uri = f"otpauth://totp/FileVault:{account_name}?secret={secret}&issuer=FileVault"

        # QR-Code generieren
        qr = qrcode.make(uri)

        # QR-Code in ein Bild umwandeln und speichern
        img = ImageTk.PhotoImage(qr)

        # Neues Fenster für den QR-Code erstellen
        self.qr_window = tk.Toplevel(self.root)
        self.qr_window.title("Authenticator QR Code")

        # Label über dem QR-Code hinzufügen
        tk.Label(self.qr_window,
                 text="Bitte scannen Sie diesen QR-Code mit einer Authenticator App um Ihren Account zu verknüpfen").pack(
            pady=10)

        # QR-Code im Fenster anzeigen
        qr_label = tk.Label(self.qr_window, image=img)
        qr_label.image = img  # Referenz halten
        qr_label.pack(pady=10)

        # Schließen der QR-Fenster-Protokolle
        self.qr_window.protocol("WM_DELETE_WINDOW", self.on_qr_window_close)


    def link_authenticator(self, username):
        """Verknüpft einen Authenticator mit dem Benutzer und speichert das Geheimnis in der DB."""
        secret = pyotp.random_base32()  # Generiere ein neues Geheimnis
        self.cursor.execute("UPDATE users SET secret=? WHERE username=?", (secret, username))
        self.conn.commit()

        return secret  # Gib das Geheimnis zurück

    def is_2fa_linked(self, username):
        """Überprüft, ob der Benutzer 2FA verknüpft hat."""
        self.cursor.execute("SELECT secret FROM users WHERE username=?", (username,))
        row = self.cursor.fetchone()
        return row and row[0] is not None

    def __del__(self):
        """Schließt die Datenbankverbindung beim Löschen der Authentifizierungsinstanz."""
        self.conn.close()

    def on_code_window_close(self):
        """Behandelt das Schließen des 2FA-Code-Fensters."""
        if self.code_window:
            self.code_window.destroy()
            self.code_window = None  # Setze das 2FA-Fenster zurück
            self.is_2fa_prompted = False  # Flag zurücksetzen, um zukünftige Eingaben zu ermöglichen

            # Optional: Rückmeldung an den Benutzer
            messagebox.showinfo("Hinweis", "Das 2FA-Fenster wurde geschlossen.")
