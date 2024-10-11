import tkinter as tk
import ttkbootstrap as tb
from tkinter import filedialog, messagebox
from ttkbootstrap import SUCCESS, DANGER
from encryption import Encryption
from authentication import Authentication
from PIL import Image, ImageTk
import logging

logging.basicConfig(
    level="INFO",
    format="%(asctime)s %(message)s",
    datefmt="%d-%m-%Y %H:%M:%S",
    filename="encryption.log"
)




class FileVault:
    def __init__(self, root):
        self.root = root
        self.root.title('FileVault')
        self.root.geometry('800x500')
        self.encryption = Encryption()
        self.authentication = Authentication(self.root, self)
        self.code_window = None  # Attribut für das 2FA-Fenster
        self.qr_window = None  # Attribut für das QR-Code-Fenster
        self.style = tb.Style('flatly')# Theme von TTKBootstrap Themes zum testen --> (flatly, journal,cyborg)


        # Lade das Hintergrundbild und speichere das Originalbild als PIL.Image.Image
        br_image_path = "assets/back_locked.jpg"
        self.original_image = Image.open(br_image_path)

        # Erstelle ein initiales ImageTk.PhotoImage für das Label
        self.br_image = ImageTk.PhotoImage(self.original_image)

        # Erstellen eines Labels, um das Bild im Fenster laden zu können
        self.br_label = tk.Label(root, image = self.br_image)
        self.br_label.place(relwidth=1, relheight=1)
        # Binden des <Configure>-Events, um die aktuelle Fenstergröße zu erhalten
        self.root.bind('<Configure>', self.on_resize)

        # Hauptmenü-Buttons
        self.login_button = tb.Button(root, bootstyle = SUCCESS,  text='Login', command=self.open_login_dialog)
        self.login_button.pack(pady=10, anchor ='center')


        self.register_button = tb.Button(root, text='Registrieren', bootstyle = DANGER , command=self.open_register_dialog)
        self.register_button.pack(pady=10, anchor='center')


        # Die Buttons für Verschlüsseln, Entschlüsseln und Logout, standardmäßig versteckt
        self.encrypt_button = tb.Button(root, text='Verschlüsseln', bootstyle = SUCCESS, state='disabled', command=lambda: self.process_file('encrypt'))
        self.decrypt_button = tb.Button(root, text='Entschlüsseln', bootstyle = SUCCESS, state='disabled', command=lambda: self.process_file('decrypt'))
        self.logout_button = tb.Button(root, text='Logout', bootstyle = SUCCESS, state='disabled', command=self.logout)

        # Statuslabel für den Benutzernamen
        self.status_label = tb.Label(root, text='')
        self.status_label.pack(pady=10)

    def on_resize(self, event):
        # Erhalten der neuen Fenstergröße
        new_width = event.width
        new_height = event.height

        # Skalieren des Originalbildes (PIL.Image.Image) auf die neue Fenstergröße
        scaled_image = self.original_image.resize((new_width, new_height), Image.LANCZOS)

        # Umwandeln des skalierten Bildes in ein ImageTk.PhotoImage für Tkinter
        self.br_image = ImageTk.PhotoImage(scaled_image)

        # Aktualisieren des Bildes im Label
        self.br_label.config(image=self.br_image)
        self.br_label.image = self.br_image  # Referenz sichern

    def open_login_dialog(self):
        # Öffnet das Login-Fenster.
        self.authentication.open_login_dialog(self.root, self.on_login_success)
        self.authentication.login_window.bind('<Return>',lambda event: self.authentication.login(self.on_login_success))

        # Setze den Fokus auf das Benutzernamensfeld
        self.authentication.username_entry.focus_set()

    def open_register_dialog(self):
        # Öffnet das Registrierungsfenster.
        self.authentication.open_register_dialog(self.root, self.on_register_success)
        self.authentication.register_window.bind('<Return>',
                                                 lambda event: self.authentication.register(self.on_register_success))

        # Setze den Fokus auf das Benutzernamensfeld
        self.authentication.register_username_entry.focus_set()

    def on_register_success(self, username):
        # Wird aufgerufen, wenn die Registrierung erfolgreich ist und der Authenticator verknüpft wird.
        secret = self.authentication.link_authenticator(username)  # Verknüpft den Authenticator
        self.authentication.show_authenticator_qr(secret)  # QR-Code anzeigen

    def on_qr_window_close(self):
        # Aktion beim Schließen des QR-Code-Fensters.
        if hasattr(self, 'qr_window') and self.qr_window is not None:
            self.qr_window.destroy()
            self.qr_window = None  # Setze das QR-Fenster zurück

    def on_login_success(self):
        # Wird aufgerufen, wenn die Anmeldung erfolgreich ist.
        print('Anmeldung erfolgreich')  # Debug-Ausgabe
        if self.authentication.is_2fa_linked(self.authentication.current_username):
            self.authentication.prompt_for_2fa_code(self.verify_2fa_code)  # Rufe die Methode von Authentication auf
        else:
            self.prompt_to_link_authenticator()  # Fordert den Benutzer auf, den Authenticator zu verknüpfen

    def prompt_to_link_authenticator(self):
        # Fragt den Benutzer, ob er einen Authenticator verknüpfen möchte.
        if messagebox.askyesno('2FA Verknüpfung',
                               'Ihr Konto ist nicht mit einem Authenticator verknüpft. Möchten Sie jetzt einen Authenticator verknüpfen?'):
            secret = self.authentication.link_authenticator(self.authentication.current_username)
            self.show_authenticator_qr(secret)  # QR-Code anzeigen

    def verify_2fa_code(self, code):
        # Überprüft den eingegebenen 2FA-Code.
        if self.authentication.verify_2fa_code(code):
            print('2FA-Code korrekt')  # Debug-Ausgabe
            self.authentication.code_window.destroy()  # Schließt das Fenster
            self.authentication.code_window = None  # Setze das 2FA-Fenster zurück
            self.enable_main_menu()  # Erfolgreicher Login
        else:
            print('Ungültiger 2FA-Code')  # Debug-Ausgabe
            messagebox.showerror('Fehler', 'Ungültiger 2FA-Code. Bitte versuchen Sie es erneut.')

    def enable_main_menu(self):
        # Aktiviert die Buttons nach erfolgreicher Anmeldung und Verifizierung.
        self.login_button.pack_forget()  # Versteckt den Login-Button
        self.register_button.pack_forget()  # Versteckt den Registrieren-Button

        self.logout_button.config(state='normal')  # Zeigt den Logout-Button an
        self.encrypt_button.config(state='normal')  # Zeigt den Verschlüsselungs-Button an
        self.decrypt_button.config(state='normal')  # Zeigt den Entschlüsselungs-Button an

        self.logout_button.pack(pady=10)  # Packe den Logout-Button
        self.encrypt_button.pack(pady=10)  # Packe den Verschlüsselungs-Button
        self.decrypt_button.pack(pady=10)  # Packe den Entschlüsselungs-Button

        self.status_label.config(text=f'Eingeloggt als: {self.authentication.current_username}')

        # Debug-Ausgaben zur Überprüfung der Button-Status
        print('Hauptmenü aktiviert')
        print('Logout-Button Status:', self.logout_button.winfo_ismapped())
        print('Verschlüsseln-Button Status:', self.encrypt_button.winfo_ismapped())
        print('Entschlüsseln-Button Status:', self.decrypt_button.winfo_ismapped())

    def logout(self):
        # Behandelt die Logout-Logik.
        self.authentication.current_username = None  # Setzt den aktuellen Benutzernamen zurück
        self.login_button.pack(pady=10)  # Zeigt den Login-Button wieder an
        self.register_button.pack(pady=10)  # Zeigt den Registrieren-Button wieder an
        self.logout_button.pack_forget()  # Versteckt den Logout-Button
        self.encrypt_button.pack_forget()  # Versteckt den Verschlüsselungs-Button
        self.decrypt_button.pack_forget()  # Versteckt den Entschlüsselungs-Button
        self.status_label.config(text='')  # Leert den Benutzerstatus

    def process_file(self, action):
        # Verarbeitet die Datei (Verschlüsseln oder Entschlüsseln) basierend auf der Auswahl.
        self.selected_file = filedialog.askopenfilename()
        if not self.selected_file:
            return

        # Algorithmus-Auswahl
        self.algorithm_window = tk.Toplevel(self.root)
        self.algorithm_window.title('Algorithmus auswählen')

        tk.Label(self.algorithm_window, text='Wählen Sie einen Algorithmus:').pack(pady=5)
        self.algorithm_var = tk.StringVar()
        self.algorithm_var.set('AES')  # Standardwert
        algorithm_options = ['AES', 'ChaCha20', 'Fernet', '3DES']

        # Dropdown-Menü zur Auswahl des Algorithmus
        algorithm_menu = tb.OptionMenu(self.algorithm_window, self.algorithm_var, *algorithm_options)
        algorithm_menu.pack(pady=5)

        # Passwort-Eingabefeld
        tk.Label(self.algorithm_window, text='Passwort:').pack(pady=5)
        self.password_entry = tb.Entry(self.algorithm_window, show='*')
        self.password_entry.pack(pady=5)

        # Checkbox für das Anzeigen des Passworts

        self.show_password_var = tb.BooleanVar()
        self.show_password_checkbox = tb.Checkbutton(self.algorithm_window,
                                                     text='Passwort im Klartext anzeigen',
                                                     variable=self.show_password_var,
                                                     command=self.toggle_password_visibility)
        self.show_password_checkbox.pack(pady=10)

        # Button zur Bestätigung
        tb.Button(self.algorithm_window, text='Bestätigen', command=lambda: self.process_file_action(action)).pack(
            pady=10)

    def toggle_password_visibility(self):
        # Wechselt zwischen Passwort anzeigen und verstecken.
        if self.show_password_var.get():
            self.password_entry.config(show='')  # Klartext anzeigen
        else:
            self.password_entry.config(show='*')  # Passwort verstecken

    def process_file_action(self, action):
        # Verarbeitet die Datei basierend auf der Auswahl (Verschlüsseln oder Entschlüsseln).
        password = self.password_entry.get()
        algorithm = self.algorithm_var.get()

        if action == 'encrypt':
            encrypted_file_path = self.encryption.encrypt_file(self.selected_file, password, algorithm)
            if encrypted_file_path:
                messagebox.showinfo('Erfolg', f'Datei erfolgreich verschlüsselt: {encrypted_file_path}')
                logging.info(f'Datei erfolgreich verschluesselt: {encrypted_file_path}')
        else:
            decrypted_file_path = self.encryption.decrypt_file(self.selected_file, password, algorithm)
            if decrypted_file_path:
                messagebox.showinfo('Erfolg', f'Datei erfolgreich entschlüsselt: {decrypted_file_path}')
                logging.info(f'Datei erfolgreich entschluesselt: {decrypted_file_path}')

        self.algorithm_window.destroy()  # Schließt das Auswahlfenster


if __name__ == '__main__':
    root = tk.Tk()
    file_vault = FileVault(root)
    root.mainloop()