import sqlite3
from tkinter import Toplevel, Label, Entry, Button, messagebox


class Authentication:
	def __init__(self):
		# Verbindung zur SQLite3-Datenbank
		self.conn = sqlite3.connect('../file-vault/users.db')
		self.create_table()

	def create_table(self):
		# Erstellen der Tabelle, falls sie noch nicht existiert
		with self.conn:
			self.conn.execute('''CREATE TABLE IF NOT EXISTS users (
                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                  username TEXT NOT NULL UNIQUE,
                                  password TEXT NOT NULL)''')

		# Überprüfen, ob der Standardbenutzer existiert
		self.add_default_user()

	def add_default_user(self):
		# Fügt den Standardbenutzer "Admin" hinzu, falls er nicht existiert
		cursor = self.conn.cursor()
		cursor.execute("SELECT * FROM users WHERE username = 'Admin'")
		if cursor.fetchone() is None:
			self.conn.execute("INSERT INTO users (username, password) VALUES ('Admin', 'admin')")
			self.conn.commit()

	def open_login_register_dialog(self, root, on_login_success):
		# Erstellt ein neues Fenster für Login/Register
		login_window = Toplevel(root)
		login_window.title("Login / Register")
		login_window.geometry("300x200")

		# Benutzername-Eingabe
		Label(login_window, text="Benutzername:").pack(pady=5)
		username_entry = Entry(login_window)
		username_entry.pack(pady=5)

		# Passwort-Eingabe
		Label(login_window, text="Passwort:").pack(pady=5)
		password_entry = Entry(login_window, show="*")
		password_entry.pack(pady=5)

		# Login-Button
		login_button = Button(login_window, text="Login",
							  command=lambda: self.login(username_entry.get(), password_entry.get(), on_login_success,
														 login_window))
		login_button.pack(side="left", padx=20, pady=10)

		# Registrieren-Button
		register_button = Button(login_window, text="Registrieren",
								 command=lambda: self.register(username_entry.get(), password_entry.get()))
		register_button.pack(side="right", padx=20, pady=10)

	def login(self, username, password, on_login_success, window):
		# Überprüft Benutzername und Passwort in der Datenbank
		cursor = self.conn.cursor()
		cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
		user = cursor.fetchone()

		if user:
			messagebox.showinfo("Erfolgreich", "Login erfolgreich!")
			on_login_success()
			window.destroy()  # Schließt das Login-Fenster
		else:
			messagebox.showerror("Fehler", "Benutzername oder Passwort falsch.")

	def register(self, username, password):
		# Fügt einen neuen Benutzer in die Datenbank ein
		if not username or not password:
			messagebox.showerror("Fehler", "Benutzername und Passwort dürfen nicht leer sein.")
			return

		try:
			with self.conn:
				self.conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
				messagebox.showinfo("Erfolgreich", "Registrierung erfolgreich!")
		except sqlite3.IntegrityError:
			messagebox.showerror("Fehler", "Benutzername existiert bereits.")
