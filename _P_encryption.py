import os
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

class Encryption:
    def __init__(self):
        """Initialisiert die Encryption-Klasse und erstellt die Datenbank."""
        self.init_db()  # Initialisiert die SQLite-Datenbank

    def init_db(self):
        """Initialisiert die SQLite-Datenbank und erstellt die Tabelle für Passwörter, falls sie nicht existiert."""
        self.conn = sqlite3.connect('users.db')  # Verbindet oder erstellt die Datenbank
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS passwords 
                          (id INTEGER PRIMARY KEY, algorithm TEXT, salt BLOB, hash BLOB)''')  # Erstellt die Tabelle für Passwort-Hashes
        self.conn.commit()  # Speichert die Änderungen in der Datenbank

    def save_password_hash(self, password, algorithm):
        """Speichert den Passwort-Hash und den Salt-Wert in der Datenbank für einen bestimmten Algorithmus."""
        cursor = self.conn.cursor()
        salt = os.urandom(16)  # Generiert einen zufälligen Salt von 16 Byte
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Verwendet SHA-256 als Hash-Algorithmus
            length=32,  # Länge des abgeleiteten Schlüssels in Bytes
            salt=salt,  # Der zuvor generierte Salt
            iterations=100000,  # Anzahl der Iterationen für die Schlüsselableitung
        )
        key = kdf.derive(password.encode())  # Leitet den Schlüssel aus dem Passwort ab

        # Fügt den Algorithmus, den Salt und den Hash in die Datenbank ein
        cursor.execute("INSERT INTO passwords (algorithm, salt, hash) VALUES (?, ?, ?)", (algorithm, salt, key))
        self.conn.commit()  # Speichert die Änderungen in der Datenbank

    def load_password_hash(self, algorithm):
        """Lädt den Salt-Wert und den Hash für einen bestimmten Algorithmus aus der Datenbank."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT salt, hash FROM passwords WHERE algorithm=?", (algorithm,))
        result = cursor.fetchone()  # Holt den ersten Treffer aus der Datenbank
        return (result[0], result[1]) if result else (None, None)  # Gibt Salt und Hash zurück oder None

    def encrypt_file(self, file_path, password, algorithm):
        """Verschlüsselt eine Datei basierend auf dem angegebenen Algorithmus."""
        if algorithm not in ['AES', 'ChaCha20', 'Fernet', '3DES']:
            raise ValueError("Unsupported algorithm")  # Überprüft, ob der Algorithmus unterstützt wird

        # Ruft die entsprechende Verschlüsselungsmethode auf
        if algorithm == 'AES':
            return self.encrypt_with_aes(file_path, password)
        elif algorithm == 'ChaCha20':
            return self.encrypt_with_chacha20(file_path, password)
        elif algorithm == 'Fernet':
            return self.encrypt_with_fernet(file_path, password)
        elif algorithm == '3DES':
            return self.encrypt_with_3des(file_path, password)

    def decrypt_file(self, file_path, password, algorithm):
        """Entschlüsselt eine Datei basierend auf dem angegebenen Algorithmus."""
        # Ruft die entsprechende Entschlüsselungsmethode auf
        if algorithm == 'AES':
            return self.decrypt_with_aes(file_path, password)
        elif algorithm == 'ChaCha20':
            return self.decrypt_with_chacha20(file_path, password)
        elif algorithm == 'Fernet':
            return self.decrypt_with_fernet(file_path, password)
        elif algorithm == '3DES':
            return self.decrypt_with_3des(file_path, password)

    # AES-Verschlüsselung
    def encrypt_with_aes(self, file_path, password):
        """Verschlüsselt eine Datei mit dem AES-Algorithmus."""
        salt, key = self.load_password_hash('AES')  # Lädt den Salt und den Hash aus der Datenbank
        if not key:  # Wenn kein Hash vorhanden ist
            self.save_password_hash(password, 'AES')  # Speichert den Hash und Salt in der Datenbank
            salt, key = self.load_password_hash('AES')

        # Erstellt einen Schlüssel aus dem Passwort und Salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())  # Leitet den Schlüssel aus dem Passwort ab
        iv = os.urandom(16)  # Generiert einen Initialisierungsvektor (IV) von 16 Byte
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())

        with open(file_path, 'rb') as f:
            file_data = f.read()  # Liest die Datei, die verschlüsselt werden soll

        encryptor = cipher.encryptor()  # Erstellt einen Verschlüsselungs-Objekt
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()  # Verschlüsselt die Datei

        encrypted_file_path = file_path + '.aes'  # Fügt die Dateierweiterung für verschlüsselte Dateien hinzu
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + encrypted_data)  # Speichert IV und verschlüsselte Daten in der neuen Datei

        os.remove(file_path)  # Löscht die ursprüngliche Datei
        return encrypted_file_path  # Gibt den Pfad zur verschlüsselten Datei zurück

    def decrypt_with_aes(self, file_path, password):
        """Entschlüsselt eine mit AES verschlüsselte Datei."""
        salt, key = self.load_password_hash('AES')  # Lädt den Salt und den Hash aus der Datenbank
        if not key:  # Wenn kein Hash vorhanden ist
            return False  # Entschlüsselung kann nicht durchgeführt werden

        # Erstellt einen Schlüssel aus dem Passwort und Salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())  # Leitet den Schlüssel aus dem Passwort ab

        with open(file_path, 'rb') as f:
            iv = f.read(16)  # Liest den IV von der verschlüsselten Datei
            encrypted_data = f.read()  # Liest die verschlüsselten Daten

        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()  # Erstellt einen Entschlüsselungs-Objekt
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()  # Entschlüsselt die Daten

        decrypted_file_path = file_path.replace('.aes', '')  # Entfernt die Dateierweiterung
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)  # Speichert die entschlüsselten Daten in einer neuen Datei

        os.remove(file_path)  # Löscht die verschlüsselte Datei
        return decrypted_file_path  # Gibt den Pfad zur entschlüsselten Datei zurück

    # ChaCha20-Verschlüsselung
    def encrypt_with_chacha20(self, file_path, password):
        """Verschlüsselt eine Datei mit dem ChaCha20-Algorithmus."""
        salt, key = self.load_password_hash('ChaCha20')  # Lädt den Salt und den Hash aus der Datenbank
        if not key:  # Wenn kein Hash vorhanden ist
            self.save_password_hash(password, 'ChaCha20')  # Speichert den Hash und Salt in der Datenbank
            salt, key = self.load_password_hash('ChaCha20')

        # Erstellt einen Schlüssel aus dem Passwort und Salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())  # Leitet den Schlüssel aus dem Passwort ab
        nonce = os.urandom(16)  # Generiert einen zufälligen Nonce von 16 Byte

        cipher = Cipher(algorithms.ChaCha20(derived_key, nonce), mode=None, backend=default_backend())

        with open(file_path, 'rb') as f:
            file_data = f.read()  # Liest die Datei, die verschlüsselt werden soll

        encryptor = cipher.encryptor()  # Erstellt einen Verschlüsselungs-Objekt
        encrypted_data = encryptor.update(file_data)  # Verschlüsselt die Datei

        encrypted_file_path = file_path + '.chacha20'  # Fügt die Dateierweiterung für verschlüsselte Dateien hinzu
        with open(encrypted_file_path, 'wb') as f:
            f.write(nonce + encrypted_data)  # Speichert Nonce und verschlüsselte Daten in der neuen Datei

        os.remove(file_path)  # Löscht die ursprüngliche Datei
        return encrypted_file_path  # Gibt den Pfad zur verschlüsselten Datei zurück

    def decrypt_with_chacha20(self, file_path, password):
        """Entschlüsselt eine mit ChaCha20 verschlüsselte Datei."""
        salt, key = self.load_password_hash('ChaCha20')  # Lädt den Salt und den Hash aus der Datenbank
        if not key:  # Wenn kein Hash vorhanden ist
            return False  # Entschlüsselung kann nicht durchgeführt werden

        # Erstellt einen Schlüssel aus dem Passwort und Salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())  # Leitet den Schlüssel aus dem Passwort ab

        with open(file_path, 'rb') as f:
            nonce = f.read(16)  # Liest den Nonce von der verschlüsselten Datei
            encrypted_data = f.read()  # Liest die verschlüsselten Daten

        cipher = Cipher(algorithms.ChaCha20(derived_key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()  # Erstellt einen Entschlüsselungs-Objekt
        decrypted_data = decryptor.update(encrypted_data)  # Entschlüsselt die Daten

        decrypted_file_path = file_path.replace('.chacha20', '')  # Entfernt die Dateierweiterung
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)  # Speichert die entschlüsselten Daten in einer neuen Datei

        os.remove(file_path)  # Löscht die verschlüsselte Datei
        return decrypted_file_path  # Gibt den Pfad zur entschlüsselten Datei zurück

    # Fernet-Verschlüsselung
    def encrypt_with_fernet(self, file_path, password):
        """Verschlüsselt eine Datei mit dem Fernet-Algorithmus."""
        salt, key = self.load_password_hash('Fernet')  # Lädt den Salt und den Hash aus der Datenbank
        if not key:  # Wenn kein Hash vorhanden ist
            self.save_password_hash(password, 'Fernet')  # Speichert den Hash und Salt in der Datenbank
            salt, key = self.load_password_hash('Fernet')

        # Erstellt einen Schlüssel aus dem Passwort und Salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())  # Leitet den Schlüssel aus dem Passwort ab
        fernet_key = base64.urlsafe_b64encode(derived_key)  # Erzeugt den Fernet-Schlüssel
        fernet = Fernet(fernet_key)  # Erstellt ein Fernet-Objekt

        with open(file_path, 'rb') as f:
            file_data = f.read()  # Liest die Datei, die verschlüsselt werden soll

        encrypted_data = fernet.encrypt(file_data)  # Verschlüsselt die Datei

        encrypted_file_path = file_path + '.fernet'  # Fügt die Dateierweiterung für verschlüsselte Dateien hinzu
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)  # Speichert die verschlüsselten Daten in der neuen Datei

        os.remove(file_path)  # Löscht die ursprüngliche Datei
        return encrypted_file_path  # Gibt den Pfad zur verschlüsselten Datei zurück

    def decrypt_with_fernet(self, file_path, password):
        """Entschlüsselt eine mit Fernet verschlüsselte Datei."""
        salt, key = self.load_password_hash('Fernet')  # Lädt den Salt und den Hash aus der Datenbank
        if not key:  # Wenn kein Hash vorhanden ist
            return False  # Entschlüsselung kann nicht durchgeführt werden

        # Erstellt einen Schlüssel aus dem Passwort und Salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())  # Leitet den Schlüssel aus dem Passwort ab
        fernet_key = base64.urlsafe_b64encode(derived_key)  # Erzeugt den Fernet-Schlüssel
        fernet = Fernet(fernet_key)  # Erstellt ein Fernet-Objekt

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()  # Liest die verschlüsselten Daten

        decrypted_data = fernet.decrypt(encrypted_data)  # Entschlüsselt die Daten

        decrypted_file_path = file_path.replace('.fernet', '')  # Entfernt die Dateierweiterung
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)  # Speichert die entschlüsselten Daten in einer neuen Datei

        os.remove(file_path)  # Löscht die verschlüsselte Datei
        return decrypted_file_path  # Gibt den Pfad zur entschlüsselten Datei zurück

    # 3DES-Verschlüsselung
    def encrypt_with_3des(self, file_path, password):
        """Verschlüsselt eine Datei mit dem 3DES-Algorithmus."""
        salt, key = self.load_password_hash('3DES')  # Lädt den Salt und den Hash aus der Datenbank
        if not key:  # Wenn kein Hash vorhanden ist
            self.save_password_hash(password, '3DES')  # Speichert den Hash und Salt in der Datenbank
            salt, key = self.load_password_hash('3DES')

        # Erstellt einen Schlüssel aus dem Passwort und Salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=24,  # 3DES benötigt 24 Byte Schlüssel
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())  # Leitet den Schlüssel aus dem Passwort ab
        iv = os.urandom(8)  # 3DES benötigt 8 Byte IV
        cipher = Cipher(algorithms.TripleDES(derived_key), modes.CFB(iv), backend=default_backend())

        with open(file_path, 'rb') as f:
            file_data = f.read()  # Liest die Datei, die verschlüsselt werden soll

        encryptor = cipher.encryptor()  # Erstellt einen Verschlüsselungs-Objekt
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()  # Verschlüsselt die Datei

        encrypted_file_path = file_path + '.3des'  # Fügt die Dateierweiterung für verschlüsselte Dateien hinzu
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + encrypted_data)  # Speichert IV zusammen mit den verschlüsselten Daten

        os.remove(file_path)  # Löscht die ursprüngliche Datei
        return encrypted_file_path  # Gibt den Pfad zur verschlüsselten Datei zurück

    def decrypt_with_3des(self, file_path, password):
        """Entschlüsselt eine mit 3DES verschlüsselte Datei."""
        salt, key = self.load_password_hash('3DES')  # Lädt den Salt und den Hash aus der Datenbank
        if not key:  # Wenn kein Hash vorhanden ist
            return False  # Entschlüsselung kann nicht durchgeführt werden

        # Erstellt einen Schlüssel aus dem Passwort und Salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=24,  # 3DES benötigt 24 Byte Schlüssel
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())  # Leitet den Schlüssel aus dem Passwort ab

        with open(file_path, 'rb') as f:
            iv = f.read(8)  # 3DES benötigt 8 Byte IV
            encrypted_data = f.read()  # Liest die verschlüsselten Daten

        cipher = Cipher(algorithms.TripleDES(derived_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()  # Erstellt einen Entschlüsselungs-Objekt
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()  # Entschlüsselt die Daten

        decrypted_file_path = file_path.replace('.3des', '')  # Entfernt die Dateierweiterung
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)  # Speichert die entschlüsselten Daten in einer neuen Datei

        os.remove(file_path)  # Löscht die verschlüsselte Datei
        return decrypted_file_path  # Gibt den Pfad zur entschlüsselten Datei zurück
