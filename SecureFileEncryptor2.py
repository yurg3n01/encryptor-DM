import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives import hashes, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap


class KeyManager:
    def generate_key(self, key_size=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        return private_key

    def save_key_to_file(self, key, filename):
        with open(filename, "wb") as key_file:
            key_bytes = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            key_file.write(key_bytes)

    def load_key_from_file(self, filename):
        with open(filename, "rb") as key_file:
            key_bytes = key_file.read()
            private_key = serialization.load_pem_private_key(
                key_bytes, password=None, backend=default_backend())
            return private_key


def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key


class SecureFileEncryptorGUI:
    translations = {
        "Select a file to encrypt:": "Выберите файл для шифрования:",
        "Select a file to decrypt:": "Выберите файл для дешифрования:",
        "Enter password:": "Введите пароль:",
        "Generate Key": "Создать ключ",
        "Save Key": "Сохранить ключ",
        "Load Key": "Загрузить ключ",
    }

    algorithms = [
        "AES", "RSA"
    ]

    def __init__(self, master):
        self.master = master
        self.master.title("Secure File Encryptor")
        self.master.configure(bg='black')
        self.file_path = ""
        self.algorithm = tk.StringVar(value=self.algorithms[0])
        self.key_manager = KeyManager()
        self.log_file = "encryption_log.txt"
        self.create_widgets()

    def create_widgets(self):
        tk.Label(
            self.master, text=self.translations["Select a file to encrypt:"], fg="blue", bg="black").grid(row=0, column=1)

        self.file_label = tk.Label(
            self.master, text="", fg="blue", bg="black")
        self.file_label.grid(row=1, column=1)

        self.file_button = tk.Button(
            self.master, text="Choose File", command=self.choose_file, fg="blue", bg="black")
        self.file_button.grid(row=2, column=1)

        self.algorithm_label = tk.Label(
            self.master, text="Choose Algorithm:", fg="blue", bg="black")
        self.algorithm_label.grid(row=3, column=1)

        self.algorithm_menu = tk.OptionMenu(
            self.master, self.algorithm, *self.algorithms)
        self.algorithm_menu.config(bg='black', fg='blue')
        self.algorithm_menu.grid(row=4, column=1)

        self.encrypt_button = tk.Button(
            self.master, text="Encrypt", command=self.encrypt_file, fg="blue", bg="black")
        self.encrypt_button.grid(row=5, column=1)

        self.decrypt_button = tk.Button(
            self.master, text="Decrypt", command=self.decrypt_file, fg="blue", bg="black")
        self.decrypt_button.grid(row=6, column=1)

        self.generate_key_button = tk.Button(
            self.master, text=self.translations["Generate Key"], command=self.generate_key, fg="blue", bg="black")
        self.generate_key_button.grid(row=7, column=1)

        self.save_key_button = tk.Button(
            self.master, text=self.translations["Save Key"], command=self.save_key, fg="blue", bg="black")
        self.save_key_button.grid(row=8, column=1)

        self.load_key_button = tk.Button(
            self.master, text=self.translations["Load Key"], command=self.load_key, fg="blue", bg="black")
        self.load_key_button.grid(row=9, column=1)

        # Добавляем изображение
        self.image = tk.PhotoImage(
            file=r"C:\Users\Admin\Desktop\Code\fone.png")
        self.image_label = tk.Label(self.master, image=self.image, bg='black')
        self.image_label.grid(row=1, column=0, rowspan=11)

    def choose_file(self):
        self.file_path = filedialog.askopenfilename(initialdir="/", title=self.translations["Select a file to encrypt:"],
                                                    filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if self.file_path:
            self.file_label.config(text=os.path.basename(self.file_path))
            self.get_password()

    def get_password(self):
        password = simpledialog.askstring(
            "Password", self.translations["Enter password:"], show="*")
        if password:
            self.password = password
            self.perform_operation()

    def generate_key(self):
        key_size = simpledialog.askinteger(
            "Key Size", "Enter key size (in bits):", initialvalue=2048)
        if key_size:
            key = self.key_manager.generate_key(key_size)
            self.generated_key = key
            messagebox.showinfo(
                "Key Generated", "New key generated successfully.")
        else:
            messagebox.showerror("Error", "Invalid key size.")

    def save_key(self):
        if hasattr(self, 'generated_key'):
            filename = filedialog.asksaveasfilename(defaultextension=".pem")
            if filename:
                self.key_manager.save_key_to_file(self.generated_key, filename)
                messagebox.showinfo(
                    "Key Saved", f"Key saved to {filename} successfully.")
        else:
            messagebox.showerror(
                "Error", "No key to save. Generate a key first.")

    def load_key(self):
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem")])
        if filename:
            self.loaded_key = self.key_manager.load_key_from_file(filename)
            messagebox.showinfo(
                "Key Loaded", f"Key loaded from {filename} successfully.")

    def encrypt_file(self):
        self.operation = "encrypt"
        self.choose_file()

    def decrypt_file(self):
        self.operation = "decrypt"
        self.choose_file()

    def perform_operation(self):
        algorithm = self.algorithm.get()
        if self.operation == "encrypt":
            success = self.perform_encryption(
                self.file_path, self.password, algorithm)
        elif self.operation == "decrypt":
            success = self.perform_decryption(
                self.file_path, self.password, algorithm)
        if success:
            messagebox.showinfo("Success", "Operation completed successfully.")
        else:
            messagebox.showerror("Error", "Operation failed.")

    def perform_encryption(self, input_file, password, algorithm='AES'):
        try:
            output_file = input_file + ".enc"
            if os.path.exists(output_file):
                messagebox.showerror("Error", "Output file already exists.")
                return False

            salt = os.urandom(16)
            key = generate_key_from_password(password, salt)
            iv = os.urandom(16)

            if algorithm == 'AES':
                cipher = Cipher(algorithms.AES(key), modes.CFB(
                    iv), backend=default_backend())
            elif algorithm == 'RSA':
                if not hasattr(self, 'generated_key'):
                    messagebox.showerror(
                        "Error", "No RSA key generated. Generate a key first.")
                    return False
                public_key = self.generated_key.public_key()
                wrapped_key = public_key.encrypt(
                    key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                with open(input_file, "rb") as file:
                    plaintext = file.read()

                encryptor = Cipher(algorithms.AES(key), modes.CFB(
                    iv), backend=default_backend()).encryptor()
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()

                with open(output_file, "wb") as file:
                    file.write(salt + iv + wrapped_key + ciphertext)
                return True

            with open(input_file, "rb") as file:
                plaintext = file.read()

            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            with open(output_file, "wb") as file:
                file.write(salt)
                file.write(iv)
                file.write(ciphertext)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            return False

    def perform_decryption(self, input_file, password, algorithm='AES'):
        try:
            output_file = os.path.splitext(input_file)[0]
            if os.path.exists(output_file):
                messagebox.showerror("Error", "Output file already exists.")
                return False

            with open(input_file, "rb") as file:
                salt = file.read(16)
                iv = file.read(16)
                ciphertext = file.read()

            key = generate_key_from_password(password, salt)

            if algorithm == 'AES':
                cipher = Cipher(algorithms.AES(key), modes.CFB(
                    iv), backend=default_backend())
            elif algorithm == 'RSA':
                if not hasattr(self, 'loaded_key'):
                    messagebox.showerror(
                        "Error", "No RSA key loaded. Load a key first.")
                    return False
                wrapped_key = ciphertext[:256]
                ciphertext = ciphertext[256:]
                key = self.loaded_key.decrypt(
                    wrapped_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                cipher = Cipher(algorithms.AES(key), modes.CFB(
                    iv), backend=default_backend())

            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            with open(output_file, "wb") as file:
                file.write(plaintext)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            return False


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileEncryptorGUI(root)
    root.mainloop()
