
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import simpledialog

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class Encryption:
    def __init__(self, password):
        self.salt = b'your_predefined_salt_here'  # Use a predefined salt
        self.key = self.derive_key(password)
        
    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_message(self, plaintext):
        iv = os.urandom(12)  # AES-GCM standard IV length
        encryptor = AESGCM(self.key)
        ciphertext = encryptor.encrypt(iv, plaintext.encode(), None)
        return iv + ciphertext

    def decrypt_message(self, ciphertext):
        iv = ciphertext[:12]  # Extract the IV
        encryptor = AESGCM(self.key)
        plaintext = encryptor.decrypt(iv, ciphertext[12:], None)
        return plaintext.decode()

class ChatClient:
    def __init__(self, master, password):
        self.master = master
        master.title("Chat Client")

        self.encryption = Encryption(password)  # Encryption instance

        self.text_area = scrolledtext.ScrolledText(master, state='disabled')
        self.text_area.grid(row=0, column=0, columnspan=2)

        self.message_entry = tk.Entry(master)
        self.message_entry.grid(row=1, column=0)

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1)

        self.setup_socket()
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

    def setup_socket(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('localhost', 12345))

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    print("No message received, exiting.")
                    break
                message = self.encryption.decrypt_message(encrypted_message)

                # Display received ciphertext and decrypted message
                self.display_message("Received (Ciphertext): " + encrypted_message.hex())
                self.display_message("Received (Plaintext): " + message)
            except Exception as e:
                print("An error occurred in receive_messages:", e)
                break




    def send_message(self):
        try:
            message = self.message_entry.get()
            if message:
                encrypted_message = self.encryption.encrypt_message(message)
                self.client_socket.send(encrypted_message)
                self.message_entry.delete(0, tk.END)

                # Display sent ciphertext
                self.display_message("Sent (Ciphertext): " + encrypted_message.hex())
        except OSError as e:
            print("Error sending message:", e)


    def close_socket(self):
        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None

    def on_closing(self):
        self.close_socket()
        self.master.destroy()



    def display_message(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, message + '\n')
        self.text_area.config(state='disabled')


if __name__ == "__main__":
    root = tk.Tk()
    password = simpledialog.askstring("Password", "Enter shared password:", parent=root)
    if password:
        chat_client = ChatClient(root, password)
        root.protocol("WM_DELETE_WINDOW", chat_client.on_closing)  # Handle window closing
        root.mainloop()