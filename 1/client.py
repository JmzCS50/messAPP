import socket
import threading
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
        # ... rest of the class ...


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
    
  
def receive_messages():
    while not exit_flag.is_set():
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print("No message received.")
                continue  # Continue listening instead of breaking the loop
            message = encryption.decrypt_message(encrypted_message)
            print(message)
        except Exception as e:
            print("An error occurred in receive_messages:", e)

def send_messages():
    while True:
        message = input("Enter message ('exit' to quit): ")
        if message.lower() == 'exit':
            exit_flag.set()  # Signal that exit is requested
            break
        encrypted_message = encryption.encrypt_message(message)
        client_socket.send(encrypted_message)

# Initialize socket and encryption
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))
password = input("Enter shared password: ")
encryption = Encryption(password)

# Exit flag for graceful thread termination
exit_flag = threading.Event()

# Start receiving thread
thread = threading.Thread(target=receive_messages)
thread.start()

# Start sending messages and handle exit
send_messages()

# Close the socket when exiting
client_socket.close()
print("Connection closed.")