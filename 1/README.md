# This is a Python-based secure chat application enabling encrypted communication between two users. It combines AES-256 encryption, socket programming, and a user-friendly GUI.

# Author: Iakov Maslovskiy

# How to run: 

1. Open the terminal.
2. Navigate to the directory. 
3. Install dependencies.

Tkinter: Usually comes pre-installed with Python.

Socket and Threading: These are part of the Python Standard Library

pip install cryptography

4. Start the server. 

python server.py

5. Run client instances. Open up two separate terminals and run the command on both. 

python client_gui.py

# Configuration 

The server listens on port 12345 (modifiable in server.py).
After running the application, the user is promted to enter the password. It MUST be the same for users to be able to decrypt messages. 
After entering the password, the users are then able to communicate securely. 

# Usage notes

Launch server script before client scripts.
Enter a shared password upon client launch.
Start secure messaging between clients.
