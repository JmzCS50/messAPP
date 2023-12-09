import socket
import threading

def handle_client(client_socket):
    client_address = client_socket.getpeername()
    print(f"Handling new client: {client_address}")

    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                print(f"Client {client_address} has disconnected.")
                break
            print(f"Message received from {client_address}, broadcasting...")
            broadcast(message, client_socket)
        except Exception as e:
            print(f"Error with client {client_address}: {e}")
            break


def broadcast(message, sender_socket):
    print(f"Broadcasting message to {len(clients) - 1} clients.")
    for client in clients:
        if client is not sender_socket:
            try:
                client.send(message)
                print(f"Message sent to {client.getpeername()}")
            except Exception as e:
                print(f"Error broadcasting to {client.getpeername()}: {e}")
                client.close()
                clients.remove(client)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen()

clients = []
print("Server is running and waiting for connections...")

while True:
    try:
        client_socket, address = server_socket.accept()
        print(f"Connected with {address}")
        clients.append(client_socket)
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()
    except KeyboardInterrupt:
        print("Server is shutting down.")
        break
    except Exception as e:
        print(f"An error occurred: {e}")

for client in clients:
    client.close()
server_socket.close()
