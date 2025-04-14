from socket import *
from threading import Thread, Lock
import os
import platform
import json
from loginRegister import register, login
from datetime import datetime

with open("config.json", "r") as file:
    config = json.load(file)

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
SERV_IP_ADDR = config["SERVER_IP"]
SERV_PORT = config["SERVER_PORT"]
MAX_CLIENTS = 2

clients = {}
client_public_keys = {}
# keep every client info in dictionary
# {<socket info>:"username"}
clients_lock = Lock()

users = {}
# keep username && password
# {'Teeboy': 'pass', 'moji': '123'}

def load_users():
    global users
    if os.path.exists(config["USER_DB_FILE"]):
        with open(config["USER_DB_FILE"], "r") as file:
            for line in file:
                username, password = line.strip().split(",")
                users[username] = password

def authenticate(client_socket):
    choice = client_socket.recv(1024).decode().strip()
    if choice == "1":  # Register
        register(client_socket, users)
    elif choice == "2":  # Login
        return login(client_socket, users)
    else:
        client_socket.send(b"Invalid choice. Disconnecting...\n")
        return None

def broadcast(message, sender_socket):
    with clients_lock:
        for client in clients:
            # Skip sending the message back to the sender
            if client != sender_socket:
                try:
                    client.send(message)  # Send the message to the client
                except:
                    pass

def handle_client(client_socket, addr):
    global clients

    username = None
    while username is None:
        username = authenticate(client_socket)

    with clients_lock:
        clients[client_socket] = username

    print(f"{username} from {addr} joined the chat.")
    log_message = f"[{timestamp}] Username: {username} From IP {addr[0]} with Port {addr[1]} joined the chat.\n"
    with open("log.txt", "a") as log_file:
        log_file.write(log_message)
            
    while True:
        try:
            msg = client_socket.recv(2048)
            if not msg:
                break
            # Handle public key message
            if msg.startswith(b'PUBKEY:'):
                key_data = msg[len(b'PUBKEY:'):]
                client_public_keys[client_socket] = key_data

                # Send existing clients' keys to the new one
                with clients_lock:
                    for other_client, pubkey in client_public_keys.items():
                        if other_client != client_socket:
                            try:
                                client_socket.send(b'PUBKEY:' + pubkey)
                            except:
                                pass

                # Broadcast this new client's key to others
                broadcast(b'PUBKEY:' + key_data, client_socket)
                continue
            

            #print(f"{username}: {msg.decode()}")
            broadcast(msg, client_socket)
            # broadcast(f"{username}: {msg}", client_socket)


        except: 
            break

    with clients_lock:
        del clients[client_socket]
        client_socket.close()
        print(f"{username} disconnected.")

def main():
    load_users()
    
    server_socket = socket(AF_INET, SOCK_STREAM)

    if any(platform.win32_ver()):
        server_socket.setsockopt(SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
    else:
        server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    server_socket.bind((SERV_IP_ADDR, SERV_PORT))
    server_socket.listen(MAX_CLIENTS)

    print(f"Server started at {SERV_IP_ADDR}:{SERV_PORT}")

    while True:
        conn_sckt, cli_addr = server_socket.accept()
        
        ip, port = cli_addr
        log_message = f"[{timestamp}] IP {ip} with Port {port} connected to server\n"
        with open("log.txt", "a") as log_file:
            log_file.write(log_message)
            
        with clients_lock:
            if len(clients) >= MAX_CLIENTS:
                conn_sckt.send(b"Server full. Try again later.\n")
                conn_sckt.close()
                continue

         # Start a new thread to handle this client's communication
        try:
            Thread(target=handle_client, args=(conn_sckt, cli_addr), daemon=True).start()
        except:
            print("Cannot start thread ..")
            # Print the stack trace to understand what went wrong
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Server shutting down...")
