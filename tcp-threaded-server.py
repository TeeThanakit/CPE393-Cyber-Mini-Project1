from socket import *
from threading import Thread, Lock
import os, sys
import platform
import json

with open("config.json", "r") as file:
    config = json.load(file)

SERV_IP_ADDR = config["SERVER_IP"]
SERV_PORT = config["SERVER_PORT"]
MAX_CLIENTS = 3

clients = {}
# keep every client info in dictionary
# {<socket info>:"username"}
clients_lock = Lock()

users = {}
# keep username && password
# {'Teeboy': 'pass', 'moji': '123'}

USER_DB_FILE = "user_db.txt"

def load_users():
    global users
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, "r") as file:
            for line in file:
                username, password = line.strip().split(",")
                users[username] = password

def save_user(username, password):
    # คิดว่าจะต้อง hash password ตรงนี้ เเล้วค่อยเก็บลง txt file
    # อาจะลองgenerate key ที่จะใช้ encrypy && decrypt เเล้วเก็บไว้ใน config.json ก็ได้ ที่มันเป็น ciphertext ไม่รู้เวิคไหม
    with open(USER_DB_FILE, "a") as file:
        file.write(f"{username},{password}\n")

def authenticate(client_socket):
    
    choice = client_socket.recv(1024).decode().strip()

    if choice == "1":  # Register
        client_socket.send(b"Enter new username: ")
        username = client_socket.recv(1024).decode().strip()
        client_socket.send(b"Enter new password: ")
        password = client_socket.recv(1024).decode().strip()

        if username in users:
            client_socket.send(b"Username already exists. Try again.\n")
            return None
        else:
            users[username] = password
            save_user(username, password)
            client_socket.send(b"Registration successful. You can now login.\n")
            return None

    elif choice == "2":  # Login
        client_socket.send(b"Enter username: ")
        username = client_socket.recv(1024).decode().strip()
        client_socket.send(b"Enter password: ")
        password = client_socket.recv(1024).decode().strip()
        # คิดว่าตรงนี้จะต้อง เอารหัสที่ user input มา compare กับ hashed password ใน txt
        if username in users and users[username] == password:
            client_socket.send(b"Login successful. Welcome!\n")
            return username
        else:
            client_socket.send(b"Invalid username or password. Try again.\n")
            return None

    else:
        client_socket.send(b"Invalid choice. Disconnecting...\n")
        return None

def fistCharToUpper(message):
    decoded_message = message.decode('utf-8')
    formatted_message = decoded_message[0].upper() + decoded_message[1:]
    result = formatted_message.encode('utf-8')
    return result

def broadcast(message, sender_socket):
    with clients_lock:
        for client, uname in clients.items():
            if client != sender_socket:
                try:
                    # Change the first char to uppercase เพื่อความสวยงาม
                    if(message.decode()[0].islower()):
                        message = fistCharToUpper(message)
                    
                    client.send(message)
                except:
                    pass  # Ignore errors

def handle_client(client_socket, addr):
    global clients

    username = None
    while username is None:
        username = authenticate(client_socket)

    with clients_lock:
        clients[client_socket] = username

    print(f"{username} from {addr} joined the chat.")

    while True:
        try:
            msg = client_socket.recv(1024)
            if not msg or msg.decode().strip().lower() == "quit":
                break

            print(f"{username}: {msg.decode()}")
            broadcast(f"{username}: {msg.decode()}".encode(), client_socket)

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
        client_socket, cli_addr = server_socket.accept()

        with clients_lock:
            if len(clients) >= MAX_CLIENTS:
                client_socket.send(b"Server full. Try again later.\n")
                client_socket.close()
                continue

        Thread(target=handle_client, args=(client_socket, cli_addr)).start()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Server shutting down...")
