import json
import bcrypt

with open("config.json", "r") as file:
    config = json.load(file)

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def save_user(username, password):
    hashed_password = hash_password(password)  # Hash the password before storing
    with open(config["USER_DB_FILE"], "a") as file:
        file.write(f"{username},{hashed_password}\n")

def load_users():
    users = {}
    try:
        with open(config["USER_DB_FILE"], "r") as file:
            for line in file:
                username, hashed_password = line.strip().split(",")
                users[username] = hashed_password
    except FileNotFoundError:
        pass  # If file doesn't exist, return empty users dictionary
    return users

def register(client_socket, users):
    client_socket.send(b"Enter new username: ")
    username = client_socket.recv(1024).decode().strip()
    client_socket.send(b"Enter new password: ")
    password = client_socket.recv(1024).decode().strip()

    if username in users:
        client_socket.send(b"Username already exists. Try again.\n")
        return None
    else:
        users[username] = hash_password(password)
        save_user(username, password)
        client_socket.send(b"Registration successful. You can now login.\n")
        return None

def login(client_socket, users):
    client_socket.send(b"Enter username: ")
    username = client_socket.recv(1024).decode().strip()
    client_socket.send(b"Enter password: ")
    password = client_socket.recv(1024).decode().strip()

    if username in users and verify_password(password, users[username]):
        client_socket.send(b"Login successful. Welcome!\n")
        return username
    else:
        client_socket.send(b"Invalid username or password. Try again.\n")
        return None