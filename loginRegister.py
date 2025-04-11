import json
import bcrypt

# Load config
with open("config.json", "r") as file:
    config = json.load(file)

def save_user(username, hashed_password):
    # Convert bytes to string if necessary
    hashed_str = hashed_password.decode()

    # Split hash into 3 roughly equal parts
    length = len(hashed_str)
    part1 = hashed_str[:length // 3]
    part2 = hashed_str[length // 3: 2 * length // 3]
    part3 = hashed_str[2 * length // 3:]

    # Save each part into separate files
    with open("usernames.txt", "a") as uf, \
         open("part1.txt", "a") as p1f, \
         open("part2.txt", "a") as p2f, \
         open("part3.txt", "a") as p3f:

        uf.write(f"{username}\n")
        p1f.write(f"{part1}\n")
        p2f.write(f"{part2}\n")
        p3f.write(f"{part3}\n")

def load_users():
    users = {}
    try:
        with open("usernames.txt") as uf, \
             open("part1.txt") as p1f, \
             open("part2.txt") as p2f, \
             open("part3.txt") as p3f:

            for u, p1, p2, p3 in zip(uf, p1f, p2f, p3f):
                username = u.strip()
                full_hash = (p1.strip() + p2.strip() + p3.strip())
                users[username] = full_hash.encode()
    except FileNotFoundError:
        pass
    return users

users = load_users()

# Register function
def register(client_socket, users):
    client_socket.send(b"Enter new username: ")
    username = client_socket.recv(1024).decode().strip()
    client_socket.send(b"Enter new password: ")
    password = client_socket.recv(1024).decode().strip()

    if username in users:
        client_socket.send(b"Username already exists. Try again.\n")
        return None
    else:
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        users[username] = hashed_password  # store hashed password in memory
        save_user(username, hashed_password)
        client_socket.send(b"Registration successful. You can now login.\n")
        return None

# Login function
def login(client_socket, users):
    client_socket.send(b"Enter username: ")
    username = client_socket.recv(1024).decode().strip()
    client_socket.send(b"Enter password: ")
    password = client_socket.recv(1024).decode().strip()

    if username in users and bcrypt.checkpw(password.encode(), users[username]):
        client_socket.send(b"Login successful. Welcome!\n")
        return username
    else:
        client_socket.send(b"Invalid username or password. Try again.\n")
        return None
