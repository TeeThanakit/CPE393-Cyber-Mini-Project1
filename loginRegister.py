import json

with open("config.json", "r") as file:
    config = json.load(file)

def save_user(username, password):
    # คิดว่าจะต้อง hash password ตรงนี้ เเล้วค่อยเก็บลง txt file
    # อาจะลองgenerate key ที่จะใช้ encrypy && decrypt เเล้วเก็บไว้ใน config.json ก็ได้ ที่มันเป็น ciphertext ไม่รู้เวิคไหม
    with open(config["USER_DB_FILE"], "a") as file:
        file.write(f"{username},{password}\n")

def register(client_socket, users):
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
    
def login(client_socket, users):
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