import json
from crypto_utils import aes_decrypt, rsa_decrypt

with open("config.json", "r") as file:
    config = json.load(file)

def save_user(username, password):
    # คิดว่าจะต้อง hash password ตรงนี้ เเล้วค่อยเก็บลง txt file
    # อาจะลองgenerate key ที่จะใช้ encrypy && decrypt เเล้วเก็บไว้ใน config.json ก็ได้ ที่มันเป็น ciphertext ไม่รู้เวิคไหม
    with open(config["USER_DB_FILE"], "a") as file:
        file.write(f"{username},{password}\n")

# client_socket เก็บข้อมูลของ client src-des ip, protocol etc.
# users เก็บข้อมูลที่อยู่ใน user_db.txt
def register(client_socket, users, private_key):
    client_socket.send(b"Enter new username: ")
    username = client_socket.recv(1024)
    username = decryptMessage(username, private_key)

    client_socket.send(b"Enter new password: ")
    password = client_socket.recv(1024)
    password = decryptMessage(password, private_key)

    if username in users:
        client_socket.send(b"Username already exists. Try again.\n")
        return None
    else:
        users[username] = password
        save_user(username, password)
        client_socket.send(b"Registration successful. You can now login.\n")
        return None
    
def login(client_socket, users, private_key):
    client_socket.send(b"Enter username: ")
    username = client_socket.recv(1024)
    username = decryptMessage(username, private_key)
    
    client_socket.send(b"Enter password: ")
    password = client_socket.recv(1024)
    password = decryptMessage(password, private_key)

    # คิดว่าตรงนี้จะต้อง เอารหัสที่ user input มา compare กับ hashed password ใน txt
    if username in users and users[username] == password:
        client_socket.send(b"Login successful. Welcome!\n")
        return username
    else:
        client_socket.send(b"Invalid username or password. Try again.\n")
        return None

def decryptMessage(msg, private_key):
    #Decrypt Message
    if msg.startswith(b'ENC:'):
        try:            
            payload = msg[len(b'ENC:'):]
            encrypted_key, encrypted_msg = payload.split(b'||')
            
            aes_key = rsa_decrypt(private_key, encrypted_key)  # use own private key
            print(aes_key)
            plain_msg = aes_decrypt(aes_key, encrypted_msg)

            return plain_msg
        except Exception as e:
            return None