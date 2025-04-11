import json
import bcrypt
from crypto_utils import aes_decrypt, rsa_decrypt

with open("config.json", "r") as file:
    config = json.load(file)

#### ใช้ เซฟข้อมูล user ลงใน database ตอน register
def save_user(username, password):
    # คิดว่าจะต้อง hash password ตรงนี้ เเล้วค่อยเก็บลง txt file
    with open(config["USER_DB_FILE"], "a") as file:
        file.write(f"{username},{password}\n")

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
# client_socket เก็บข้อมูลของ client src-des ip, protocol etc.
# users เก็บข้อมูลที่อยู่ใน user_db.txt
def register(client_socket, users, private_key):
    client_socket.send(b"Enter new username: ") # ส่ง Prompt ให้ กรอก username ไปยัง client_socket
    username = client_socket.recv(1024) # รอรับข้อความจาก client_socket
    username = decryptMessage(username, private_key) #ถอดรหัสข้อความ AES ที่ถูก encrypt ซ้อนมาด้วย publick key ของ server

    client_socket.send(b"Enter new password: ")
    password = client_socket.recv(1024)
    password = decryptMessage(password, private_key)

    if username in users: #### เช็คว่า username ซ้ำมั้ยจาก global variable users{} ที่กำหนดไว้ใน tcp-threaded-server ### ​!!! ควรแก้ !!! 
        client_socket.send(b"Username already exists. Try again.\n")
        return None
    else:
        users[username] = password
        save_user(username, password) ### เรียก function "save_user" เพื่อเซฟลง database
        client_socket.send(b"Registration successful. You can now login.\n")
        return None
    
### ใช้สหรับ login 
def login(client_socket, users, private_key):
    client_socket.send(b"Enter username: ") # ส่ง Prompt ให้ กรอก username ไปยัง client_socket
    username = client_socket.recv(1024) # รอรับข้อความจาก client_socket
    username = decryptMessage(username, private_key) #ถอดรหัสข้อความ AES ที่ถูก encrypt ซ้อนมาด้วย public key ของ server
    
    client_socket.send(b"Enter password: ")
    password = client_socket.recv(1024)
    password = decryptMessage(password, private_key)

    # คิดว่าตรงนี้จะต้องแก้ ให้เอารหัสที่ user input มา compare กับ hashed password ใน txt ไม่ใช่จาก global variable users{}
    if username in users and users[username] == password:
        client_socket.send(b"Login successful. Welcome!\n")
        return username
    else:
        client_socket.send(b"Invalid username or password. Try again.\n")
        return None
    

### ใช้ถอดรหัสข้อความ จาก client ที่ส่งมาเป็น -> SERVER_Public_Key(Client_AES_Key(ข้อความจริงๆ))
def decryptMessage(msg, private_key):
    # Decrypt Message
    if msg.startswith(b'ENC:'):
        try:            
            payload = msg[len(b'ENC:'):]
            encrypted_key, encrypted_msg = payload.split(b'||')  ### แยกระหว่าง encrypted AES key กับ encrypted AES message 
            
            aes_key = rsa_decrypt(private_key, encrypted_key) # ถอดรหัส encrypted AES key ด้วย private key ของ server (เพราะ client ส่งข้อความาเป็น AES key ที่ encrypted ซ้อนด้วย public key ของ server)
            plain_msg = aes_decrypt(aes_key, encrypted_msg) # ถอดรหัส encrypted AES message ด้วย AES key ที่ถอดรหัสออกมาได้

            return plain_msg
        except Exception as e:
            return None