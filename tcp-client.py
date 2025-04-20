from socket import *
import sys
import threading
from helper import fistCharToUpperClient
import json
from crypto_utils import (generate_aes_key, aes_encrypt, aes_decrypt,
                          rsa_encrypt, rsa_decrypt, generate_rsa_keypair,
                          serialize_public_key, load_public_key)

private_key, public_key = generate_rsa_keypair()
serialized_pubkey = serialize_public_key(public_key)

with open("config.json", "r") as file:
    config = json.load(file)
    
SERV_SOCK_ADDR = (config["SERVER_IP"], config["SERVER_PORT"])
cli_sock = socket(AF_INET, SOCK_STREAM)


# เก็บ other client public key ไว้ใช้เข้ารหัสข้อความทั่วไปเวลาแชท
public_keys = {}
# เก็บ server public key ไว้ใช้เข้ารหัสข้อความแค่ตอน login/register
server_public_keys = {}
# Maximum size (in bytes) for receiving messages
MAX_BUF = 2048


######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########
######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########
######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########
######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########
######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########


### ใช้เข้ารหัสข้อความ choice, username, password ที่จะส่งไปให้ server ตอน login/register เท่านั้น!!
def encryptedKeyAndMessageForAuthentication(message):
    if 'server' in server_public_keys: #เช็คว่าได้รับ public key ของ server มาหรือยัง
        server_pubkey = server_public_keys['server']
        key = generate_aes_key() # สร้าง AES KEY
        encrypted_key = rsa_encrypt(server_pubkey, key) # ใช้ public key ของ server เพื่อเข้ารหัส AES key
        encrypted_msg = aes_encrypt(key, message) # เข้ารหัสข้อความ ด้วย AES Key ของตัวเอง

        return (b'ENC:' + encrypted_key + b'||' + encrypted_msg)
    else:
        return None

### ใช้ register
def register():
    cli_sock.send(encryptedKeyAndMessageForAuthentication("1")) # ส่ง encrypt message ว่าเลือกช้อย 1 ไปหา server
    print(cli_sock.recv(1024).decode(), end="") # print สื่งที่ server ส่งตอบกลับมาบน console
    username = input() # ให้ user input username
    cli_sock.send(encryptedKeyAndMessageForAuthentication(username)) # ส่ง encrypt message (username) ไปยัง server

    print(cli_sock.recv(1024).decode(), end="") # print สื่งที่ server ส่งตอบกลับมาบน console
    password = input() 
    cli_sock.send(encryptedKeyAndMessageForAuthentication(password)) # ส่ง encrypt message (password) ไปยัง server

    print(cli_sock.recv(1024).decode())


### ใช้ login
def login():
    cli_sock.send(encryptedKeyAndMessageForAuthentication("2"))  # ส่ง encrypt message ว่าเลือกช้อย 2 ไปหา server
    print(cli_sock.recv(1024).decode(), end="") # print สื่งที่ server ส่งตอบกลับมาบน console
    username = input() # ให้ user input username
    cli_sock.send(encryptedKeyAndMessageForAuthentication(username)) # ส่ง encrypt message (username) ไปยัง server

    print(cli_sock.recv(1024).decode(), end="") # print สื่งที่ server ส่งตอบกลับมาบน console
    password = input()
    cli_sock.send(encryptedKeyAndMessageForAuthentication(password)) # ส่ง encrypt message (password) ไปยัง server

    response = cli_sock.recv(1024).decode()
    print(response)
    if("Login successful" in response):
        return username

#### ไว้ handle ข้อความที่ได้รับ
def receive_messages():
    while True:
        try:
            msg = cli_sock.recv(MAX_BUF)
            if not msg:
                print("Disconnected from server.")
                break

            if msg.startswith(b'PUBKEY:'):  ##เมื่อขั้นต้นด้วย PUBKEY แปลว่า เป็น public key ของอีก client ที่ส่งผ่าน server มาหาเรา เพื่อใช้เข้ารหัสข้อความ ทั่วไป (chat message)
                peer_key = msg[len(b'PUBKEY:'):]
                peer_pub = load_public_key(peer_key)
                public_keys['peer'] = peer_pub
                continue
            elif msg.startswith(b'SERVERPUBKEY:'): ##เมื่อขึ้นต้นด้วย SERVERPUBKEY แสดงว่าเป็น public key ของ server เพื่อใช้เข้ารหัส login/register (choice, username, password)
                server_key = msg[len(b'SERVERPUBKEY:'):]
                server_pub = load_public_key(server_key)
                server_public_keys['server'] = server_pub
                break
            elif msg.startswith(b'ENC:'): ##ขึ้นต้นด้วย ENC แปลว่าเป็นข้อความปกติที่ถูกส่งมาจากอีก client ผ่าน server เป็นตัวกลาง (การจะถอดรหัสนี้ได้ต้องใช้ private key ของตัว client เอง)
                try:
                    payload = msg[len(b'ENC:'):]
                    encrypted_key, encrypted_msg = payload.split(b'||') # แยกส่วนระหว่าง Encrypt Aes Key กับ Encryp Aes Message

                    aes_key = rsa_decrypt(private_key, encrypted_key)  # ใช้ private key ของตัวเอง เพื่อถอดรหัสเอา AES KEY ที่อีก client นึงสร้างไว้
                    plain_msg = aes_decrypt(aes_key, encrypted_msg) # ใช้ AES Key ที่อีก client สร้างไว้ เพื่อถอดรหัสหาข้อความ plain text

                    print(f'{plain_msg}\n> ', end='', flush=True) #output plainttext ไปที่ console
                except Exception as e:
                    print(f'[ERROR] Failed to decrypt secure message: {e}')
        except Exception as e:
            print(f'[ERROR] {e}')
            break

#### function หลัก สำหรับการเชื่อต่อไปยัง server #### โค้ดจะรันอยู่ในนี้ตลอด
def makeConnection():
    cli_sock.connect(SERV_SOCK_ADDR)
    print("Connected to server.")
    
    ### ========= เมื่อ connect เสร็จ จะสร้างเทรดแยกสำหรับรอรับข้อความ จาก server ======= ###
    ### ===== เทรด นี้จะใช้แค่ตอน login/register เท่านั้น และจะถูก terminate ไปภายหลัง ==== ###
    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()
    #### ========================================================================= ###

    ### ลูปจนกว่าจะ login เสร็จ (ได้ return ค่า username สำเร็จ) 
    while True:
        print("\n1: Register\n2: Login")
        choice = input("Enter menu: ")

        if choice == "1":
            register() # ไปยัง function "register()"
        elif choice == "2":
            username = login() # ไปยัง function "login()" แล้วรับค่า return = username แล้วจึง break loop
            if (username):
                break ## ออกจาก while loop เมื่อได้รับต่า username แล้ว
        else:
            print("Invalid choice. Try again.")

    # ส่ง public key ของตัวเอง ไปให้ server เพื่อรอแลกเปลี่ยนกับ client2
    cli_sock.send(b'PUBKEY:' + serialized_pubkey)

    #### สร้างเทรดใหม่... เทรดนี้ใช้สำหรับเวลาแชทปกติ #### เทรดนี้จะอยู่ตลอดเพื่อรอรับข้อความแชทที่ส่งผ่าน server
    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()
    
    while True:
        print('> ', end='', flush=True)  # พร้อมพ์รอให้ user input
        username = fistCharToUpperClient(username)
        txtout = username + ': ' + sys.stdin.readline().strip() # กำหนดให้ข้อความที่จะส่ง = username + : + ข้อความ
        if 'peer' in public_keys:   # เช็คว่าได้รับ public key ของอีก client มาแล้วหรือยัง
            peer_pubkey = public_keys['peer'] 
            key = generate_aes_key() #สร้าง AES key เพื่อเข้ารหัส ข้อความ
            encrypted_key = rsa_encrypt(peer_pubkey, key) #เข้ารหัส AES key ด้วย public key ของอีก client
            encrypted_msg = aes_encrypt(key, txtout) #เข้ารหัสข้อความด้วย AES key

            cli_sock.send(b'ENC:' + encrypted_key + b'||' + encrypted_msg) #ส่งข้อความไปยัง server || Encrypt AES key + Encrpy AES message (การจะถอดรหัสข้อความได้จำเป็นต้อง ถอดรหัส AES KEY ด้วย Private Key ของอีก client ก่อน)
        else:
            print("[ERROR] No peer public key available.")

        if txtout ==  username + ': ' + 'QUIT':
            break
    cli_sock.close()

#### โค้ดจะอ่านอันนี้ก่อน ####
if __name__ == '__main__':
    makeConnection() # เริ่มด้วยการรัน function "makeConnection()"
