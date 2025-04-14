from socket import *
from threading import Thread, Lock
import os
import platform
import json
from loginRegister import register, login
from crypto_utils import  aes_decrypt, rsa_decrypt, generate_rsa_keypair, serialize_public_key
from helper import get_current_timestamp

private_key, public_key = generate_rsa_keypair()
serialized_pubkey = serialize_public_key(public_key)

with open("config.json", "r") as file:
    config = json.load(file)

SERV_IP_ADDR = config["SERVER_IP"]
SERV_PORT = config["SERVER_PORT"]
MAX_CLIENTS = 2

clients = {} # เก็บ socket address ของ client
client_public_keys = {} # เก็บ public key ของ client ไว้แลกเปลี่ยนตอน 2 client connect ครบ


# keep every client info in dictionary
# {<socket info>:"username"}
clients_lock = Lock()

users = {} # เก็บ user_db ที่ read มา ตั้งแต่แรก ## ควรแก้ (อ่านต่อใน function "main")
# keep username && password
# {'Teeboy': 'pass', 'moji': '123'}


######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########
######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########
######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########
######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########
######### เวลาอ่านโค้ด python อ่านจาก ล่าง -> บน จ้า จะเข้าใจง่ายกว่า ########



#### ใช้ broadcast ข้อความ ไปยัง client ทั้งหมดที่ connect อยู่ ยกเว้นตัวเอง (sender_socket)
#### ในกรณีของเรา ที่มี connection ได้เพียง 2 client ไม่จำเป็น!!!!! #### ควรแก้ให้ส่งไปอีก client ตรงๆ และลบ function นี้ออก
def broadcast(message, sender_socket):
    with clients_lock:
        for client in clients: # ลูป clients{}
            # เช็คว่าไม่ใช่ sender
            if client != sender_socket:
                try:
                    # ส่งข้อตวามไปให้อีก client
                    client.send(message) 
                except:
                    pass

### ใช้แค่ตอน client login/register
def authenticate(client_socket):
    choice = client_socket.recv(2048) ### รับ choice ที่ user เลือก ( ควรจะได้รับมาเป็น AES message ที่ encrypt ซ้อนด้วย public key ของ server อีกที)

    #### === Section การถอดรหัสข้อความ #### 
    if choice.startswith(b'ENC:'):
        try:            
            payload = choice[len(b'ENC:'):]
            encrypted_key, encrypted_msg = payload.split(b'||') ### แยกระหว่าง encrypted AES key กับ encrypted AES message 

            aes_key = rsa_decrypt(private_key, encrypted_key) #ถอดรหัส encrypted AES key ด้วย private key ของ server (เพราะ client ส่งข้อความาเป็น AES key ที่ encrypted ซ้อนด้วย public key ของ server)
            plain_msg = aes_decrypt(aes_key, encrypted_msg) #ถอดรหัส encrypted AES message ด้วย AES key ที่ถอดรหัสออกมาได้

        except Exception as e:
            print(f'[ERROR] Failed to decrypt secure message: {e}')

    # เช็คดูว่า plain text เลือกช้อย 1 หรือ 2
    ## หลังจากนี้จะเป็นการเรียก function จากไฟล์ "loginRegister.py" -> ให้ไปอ่านต่อในไฟล์นั้น
    if plain_msg == "1":  # Register
        register(client_socket, users, private_key) 
    elif plain_msg == "2":  # Login
        return login(client_socket, users, private_key)
    else:
        client_socket.send(b"Invalid choice: \n" + plain_msg)
        return None



#### จัดการ client แต่ละตัว ในนี้ ####
def handle_client(client_socket, addr):
    global clients

    username = None ### เริ่มแรกยังไม่ login ให้ username = None

    while username is None:  ### ลูปรอใน function "authenticate()"
        username = authenticate(client_socket)

    with clients_lock:
        clients[client_socket] = username

    ### ==== เมืื่อ user login เสร็จแล้ว ====
    print(f"{username} from {addr} joined the chat.") 
    log_message = f"[{get_current_timestamp()}] Username: {username} From IP {addr[0]} with Port {addr[1]} joined the chat.\n"
    with open("log.txt", "a") as log_file:
        log_file.write(log_message)

    ### ================================

    ### หลังจาก login เสร็จแล้ว จะวนลูปอยู่ในนี้ตลอด
    while True:
        try:
            msg = client_socket.recv(2048) ### recv ย่อ มาจาก recieve ### กำหนดให้ msg = ข้อความที่ได้รับมาจาก socket ที่กำหนด (ตัวแปร client_socket)
            if not msg:
                break
            # ถ้าข้อความเริ่มต้นด้วย "PUBKEY" แสดงว่า client พยายามส่ง Public key มาให้ server
            if msg.startswith(b'PUBKEY:'):
                key_data = msg[len(b'PUBKEY:'):]
                client_public_keys[client_socket] = key_data

                #### ================= ตรงนี้ miracle มาก ไม่เข้าใจเลย ใครเข้าใจฝาก comment ต่อที ========================================================== ####
                #### *** หลักการคือ พอมันตรวจเช็คเจอ client connect เข้ามา 2 คน > มันจะส่ง public ของกันและกันให้กัน (แลกเปลี่ยน public key ระหว่าง client1 && client2) 
                with clients_lock:
                    for other_client, pubkey in client_public_keys.items():
                        if other_client != client_socket: 
                            try:
                                client_socket.send(b'PUBKEY:' + pubkey)
                            except:
                                pass

                broadcast(b'PUBKEY:' + key_data, client_socket)
                continue
                ### =============================================================================================================================== ####
            
            # ข้อความอื่นๆ จะถูก ส่งไป function "broadcast()" เพื่อส่งข้อความที่ได้รับไปยัง client ทั้งหมดใน server
            broadcast(msg, client_socket)


        except: 
            break

    ##### ลบ user ออก เมื่อ client disconnected ##### !!! สำคัญ !!! 
    with clients_lock:
        del clients[client_socket]
        if client_socket in client_public_keys:
            del client_public_keys[client_socket]
        client_socket.close()
        print(f"{username} disconnected.")
        log_message = f"[{get_current_timestamp()}] Username: {username} disconnected.\n"
        with open("log.txt", "a") as log_file:
            log_file.write(log_message)


### อ่านไฟล์ "user_db" แล้วเซฟเก็บไว้ใน global variable 
def load_users():
    global users
    if os.path.exists(config["USER_DB_FILE"]):
        with open(config["USER_DB_FILE"], "r") as file:
            for line in file:
                username, password = line.strip().split(",")
                users[username] = password
                # dictionary username is a key, password is value
                #{'Teeboy': 'pass', 'moji': '123', 'jj': 'patty'}

def main():
    ### อ่านไฟล์ user_db เพื่อ เก็บ username + password ไว้ใน global variable
    ### แล้ว ตอน login มันเช็คกับใน variable นี้ ไม่ได้เช็คจาก db ตรงๆ
    ### ซึ่งจะเจรู้สึกว่าไม่ถูกต้องมั้ยนะ ควรต้องแก้ทีหลัง
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
        
        log_message = f"[{get_current_timestamp()}] IP {cli_addr[0]} with Port {cli_addr[1]} connected to server\n"
        with open("log.txt", "a") as log_file:
            log_file.write(log_message)
            
        with clients_lock:
            if len(clients) >= MAX_CLIENTS:
                conn_sckt.send(b"Server full. Try again later.\n")
                conn_sckt.close()
                continue
            ##ส่ง public key ของเซิฟเวอร์ ไปให้ client ใช้ เพื่อเข้ารหัสข้อความ AES ในขั้นตอน login/register
            conn_sckt.send(b'SERVERPUBKEY:' + serialized_pubkey)
            

        # สร้างเทรดรันฟังค์ชั่น handle_client 
        ## ทำไมต้องสร้างเทรด?? เพราะจะทำให้ client อื่นๆ สามารถ connect มาพร้อมกันได้ >> แยก function "handle_client()" ให้แต่ละ connection ไปเลย
        try:
            Thread(target=handle_client, args=(conn_sckt, cli_addr), daemon=True).start()
        except:
            print("Cannot start thread ..")
            # Print the stack trace to understand what went wrong
            import traceback
            traceback.print_exc()



#### โค้ดจะอ่านอันนี้ก่อน ####
if __name__ == '__main__':
    try:
        main() ###เริ่มต้นที่ function "main()"
    except KeyboardInterrupt:
        print("Server shutting down...")
