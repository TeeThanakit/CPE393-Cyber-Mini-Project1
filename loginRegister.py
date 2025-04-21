import json
import bcrypt
import re
import time
import uuid
from database import Database 
from crypto_utils import aes_decrypt, rsa_decrypt


with open("config.json", "r") as file:
    config = json.load(file)

class AuthHandler:
    def __init__(self, private_key):
        self.db = Database()
        self.private_key = private_key

        self.failed_attempts = {} 
        self.banned_ips = {}    

    #### ใช้ เซฟข้อมูล user ลงใน database ตอน register
    def register_user(self, username, password):
        user_id = str(uuid.uuid4())
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return self.db.register_user(username, hashed_password, user_id)



#### ใช้สำหรับ register
    def register(self, client_socket):
        client_socket.send(b"Enter new username: ") # ส่ง Prompt ให้ กรอก username ไปยัง client_socket
        username = client_socket.recv(1024) # รอรับข้อความจาก client_socket
        username = self.decrypt_message(username) #ถอดรหัสข้อความ AES ที่ถูก encrypt ซ้ #ถอดรหัสข้อความ AES ที่ถูก encrypt ซ้อนมาด้วย publick key ของ server

        client_socket.send(b"Enter new password: ")
        password = client_socket.recv(1024)
        password = self.decrypt_message(password) # ถอดรหัสข้อความรหัสผ่าน

        user = self.db.get_user_by_username(username)
        print(f"User found in DB: {user}")  # ดูว่าผลลัพธ์จากฐานข้อมูลเป็นอะไร
        if not username or not password:
                raise ValueError("Username or password is missing.") # ถ้าไม่ได้กรอก username หรือ password ให้แจ้งเตือน
        # Password validation
        if len(password) < 8 or len(password) > 22:
            client_socket.send(b"Password must be between 8-22 characters. Try again.\n")
            return
        elif not re.search(r"[^a-zA-Z0-9]", password):
            client_socket.send(b"Password must include at least one special character. Try again.\n")
            return
        if user:
            client_socket.send(b"Username already exists. Try again.\n")  # ถ้ามีผู้ใช้อยู่แล้ว ให้แจ้งเตือน
        else:
            self.db.register_user(username, password)
            print("User registered, checking DB...")# ตรวจสอบฐานข้อมูลหลังจากการลงทะเบียน

            client_socket.send(b"Registration successful. You can now login.\n") # แจ้ง client ว่าลงทะเบียนสำเร็จ
   
    
   ### ใช้สหรับ login 
    def login(self, client_socket, clientIP):
        current_time = time.time() # เช็คเวลาปัจจุบัน
        
        #ดูว่า ip ถูกแบนอยู่มั้ย
        if clientIP in self.banned_ips:
            if current_time < self.banned_ips[clientIP]:
                client_socket.send(b"You are temporarily banned due to multiple failed login attempts. Try again later.\n")
                return None
            else:
                del self.banned_ips[clientIP]  #ปลดแบนถ้าเวลาเกิน 5 นาที


        client_socket.send(b"Enter username: ") # ส่ง Prompt ให้ กรอก username ไปยัง client_socket
        username = client_socket.recv(1024) # รอรับข้อความจาก client_socket
        username = self.decrypt_message(username) #ถอดรหัสข้อความ AES ที่ถูก encrypt ซ้อนมาด้วย public key ของ server
    
        client_socket.send(b"Enter password: ") # ส่งข้อความให้ client กรอกรหัสผ่าน
        password = client_socket.recv(1024)  # รอรับรหัสผ่าน
        password = self.decrypt_message(password) # ถอดรหัสข้อความ

        user = self.db.get_user_by_username(username) # ตรวจสอบผู้ใช้ในฐานข้อมูล
        if user and bcrypt.checkpw(password.encode(), user[2]):
            if clientIP in self.failed_attempts: #reset fail attemp ถ้ามี
                del self.failed_attempts[clientIP]
            client_socket.send(b"Login successful. Welcome!\n")
            return username
        else:
            ### ลง timestamp user ที่ใส่ password ผิด
            if clientIP not in self.failed_attempts:
                self.failed_attempts[clientIP] = {'count': 1, 'last_attempt': current_time}
            else:
                self.failed_attempts[clientIP]['count'] += 1
                self.failed_attempts[clientIP]['last_attempt'] = current_time

            if self.failed_attempts[clientIP]['count'] >= 3:
                self.banned_ips[clientIP] = current_time + 300  # แบน 5 นาที
                del self.failed_attempts[clientIP]
                client_socket.send(b"Too many failed attempts. You are banned for 5 minutes.\n")
            else:
                client_socket.send(b"Invalid username or password. Try again.\n")

            return 20 #จำไม่ได้ละว่าทำไม แต่ใน server handle ทั้ง retur none & 20 และแยกหน้าที่กัน
    

### ใช้ถอดรหัสข้อความ จาก client ที่ส่งมาเป็น -> SERVER_Public_Key(Client_AES_Key(ข้อความจริงๆ))
    def decrypt_message(self, msg):
    # Decrypt Message
        if msg.startswith(b'ENC:'):
            try:            
                payload = msg[len(b'ENC:'):]
                encrypted_key, encrypted_msg = payload.split(b'||')  ### แยกระหว่าง encrypted AES key กับ encrypted AES message 
            
                aes_key = rsa_decrypt(self.private_key, encrypted_key)# ถอดรหัส encrypted AES key ด้วย private key ของ server (เพราะ client ส่งข้อความาเป็น AES key ที่ encrypted ซ้อนด้วย public key ของ server)
                plain_msg = aes_decrypt(aes_key, encrypted_msg) # ถอดรหัส encrypted AES message ด้วย AES key ที่ถอดรหัสออกมาได้

                return plain_msg
            except Exception as e:
                return None