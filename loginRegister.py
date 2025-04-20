import json
import bcrypt
from crypto_utils import aes_decrypt, rsa_decrypt
from database import Database 

class AuthHandler:
    def __init__(self, private_key):
        self.db = Database() # สร้าง object สำหรับเชื่อมต่อกับฐานข้อมูล
        self.private_key = private_key # กำหนด private key ของ server สำหรับใช้ถอดรหัส

    #### ใช้ เซฟข้อมูล user ลงใน database ตอน register
    def register_user(self, username, password):
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return self.db.register_user(username, hashed_password)



    #### ใช้สำหรับ register
    def register(self, client_socket):
        client_socket.send(b"Enter new username: ")# ส่งข้อความให้ client กรอก username
        username = client_socket.recv(1024) # รอรับข้อความจาก client_socket
        username = self.decrypt_message(username) #ถอดรหัสข้อความ AES ที่ถูก encrypt ซ้อนมาด้วย publick key ของ server
        

        client_socket.send(b"Enter new password: ") # ส่งข้อความให้ client กรอกรหัสผ่าน
        password = client_socket.recv(1024) # รอรับรหัสผ่านจาก client
    
        password = self.decrypt_message(password) # ถอดรหัสข้อความรหัสผ่าน

        user = self.db.get_user_by_username(username)
        print(f"User found in DB: {user}")  # ดูว่าผลลัพธ์จากฐานข้อมูลเป็นอะไร
        if not username or not password:
            raise ValueError("Username or password is missing.") # ถ้าไม่ได้กรอก username หรือ password ให้แจ้งเตือน

        if user:
            client_socket.send(b"Username already exists. Try again.\n")  # ถ้ามีผู้ใช้อยู่แล้ว ให้แจ้งเตือน
        else:
            self.db.register_user(username, password)
            print("User registered, checking DB...")# ตรวจสอบฐานข้อมูลหลังจากการลงทะเบียน

            client_socket.send(b"Registration successful. You can now login.\n") # แจ้ง client ว่าลงทะเบียนสำเร็จ
   
    
    ### ใช้สหรับ login 
    def login(self, client_socket):
        client_socket.send(b"Enter username: ") # ส่ง Prompt ให้ กรอก username ไปยัง client_socket
        username = client_socket.recv(1024) # รอรับข้อความจาก client_socket
        username = self.decrypt_message(username) #ถอดรหัสข้อความ AES ที่ถูก encrypt ซ้อนมาด้วย public key ของ server
    
        client_socket.send(b"Enter password: ") # ส่งข้อความให้ client กรอกรหัสผ่าน
        password = client_socket.recv(1024)  # รอรับรหัสผ่าน
        password = self.decrypt_message(password) # ถอดรหัสข้อความ

        user = self.db.get_user_by_username(username) # ตรวจสอบผู้ใช้ในฐานข้อมูล
        if user and bcrypt.checkpw(password.encode(), user[2]):  # ← use index instead of 'password'
            client_socket.send(b"Login successful. Welcome!\n")
            return username
        else:
            client_socket.send(b"Invalid username or password. Try again.\n")
            return None
    

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