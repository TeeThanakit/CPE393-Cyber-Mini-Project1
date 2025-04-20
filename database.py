import sqlite3
import bcrypt

class Database:
    def __init__(self, db_file="user_db.sqlite3"):
        self.db_file = db_file
        self.create_table() # สร้างตาราง users

    def create_connection(self):
        return sqlite3.connect(self.db_file)

    def create_table(self):
        with self.create_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                );
            ''')

    def register_user(self, username, password):
          # ฟังก์ชันสำหรับลงทะเบียนผู้ใช้ใหม่
        if password is None:
            raise ValueError("Password cannot be None.")

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        # เข้ารหัสรหัสผ่านก่อนเก็บลงฐานข้อมูล
        try:
            with self.create_connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?);",
                    (username, hashed)
                )
            print("✅ ลงทะเบียนผู้ใช้สำเร็จ.")
            return True
        except sqlite3.IntegrityError:
            # ถ้าชื่อผู้ใช้ซ้ำ จะแสดงข้อความว่าใช้ชื่อผู้ใช้นี้ไม่ได้
            print("❗ ชื่อผู้ใช้มีอยู่แล้ว.")
            return False

    def validate_login(self, username, password):
        # ตรวจสอบชื่อผู้ใช้และรหัสผ่านตอนล็อกอิน
        with self.create_connection() as conn:
            cursor = conn.execute(
                "SELECT password FROM users WHERE username = ?;",
                (username,)
            )
            row = cursor.fetchone()
            if row:
                stored_hash = row[0]
                return bcrypt.checkpw(password.encode(), stored_hash)
        return False

    def get_all_users(self):
         # ดึงชื่อผู้ใช้ทั้งหมดในฐานข้อมูล
        with self.create_connection() as conn:
            cursor = conn.execute("SELECT username FROM users;")
            return [row[0] for row in cursor.fetchall()]

    def get_user_by_username(self, username):
         # ดึงข้อมูลของผู้ใช้ตามชื่อผู้ใช้
        with self.create_connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
            return cursor.fetchone()