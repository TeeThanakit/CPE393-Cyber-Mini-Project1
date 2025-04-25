import socket
import time

SERVER_HOST = '127.0.0.1'  # Change if your server is on another host
SERVER_PORT = 50001      # Make sure this matches your server's port
ATTEMPTS = 10              # Number of rapid connections to try
DELAY = 0.2                # Seconds between connection attempts

for i in range(ATTEMPTS):
    try:
        print(f"Attempt {i + 1}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.close()
    except Exception as e:
        print(f"Connection failed on attempt {i + 1}: {e}")
    time.sleep(DELAY)
