import socket
import threading
import time

SERVER_IP = '127.0.0.1'  # Change this to match your server
SERVER_PORT = 50001      # Change this to match your port
NUM_CONNECTIONS = 10     # Number of repeated connections
DELAY_BETWEEN = 0.1     # Delay between connections (in seconds)

def create_connection(index):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        print(f"[{index}] Connected")
        time.sleep(5)  # Keep the connection alive for 5 seconds
        sock.close()
        print(f"[{index}] Closed")
    except Exception as e:
        print(f"[{index}] Connection failed: {e}")

threads = []

for i in range(NUM_CONNECTIONS):
    t = threading.Thread(target=create_connection, args=(i,))
    t.start()
    threads.append(t)
    time.sleep(DELAY_BETWEEN)  # Optional: small delay to simulate more real-world spam

# Wait for all threads to complete
for t in threads:
    t.join()

print("All connections attempted.")