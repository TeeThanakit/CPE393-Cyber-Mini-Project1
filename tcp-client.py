from socket import *
import sys
import threading

MAX_BUF = 2048
SERV_IP_ADDR, SERV_PORT = '127.0.0.1', 50001
SERV_SOCK_ADDR = (SERV_IP_ADDR, SERV_PORT)

cli_sock = socket(AF_INET, SOCK_STREAM)
cli_sock.connect(SERV_SOCK_ADDR)
print('Connected to server ...')

# Thread สำหรับรับข้อความจาก server
def receive_messages():
    while True:
        try:
            msg = cli_sock.recv(MAX_BUF)
            if not msg:
                print("Disconnected from server.")
                break
            print('\n' + msg.decode('utf-8') + '\n> ', end='', flush=True)
        except:
            break

recv_thread = threading.Thread(target=receive_messages, daemon=True)
recv_thread.start()

# Main loop สำหรับส่งข้อความ
while True:
    print('> ', end='', flush=True)
    txtout = sys.stdin.readline().strip()
    cli_sock.send(txtout.encode('utf-8'))

    if txtout == 'quit':
        break

cli_sock.close()