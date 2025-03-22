from socket import * 
from threading import Thread, Lock
import os, sys
import platform

SERV_IP_ADDR, SERV_PORT = '127.0.0.1', 50001

clients = []
clients_lock = Lock()

MAX_CLIENTS = 2

def broadcast(message, sender_socket):
    with clients_lock:
        for client in clients:
            if client != sender_socket:
                try:
                    client.send(message)
                except:
                    pass  # If sending fails, just ignore for now

def handle_client(s, addr):
    global clients
    
    while True:
        try:
            txtin = s.recv(1024)
            if not txtin:
                break

            print(addr[0], ':', addr[1], '>', txtin.decode("utf-8"), sep='')

            if txtin == b'quit':
                break
            else:
                broadcast(txtin, s)

        except:
            break

    with clients_lock:
        if s in clients:
            clients.remove(s)
        s.close()
        print('Disconnect client ', addr[0], ':', addr[1], ' ...', sep='')

def main():
    SERV_SOCK_ADDR = (SERV_IP_ADDR, SERV_PORT) 
    welcome_sckt = socket(AF_INET, SOCK_STREAM)

    if any(platform.win32_ver()):
        welcome_sckt.setsockopt(SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
    else:
        welcome_sckt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    welcome_sckt.bind(SERV_SOCK_ADDR)
    welcome_sckt.listen(5)

    print ('TCP server started at ', SERV_IP_ADDR,":", SERV_PORT, ' ...', sep='')

    while True:
        conn_sckt, cli_addr = welcome_sckt.accept()

        with clients_lock:
            if len(clients) >= MAX_CLIENTS:
                print("Connection refused from", cli_addr, "- server full")
                conn_sckt.send(b"Server full. Try again later.\n")
                conn_sckt.close()
                continue
            else:
                clients.append(conn_sckt)

        print ('New client connected from', cli_addr[0], ':', cli_addr[1], ' ...', sep='')

        try:
            Thread(target=handle_client, args=(conn_sckt, cli_addr)).start()
        except:
            print("Cannot start thread ..")
            import traceback
            traceback.print_exc()

    welcome_sckt.close()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print ('Interrupted ..')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)