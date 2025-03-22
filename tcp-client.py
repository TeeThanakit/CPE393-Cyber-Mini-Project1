from socket import *
import sys
import threading

SERV_IP_ADDR, SERV_PORT = '127.0.0.1', 50001
SERV_SOCK_ADDR = (SERV_IP_ADDR, SERV_PORT)
cli_sock = socket(AF_INET, SOCK_STREAM)

def register():
    cli_sock.send(b"1\n")
    print(cli_sock.recv(1024).decode(), end="")
    username = input()
    cli_sock.send(username.encode() + b"\n")

    print(cli_sock.recv(1024).decode(), end="")
    password = input()
    cli_sock.send(password.encode() + b"\n")

    print(cli_sock.recv(1024).decode())

def login():
    cli_sock.send(b"2\n")  # Send login option
    print(cli_sock.recv(1024).decode(), end="")  # "Enter username: "
    username = input()
    cli_sock.send(username.encode() + b"\n")

    print(cli_sock.recv(1024).decode(), end="")  # "Enter password: "
    password = input()
    cli_sock.send(password.encode() + b"\n")

    response = cli_sock.recv(1024).decode()
    print("back from server", response)
    if("Login successful" in response):
        return username

def receive_messages():
    while True:
        try:
            msg = cli_sock.recv(2048)
            if not msg:
                print("Disconnected from server.")
                break
            print(f"{msg.decode()}\n", end='', flush=True)
        except:
            break

def makeConnection():
    cli_sock.connect(SERV_SOCK_ADDR)
    print("Connected to server.")

    while True:
        print("\n1: Register\n2: Login")
        choice = input("Enter menu: ")

        if choice == "1":
            register()
        elif choice == "2":
            username = login()
            if (username):
                break
        else:
            print("Invalid choice. Try again.")

    # Start thread to receive messages
    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()

    while True:
        msg = input()
        # msg = input("> ")
        cli_sock.send(msg.encode())

        if msg.lower() == "quit":
            break

    cli_sock.close()

if __name__ == '__main__':
    makeConnection()
