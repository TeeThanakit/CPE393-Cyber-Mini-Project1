from socket import *
import sys
import threading
import json
from crypto_utils import generate_aes_key, aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt


from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    load_public_key
)

private_key, public_key = generate_rsa_keypair()
serialized_pubkey = serialize_public_key(public_key)

with open("config.json", "r") as file:
    config = json.load(file)
    
SERV_SOCK_ADDR = (config["SERVER_IP"], config["SERVER_PORT"])
cli_sock = socket(AF_INET, SOCK_STREAM)


# Other client public RSA key
public_keys = {}
# Maximum size (in bytes) for receiving messages
MAX_BUF = 2048



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
    print(cli_sock.recv(1024).decode(), end="")
    username = input()
    cli_sock.send(username.encode() + b"\n")

    print(cli_sock.recv(1024).decode(), end="")
    password = input()
    cli_sock.send(password.encode() + b"\n")

    response = cli_sock.recv(1024).decode()
    print(response)
    if("Login successful" in response):
        return username

def receive_messages():
    while True:
        try:
            msg = cli_sock.recv(MAX_BUF)
            if not msg:
                print("Disconnected from server.")
                break

            if msg.startswith(b'PUBKEY:'):
                peer_key = msg[len(b'PUBKEY:'):]
                peer_pub = load_public_key(peer_key)
                public_keys['peer'] = peer_pub
                print('\n[INFO] Received public key from another client.\n> ', end='', flush=True)
                # You can store this key by some ID if the server sends one
                continue
            elif msg.startswith(b'ENC:'):
                try:
                    payload = msg[len(b'ENC:'):]
                    encrypted_key, encrypted_msg = payload.split(b'||')

                    aes_key = rsa_decrypt(private_key, encrypted_key)  # use own private key
                    plain_msg = aes_decrypt(aes_key, encrypted_msg)

                    print(f'[PEER] {plain_msg}\n> ', end='', flush=True)
                except Exception as e:
                    print(f'[ERROR] Failed to decrypt secure message: {e}')
        except Exception as e:
            print(f'[ERROR] {e}')
            break

def makeConnection():
    cli_sock.connect(SERV_SOCK_ADDR)
    print("Connected to server.")
    
    #print('Sent Public RSA key to server')

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

    # print("Sent publioc key to server")
    cli_sock.send(b'PUBKEY:' + serialized_pubkey)

    # Start thread to receive messages
    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()

    while True:
        print('> ', end='', flush=True)       # Print prompt for user input
        txtout = sys.stdin.readline().strip() # Read a line of user input (blocking)
        if 'peer' in public_keys:
            peer_pubkey = public_keys['peer']
            key = generate_aes_key()
            encrypted_key = rsa_encrypt(peer_pubkey, key)
            encrypted_msg = aes_encrypt(key, txtout)

            # Format: ENC_KEY + delimiter + ENC_MSG
            cli_sock.send(b'ENC:' + encrypted_key + b'||' + encrypted_msg)
        else:
            print("[ERROR] No peer public key available.")

        # If the user types 'quit', break the loop and disconnect
        if txtout == 'quit':
            break
    cli_sock.close()

if __name__ == '__main__':
    makeConnection()
