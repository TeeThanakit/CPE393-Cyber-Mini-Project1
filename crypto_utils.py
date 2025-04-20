from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.backends import default_backend
from os import urandom
import json
import logging

### ใช้โหลด config เพื่อ update แบบ realtime ### ความจริงตอน production ไม่จำเป็น
def load_config():
    try:
        with open("config.json", "r") as file:
            return json.load(file)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        # Return default values if config can't be loaded
        return {"AES_Encryption": True, "RSA_Encryption": True}
# === AES SECTION === Use for encrypt plain text

def generate_aes_key(length=32):
    # Generate a random 32 bytes AES key. 
    return urandom(length)

def aes_encrypt(key, plaintext):

    # ถ้าอยากได้ config update โดยไม่ต้องรี server เพื่อเทส ให้ uncomment
    config = load_config()


    if config["AES_Encryption"]:
        ## Encrypt plaintext using AES-CBC with random IV. ##
        
        iv = urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext  # prepend IV for use in decryption
    else:
        return plaintext.encode()

def aes_decrypt(key, ciphertext):

    # ถ้าอยากได้ config update โดยไม่ต้องรี server เพื่อเทส ให้ uncomment
    config = load_config()

    if config["AES_Encryption"]:
        ##Decrypt AES-CBC encrypted ciphertext (expects IV at start).##
        iv = ciphertext[:16]
        actual_cipher = ciphertext[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_cipher) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode()
    else:
        return ciphertext.decode()


# === RSA Section === To generate Private/Public Keys || Encrypt/Decrypt AES message

def generate_rsa_keypair():
    """Generate RSA public and private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key
    

def rsa_encrypt(public_key, message: bytes):
    ###Encrypt a AES message with a public RSA key.###
    return public_key.encrypt(
        message,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext: bytes):
    ###Decrypt RSA-encrypted message with private key. To get AES message
    return private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


### Convert PubKey obj to string
def serialize_public_key(public_key):
    """Serialize public key to bytes for transmission."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(public_key_bytes):
    """Load public key from bytes."""
    return serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

def serialize_private_key(private_key):
    """Serialize private key to bytes (PEM format)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def load_private_key(private_key_bytes):
    """Load private key from PEM bytes."""
    return serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
