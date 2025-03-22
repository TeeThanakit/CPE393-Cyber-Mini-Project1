from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.backends import default_backend
from os import urandom

# === AES SYMMETRIC ENCRYPTION ===

def generate_aes_key(length=32):
    """Generate a random AES key. Default is 256-bit (32 bytes)."""
    return urandom(length)

def aes_encrypt(key, plaintext):
    """Encrypt plaintext using AES-CBC with random IV."""
    iv = urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext  # prepend IV for use in decryption

def aes_decrypt(key, ciphertext):
    """Decrypt AES-CBC encrypted ciphertext (expects IV at start)."""
    iv = ciphertext[:16]
    actual_cipher = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_cipher) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()


# === RSA ASYMMETRIC ENCRYPTION (For key exchange) ===

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
    """Encrypt a message with a public RSA key."""
    return public_key.encrypt(
        message,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext: bytes):
    """Decrypt RSA-encrypted message with private key."""
    return private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

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
