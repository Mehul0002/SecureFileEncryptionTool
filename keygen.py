from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

def generate_aes_key():
    """Generate a new AES key using Fernet."""
    key = Fernet.generate_key()
    return key

def save_aes_key(key, filename):
    """Save AES key to a file."""
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_aes_key(filename):
    """Load AES key from a file."""
    with open(filename, 'rb') as key_file:
        key = key_file.read()
    return key

def generate_rsa_keypair():
    """Generate RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_private_key(private_key, filename):
    """Save RSA private key to a file."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def save_rsa_public_key(public_key, filename):
    """Save RSA public key to a file."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_rsa_private_key(filename):
    """Load RSA private key from a file."""
    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    return private_key

def load_rsa_public_key(filename):
    """Load RSA public key from a file."""
    with open(filename, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key
