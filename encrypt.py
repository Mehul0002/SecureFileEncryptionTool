from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

def encrypt_file_aes(input_file, output_file, key):
    """Encrypt a file using AES (Fernet)."""
    fernet = Fernet(key)
    with open(input_file, 'rb') as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    print(f"File encrypted successfully: {output_file}")

def encrypt_file_rsa(input_file, output_file, public_key):
    """Encrypt a file using RSA public key."""
    with open(input_file, 'rb') as f:
        data = f.read()
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    print(f"File encrypted successfully: {output_file}")

def validate_file_path(file_path):
    """Validate if the file path exists."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
