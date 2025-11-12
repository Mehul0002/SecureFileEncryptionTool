from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

def decrypt_file_aes(input_file, output_file, key):
    """Decrypt a file using AES (Fernet)."""
    fernet = Fernet(key)
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    print(f"File decrypted successfully: {output_file}")

def decrypt_file_rsa(input_file, output_file, private_key):
    """Decrypt a file using RSA private key."""
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    print(f"File decrypted successfully: {output_file}")

def validate_file_path(file_path):
    """Validate if the file path exists."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
