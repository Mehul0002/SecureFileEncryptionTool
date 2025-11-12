# Secure File Encryption Tool

A command-line tool for encrypting and decrypting files using AES (symmetric) and RSA (asymmetric) algorithms.

## Features

- **AES Encryption**: Symmetric encryption using Fernet (AES in CBC mode with HMAC).
- **RSA Encryption**: Asymmetric encryption for secure key exchange.
- **Key Management**: Generate, save, and load encryption keys securely.
- **File Handling**: Read from and write to files with validation.
- **Modular Design**: Separate modules for key generation, encryption, and decryption.

## Requirements

- Python 3.6+
- `cryptography` library

## Installation

1. Clone or download the project.
2. Navigate to the project directory.
3. Install dependencies:
   ```
   pip install cryptography
   ```

## Usage

### Command Line Interface (CLI)

#### Generate Keys

##### AES Key
```
python main.py generate --algorithm aes --key aes_key.key
```

##### RSA Key Pair
```
python main.py generate --algorithm rsa --private-key rsa_private.pem --public-key rsa_public.pem
```

#### Encrypt a File

##### AES Encryption
```
python main.py encrypt --algorithm aes --input plaintext.txt --output encrypted.aes --key aes_key.key
```

##### RSA Encryption
```
python main.py encrypt --algorithm rsa --input plaintext.txt --output encrypted.rsa --public-key rsa_public.pem
```

#### Decrypt a File

##### AES Decryption
```
python main.py decrypt --algorithm aes --input encrypted.aes --output decrypted.txt --key aes_key.key
```

##### RSA Decryption
```
python main.py decrypt --algorithm rsa --input encrypted.rsa --output decrypted.txt --private-key rsa_private.pem
```

### Graphical User Interface (GUI)

#### Python GUI
Run the GUI application:
```
python gui.py
```
- Select a file using the "Browse" button.
- Choose the algorithm (AES or RSA).
- Click "Generate Key" to create keys.
- Click "Encrypt" or "Decrypt" to process the file.

#### Java GUI
Compile and run the GUI:
```
javac *.java
java EncryptionGUI
```
- Use the "Browse" button to select a file.
- Select the algorithm from the dropdown.
- Click "Generate Key" to create keys.
- Click "Encrypt" or "Decrypt" to process the file.

## Security Notes

- Keep private keys secure and never share them.
- Use strong, randomly generated keys.
- Validate file paths to prevent errors.
- The tool prevents accidental overwriting by design (output files are overwritten if they exist).

## License

This project is open-source. Use at your own risk.
