import argparse
import sys
from keygen import (
    generate_aes_key, save_aes_key, load_aes_key,
    generate_rsa_keypair, save_rsa_private_key, save_rsa_public_key,
    load_rsa_private_key, load_rsa_public_key
)
from encrypt import encrypt_file_aes, encrypt_file_rsa, validate_file_path
from decrypt import decrypt_file_aes, decrypt_file_rsa

def main():
    parser = argparse.ArgumentParser(description="Secure File Encryption Tool")
    parser.add_argument('action', choices=['generate', 'encrypt', 'decrypt'], help='Action to perform')
    parser.add_argument('--algorithm', choices=['aes', 'rsa'], required=True, help='Encryption algorithm')
    parser.add_argument('--input', help='Input file path')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--key', help='Key file path')
    parser.add_argument('--public-key', help='RSA public key file path')
    parser.add_argument('--private-key', help='RSA private key file path')

    args = parser.parse_args()

    try:
        if args.action == 'generate':
            if args.algorithm == 'aes':
                key = generate_aes_key()
                save_aes_key(key, args.key)
                print(f"AES key generated and saved to {args.key}")
            elif args.algorithm == 'rsa':
                private_key, public_key = generate_rsa_keypair()
                save_rsa_private_key(private_key, args.private_key)
                save_rsa_public_key(public_key, args.public_key)
                print(f"RSA key pair generated and saved to {args.private_key} and {args.public_key}")

        elif args.action == 'encrypt':
            validate_file_path(args.input)
            if args.algorithm == 'aes':
                key = load_aes_key(args.key)
                encrypt_file_aes(args.input, args.output, key)
            elif args.algorithm == 'rsa':
                public_key = load_rsa_public_key(args.public_key)
                encrypt_file_rsa(args.input, args.output, public_key)

        elif args.action == 'decrypt':
            validate_file_path(args.input)
            if args.algorithm == 'aes':
                key = load_aes_key(args.key)
                decrypt_file_aes(args.input, args.output, key)
            elif args.algorithm == 'rsa':
                private_key = load_rsa_private_key(args.private_key)
                decrypt_file_rsa(args.input, args.output, private_key)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
