import tkinter as tk
from tkinter import filedialog, messagebox
from keygen import (
    generate_aes_key, save_aes_key, load_aes_key,
    generate_rsa_keypair, save_rsa_private_key, save_rsa_public_key,
    load_rsa_private_key, load_rsa_public_key
)
from encrypt import encrypt_file_aes, encrypt_file_rsa, validate_file_path
from decrypt import decrypt_file_aes, decrypt_file_rsa

class EncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryption Tool")
        self.root.geometry("400x300")

        # File selection
        self.file_label = tk.Label(root, text="Select File:")
        self.file_label.pack(pady=5)
        self.file_entry = tk.Entry(root, width=40)
        self.file_entry.pack()
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=5)

        # Algorithm selection
        self.algo_label = tk.Label(root, text="Algorithm:")
        self.algo_label.pack(pady=5)
        self.algo_var = tk.StringVar(value="AES")
        self.algo_menu = tk.OptionMenu(root, self.algo_var, "AES", "RSA")
        self.algo_menu.pack()

        # Buttons
        self.generate_button = tk.Button(root, text="Generate Key", command=self.generate_key)
        self.generate_button.pack(pady=10)
        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.pack(pady=5)
        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.pack(pady=5)

        # Status
        self.status_label = tk.Label(root, text="")
        self.status_label.pack(pady=10)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)

    def generate_key(self):
        algo = self.algo_var.get()
        try:
            if algo == "AES":
                key = generate_aes_key()
                save_aes_key(key, "aes_key.key")
                self.status_label.config(text="AES key generated and saved.")
            elif algo == "RSA":
                private_key, public_key = generate_rsa_keypair()
                save_rsa_private_key(private_key, "rsa_private.pem")
                save_rsa_public_key(public_key, "rsa_public.pem")
                self.status_label.config(text="RSA key pair generated and saved.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt_file(self):
        input_file = self.file_entry.get()
        algo = self.algo_var.get()
        try:
            validate_file_path(input_file)
            if algo == "AES":
                key = load_aes_key("aes_key.key")
                output_file = input_file + ".aes"
                encrypt_file_aes(input_file, output_file, key)
                self.status_label.config(text=f"File encrypted: {output_file}")
            elif algo == "RSA":
                public_key = load_rsa_public_key("rsa_public.pem")
                output_file = input_file + ".rsa"
                encrypt_file_rsa(input_file, output_file, public_key)
                self.status_label.config(text=f"File encrypted: {output_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        input_file = self.file_entry.get()
        algo = self.algo_var.get()
        try:
            validate_file_path(input_file)
            if algo == "AES":
                key = load_aes_key("aes_key.key")
                output_file = input_file.replace(".aes", "_decrypted.txt")
                decrypt_file_aes(input_file, output_file, key)
                self.status_label.config(text=f"File decrypted: {output_file}")
            elif algo == "RSA":
                private_key = load_rsa_private_key("rsa_private.pem")
                output_file = input_file.replace(".rsa", "_decrypted.txt")
                decrypt_file_rsa(input_file, output_file, private_key)
                self.status_label.config(text=f"File decrypted: {output_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    gui = EncryptionGUI(root)
    root.mainloop()
