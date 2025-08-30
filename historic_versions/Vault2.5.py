import os
import hashlib
import json
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from easygui import buttonbox, fileopenbox, msgbox, enterbox, passwordbox, diropenbox

VAULT_META_DIR = ".Vault_files"
VAULT_FILES_DIR = ".files"
PUBLIC_KEY_FILE = os.path.join(VAULT_META_DIR, "vault_public_key.pem")
PASSWORD_FILE = os.path.join(VAULT_META_DIR, "vault_password.json")
PRIVATE_KEY_EXPORT = "key.pem"

def migrate_legacy_password():
    """Migrate legacy password file if it exists."""
    legacy_password_file = ".vault_password.json"
    if os.path.exists(legacy_password_file):
        import shutil
        shutil.move(legacy_password_file, PASSWORD_FILE)

def ensure_dirs():
    """Ensure required directories exist."""
    for d in [VAULT_META_DIR, VAULT_FILES_DIR]:
        if not os.path.exists(d):
            os.makedirs(d)

ensure_dirs()
migrate_legacy_password()

LOG_FILE = os.path.join(VAULT_META_DIR, "vault.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

class UserAuth:
    """Handles password and key management."""
    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def save_password(password):
        with open(PASSWORD_FILE, "w") as f:
            json.dump({"hash": UserAuth.hash_password(password)}, f)

    @staticmethod
    def check_password(password):
        if not os.path.exists(PASSWORD_FILE):
            return False
        with open(PASSWORD_FILE, "r") as f:
            data = json.load(f)
        return UserAuth.hash_password(password) == data.get("hash")

    @staticmethod
    def password_flow():
        """Handles password setup and authentication."""
        if not os.path.exists(PUBLIC_KEY_FILE):
            intensity_choice = buttonbox(
                "Choose encryption intensity (RSA key size):",
                "Encryption Intensity",
                choices=["1024 (Low)", "2048 (Standard)", "3072 (High)", "4096 (Higher)", "6144 (Ultimate)", "8192 (Extreme)", "10240 (Maximum)"]
            )
            if intensity_choice == "4096 (Higher)":
                key_size = 4096
            elif intensity_choice == "3072 (High)":
                key_size = 3072
            elif intensity_choice == "1024 (Low)":
                key_size = 1024
            elif intensity_choice == "2048 (Standard)":
                key_size = 2048
            elif intensity_choice == "6144 (Ultimate)":
                key_size = 6144
            elif intensity_choice == "8192 (Extreme)":
                key_size = 8192
            elif intensity_choice == "10240 (Maximum)":
                key_size = 10240
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            public_key = private_key.public_key()
            with open(PUBLIC_KEY_FILE, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            # Optionally encrypt private key with password
            encrypt_choice = buttonbox(
                "Do you want to encrypt your private key with your vault password?",
                "Private Key Protection",
                choices=["Yes", "No"]
            )
            if encrypt_choice == "Yes":
                while True:
                    pwd1 = enterbox("Set password for private key encryption:")
                    if not pwd1:
                        msgbox("Password cannot be empty.")
                        continue
                    elif pwd1 == None:
                        return False
                    pwd2 = passwordbox("Confirm password for private key encryption:")
                    if pwd1 == pwd2:
                        encryption_alg = serialization.BestAvailableEncryption(pwd1.encode())
                        break
                    elif pwd2 == None:
                        return False
                    else:
                        msgbox("Passwords do not match. Try again.")
            else:
                encryption_alg = serialization.NoEncryption()
            with open(PRIVATE_KEY_EXPORT, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_alg
                ))
            msgbox(f"Your private key has been saved as '{PRIVATE_KEY_EXPORT}'. Please keep it safe!")
        if not os.path.exists(PASSWORD_FILE):
            while True:
                pwd1 = enterbox("Set a password for your vault:")
                if not pwd1:
                    msgbox("Password cannot be empty.")
                    continue
                elif pwd1 == None:
                    return False
                pwd2 = passwordbox("Confirm password:")
                if pwd1 == pwd2:
                    UserAuth.save_password(pwd1)
                    msgbox("Password set! Please remember it.")
                    return True
                elif pwd2 == None:
                    return False
                else:
                    msgbox("Passwords do not match. Try again.")
        else:
            attempts = 0
            while attempts < 3:
                pwd = passwordbox("Enter your vault password:")
                if pwd and UserAuth.check_password(pwd):
                    return True
                else:
                    msgbox("Incorrect password.")
                    attempts += 1
            reset = buttonbox(
                "Incorrect password entered 3 times.\nWould you like to reset your vault? This will delete ALL vault settings and keys.",
                "Reset Vault",
                choices=["Reset Vault", "Exit"]
            )
            if reset == "Reset Vault":
                import shutil
                shutil.rmtree(VAULT_META_DIR)
                msgbox("Vault reset. Please restart the program to set a new password and keys.")
            return False

class EncryptionManager:
    """Handles file encryption and decryption."""
    @staticmethod
    def encrypt_file_with_rsa(input_file, output_file, public_key_path, encrypted_key_file):
        try:
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            aes_key = os.urandom(32)  # AES-256
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
                f_out.write(iv)
                while True:
                    chunk = f_in.read(4096)
                    if not chunk:
                        break
                    f_out.write(encryptor.update(chunk))
                f_out.write(encryptor.finalize())
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            with open(encrypted_key_file, "wb") as key_out:
                key_out.write(encrypted_key)
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            raise

    @staticmethod
    def decrypt_file_with_rsa(encrypted_file, output_file, private_key_path, encrypted_key_file):
        try:
            with open(private_key_path, "rb") as key_file:
                # Try both encrypted and unencrypted private key
                try:
                    private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
                except TypeError:
                    pwd = passwordbox("Enter password for private key:")
                    key_file.seek(0)
                    private_key = serialization.load_pem_private_key(key_file.read(), password=pwd.encode(), backend=default_backend())
            with open(encrypted_key_file, "rb") as key_in:
                encrypted_key = key_in.read()
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            with open(encrypted_file, "rb") as f_in:
                iv = f_in.read(16)
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                with open(output_file, "wb") as f_out:
                    while True:
                        chunk = f_in.read(4096)
                        if not chunk:
                            break
                        f_out.write(decryptor.update(chunk))
                    f_out.write(decryptor.finalize())
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            raise

class Vault:
    """Main vault logic and user interface."""
    @staticmethod
    def open_vault():
        ensure_dirs()
        while True:
            files = os.listdir(VAULT_FILES_DIR)
            enc_files = [f for f in files if f.startswith("encrypted_")]
            choices = [os.path.basename(f)[len("encrypted_"): ] for f in enc_files]
            action = buttonbox(
                "Vault Contents:", "Vault",
                choices=["Store", "Take Out", "Reset Password", "Exit"],
                default_choice="Store"
            )
            if action == "Store":
                Vault.store_file()
            elif action == "Take Out":
                file_choice_path = fileopenbox("Select encrypted file to take out:", default=f"{VAULT_FILES_DIR}/encrypted_*")
                if not file_choice_path:
                    msgbox("No file selected.")
                    continue
                file_choice = os.path.basename(file_choice_path)[len("encrypted_"): ] if os.path.basename(file_choice_path).startswith("encrypted_") else os.path.basename(file_choice_path)
                Vault.take_out_file(file_choice)
            elif action == "Reset Password":
                confirm = buttonbox(
                    "Do you want to reset your vault password? This will NOT delete your vault files or keys.",
                    "Reset Password",
                    choices=["Yes", "No"]
                )
                if confirm == "Yes":
                    if os.path.exists(PASSWORD_FILE):
                        os.remove(PASSWORD_FILE)
                    msgbox("Password reset. Please restart the program to set a new password.")
                    break
            else:
                break

    @staticmethod
    def store_file():
        input_file = fileopenbox("Select file to store in vault:")
        if not input_file:
            return
        base_name = os.path.basename(input_file)
        output_file = os.path.join(VAULT_FILES_DIR, f"encrypted_{base_name}")
        encrypted_key_file = os.path.join(VAULT_FILES_DIR, f"AES_{base_name}.key")
        public_key = PUBLIC_KEY_FILE
        # Overwrite protection
        if os.path.exists(output_file) or os.path.exists(encrypted_key_file):
            confirm = buttonbox(
                f"Encrypted file or AES key already exists for {base_name}. Overwrite?",
                "Overwrite Protection",
                choices=["Yes", "No"]
            )
            if confirm != "Yes":
                msgbox("Store cancelled.")
                return
        try:
            EncryptionManager.encrypt_file_with_rsa(input_file, output_file, public_key, encrypted_key_file)
            msgbox(f"File stored in vault!\nEncrypted file: {output_file}\nAES key: {encrypted_key_file}")
        except Exception as e:
            msgbox(f"Storing failed: {e}")
            logging.error(f"Storing failed: {e}")

    @staticmethod
    def take_out_file(file_name):
        encrypted_file = os.path.join(VAULT_FILES_DIR, f"encrypted_{file_name}")
        encrypted_key_file = os.path.join(VAULT_FILES_DIR, f"AES_{file_name}.key")
        if not os.path.exists(encrypted_file) or not os.path.exists(encrypted_key_file):
            msgbox("Encrypted file or AES key not found.")
            return
        private_key = fileopenbox("Select your private key (key.pem):", default=PRIVATE_KEY_EXPORT)
        if not private_key:
            msgbox("You must select a private key to take out the file.")
            return
        dest_dir = diropenbox("Choose folder to save the decrypted file:")
        if not dest_dir:
            return
        dest_file = os.path.join(dest_dir, file_name)
        # Overwrite protection
        if os.path.exists(dest_file):
            confirm = buttonbox(
                f"File {dest_file} already exists. Overwrite?",
                "Overwrite Protection",
                choices=["Yes", "No"]
            )
            if confirm != "Yes":
                msgbox("Take out cancelled.")
                return
        try:
            EncryptionManager.decrypt_file_with_rsa(encrypted_file, dest_file, private_key, encrypted_key_file)
            confirm = buttonbox(
                f"Delete encrypted file and AES key from vault?\n\n{encrypted_file}\n{encrypted_key_file}",
                "Confirm Deletion",
                choices=["Yes", "No"]
            )
            if confirm == "Yes":
                if os.path.exists(encrypted_file):
                    os.remove(encrypted_file)
                if os.path.exists(encrypted_key_file):
                    os.remove(encrypted_key_file)
            msgbox(f"File taken out and saved to: {dest_file}")
        except Exception as e:
            msgbox(f"Take out failed: {e}")
            logging.error(f"Take out failed: {e}")

def main():
    """Main entry point."""
    if UserAuth.password_flow():
        Vault.open_vault()

if __name__ == "__main__":
    main()

