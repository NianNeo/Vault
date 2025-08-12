import os
import stat
import hashlib
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

def setup_logging():
    """Setup logging configuration."""
    if not os.path.exists(VAULT_META_DIR):
        os.makedirs(VAULT_META_DIR)
        logging.info(f"Created directory: {VAULT_META_DIR}")
    LOG_FILE = os.path.join(VAULT_META_DIR, "vault.log")
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

def migrate_legacy_password():
    """Migrate legacy password file if it exists."""
    legacy_password_file = ".vault_password.json"
    if os.path.exists(legacy_password_file):
        import shutil
        shutil.move(legacy_password_file, PASSWORD_FILE)
        logging.info("Migrated legacy password file.")

def ensure_dirs():
    """Ensure required directories exist."""
    for d in [VAULT_META_DIR, VAULT_FILES_DIR]:
        if not os.path.exists(d):
            os.makedirs(d)
            logging.info(f"Created directory: {d}")

setup_logging()
ensure_dirs()
migrate_legacy_password()

class UserAuth:
    """Handles password and key management."""
    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def save_password(password):
        # Encrypt password file with password-derived key
        import base64
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        # Store salt and encrypted hash
        import json
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        hash_val = UserAuth.hash_password(password)
        encrypted_hash = encryptor.update(hash_val.encode()) + encryptor.finalize()
        with open(PASSWORD_FILE, "wb") as f:
            f.write(json.dumps({
                "salt": base64.b64encode(salt).decode(),
                "iv": base64.b64encode(iv).decode(),
                "hash": base64.b64encode(encrypted_hash).decode()
            }).encode())
        # Set restrictive permissions
        try:
            os.chmod(PASSWORD_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logging.warning(f"Could not set file permissions for password file: {e}")
        # Zero sensitive data
        password = None
        key = None
        hash_val = None
        encrypted_hash = None
        logging.info("Password saved successfully.")

    @staticmethod
    def check_password(password):
        if not os.path.exists(PASSWORD_FILE):
            return False
        import base64
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        import json
        with open(PASSWORD_FILE, "rb") as f:
            data = json.loads(f.read().decode())
        salt = base64.b64decode(data["salt"])
        iv = base64.b64decode(data["iv"])
        encrypted_hash = base64.b64decode(data["hash"])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            decrypted_hash = decryptor.update(encrypted_hash) + decryptor.finalize()
        except Exception:
            logging.error("Failed to decrypt password hash.")
            return False
        result = UserAuth.hash_password(password).encode() == decrypted_hash
        # Zero sensitive data
        password = None
        key = None
        decrypted_hash = None
        return result

    @staticmethod
    def password_flow():
        """Handles password setup and authentication."""
        if not os.path.exists(PUBLIC_KEY_FILE):
            intensity_choice = buttonbox(
                "Choose encryption intensity (RSA key size):",
                "Encryption Intensity",
                choices=["1024 (Low)", "2048 (Standard)", "3072 (High)", "4096 (Higher)", "6144 (Ultimate)", "8192 (Extreme)", "10240 (Maximum)"]
            )
            if intensity_choice is None:
                logging.shutdown()
                import shutil
                shutil.rmtree(VAULT_META_DIR)
                return False
            if intensity_choice == "1024 (Low)":
                msgbox("Warning: 1024-bit RSA is not secure. Use only for quick experiments.")
            key_size = {
                "1024 (Low)": 1024,
                "2048 (Standard)": 2048,
                "3072 (High)": 3072,
                "4096 (Higher)": 4096,
                "6144 (Ultimate)": 6144,
                "8192 (Extreme)": 8192,
                "10240 (Maximum)": 10240
            }.get(intensity_choice, 2048)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            public_key = private_key.public_key()
            with open(PUBLIC_KEY_FILE, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            # Set restrictive permissions
            try:
                os.chmod(PUBLIC_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as e:
                logging.warning(f"Could not set file permissions for public key: {e}")
            # Optionally encrypt private key with password
            encrypt_choice = buttonbox(
                "Do you want to encrypt your private key with your vault password?",
                "Private Key Protection",
                choices=["Yes", "No"]
            )
            if encrypt_choice == "Yes":
                while True:
                    pwd1 = enterbox("Set password for private key encryption:")
                    if pwd1 is None:
                        logging.shutdown()
                        import shutil
                        shutil.rmtree(VAULT_META_DIR)
                        return False
                    if not pwd1:
                        msgbox("Password cannot be empty.")
                        continue
                    pwd2 = passwordbox("Confirm password for private key encryption:")
                    if pwd2 is None:
                        logging.shutdown()
                        import shutil
                        shutil.rmtree(VAULT_META_DIR)
                        return False
                    if pwd1 == pwd2:
                        encryption_alg = serialization.BestAvailableEncryption(pwd1.encode())
                        break
                    else:
                        msgbox("Passwords do not match. Try again.")
            elif encrypt_choice is None:
                logging.shutdown()
                import shutil
                shutil.rmtree(VAULT_META_DIR)
                return False
            else:
                encryption_alg = serialization.NoEncryption()
            with open(PRIVATE_KEY_EXPORT, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_alg
                ))
            # Set restrictive permissions
            try:
                os.chmod(PRIVATE_KEY_EXPORT, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as e:
                logging.warning(f"Could not set file permissions for private key: {e}")
            selection = msgbox(f"Your private key has been saved as '{PRIVATE_KEY_EXPORT}'. Please keep it safe!")
            if selection is None:
                return False
        if not os.path.exists(PASSWORD_FILE):
            while True:
                pwd1 = enterbox("Set a password for your vault:")
                if pwd1 is None:
                    return False
                if not pwd1:
                    msgbox("Password cannot be empty.")
                    continue
                pwd2 = passwordbox("Confirm password:")
                if pwd2 is None:
                    return False
                if pwd1 == pwd2:
                    UserAuth.save_password(pwd1)
                    msgbox("Password set! Please remember it.\nPlease restart the program to log in with your new password.")
                    logging.info("New password created successfully.")
                    logging.shutdown()
                    return False
                else:
                    msgbox("Passwords do not match. Try again.")
        else:
            attempts = 0
            while attempts < 3:
                pwd = passwordbox("Enter your vault password:")
                if pwd and UserAuth.check_password(pwd):
                    logging.info("User authenticated successfully.")
                    return True
                elif pwd is None:
                    return False
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
                logging.info("Vault was reset due to multiple incorrect password attempts.")
            return False

class EncryptionManager:
    """Handles file encryption and decryption."""
    @staticmethod
    def encrypt_file_with_rsa(input_file, output_file, public_key_path, encrypted_key_file):
        # Validate file paths
        if not os.path.abspath(input_file).startswith(os.path.abspath(VAULT_FILES_DIR)) and not os.path.isfile(input_file):
            logging.warning(f"Invalid input file path: {input_file}")
            raise ValueError("Invalid input file path.")
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
            # Set restrictive permissions
            try:
                os.chmod(output_file, stat.S_IRUSR | stat.S_IWUSR)
                os.chmod(encrypted_key_file, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as e:
                logging.warning(f"Could not set file permissions for encrypted files: {e}")
            # Zero sensitive data
            aes_key = None
            iv = None
            encrypted_key = None
            logging.info(f"File encrypted successfully: {output_file}, Encrypted key saved to: {encrypted_key_file}")
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            raise

    @staticmethod
    def decrypt_file_with_rsa(encrypted_file, output_file, private_key_path, encrypted_key_file):
        # Validate file paths
        if not os.path.abspath(encrypted_file).startswith(os.path.abspath(VAULT_FILES_DIR)) and not os.path.isfile(encrypted_file):
            logging.warning(f"Invalid encrypted file path: {encrypted_file}")
            raise ValueError("Invalid encrypted file path.")
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
            # Set restrictive permissions
            try:
                os.chmod(output_file, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as e:
                logging.warning(f"Could not set file permissions for decrypted file: {e}")
            # Zero sensitive data
            aes_key = None
            encrypted_key = None
            logging.info(f"File decrypted successfully: {output_file}")
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
                choices=["In", "Out", "Exit"],
                default_choice="In"
            )
            if action == "In":
                Vault.store_file()
            elif action == "Out":
                file_choice_path = fileopenbox("Select encrypted file to take out:", default=f"{VAULT_FILES_DIR}/encrypted_*")
                if not file_choice_path:
                    msgbox("No file selected.")
                    logging.info("No file selected for taking out.")
                    continue
                file_choice = os.path.basename(file_choice_path)[len("encrypted_"): ] if os.path.basename(file_choice_path).startswith("encrypted_") else os.path.basename(file_choice_path)
                Vault.take_out_file(file_choice)
            else:
                logging.info("Exiting vault.")
                break

    @staticmethod
    def store_file():
        input_file = fileopenbox("Select file to store in vault:")
        if not input_file:
            logging.info("No file selected for storing.")
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
                logging.info("Store operation cancelled by user.")
                return
        try:
            EncryptionManager.encrypt_file_with_rsa(input_file, output_file, public_key, encrypted_key_file)
            msgbox(f"File stored in vault!\nEncrypted file: {output_file}\nAES key: {encrypted_key_file}")
            logging.info(f"File stored in vault: {input_file} -> {output_file}, AES key: {encrypted_key_file}")
        except Exception as e:
            msgbox(f"Storing failed: {e}")
            logging.error(f"Storing failed: {e}")

    @staticmethod
    def take_out_file(file_name):
        encrypted_file = os.path.join(VAULT_FILES_DIR, f"encrypted_{file_name}")
        encrypted_key_file = os.path.join(VAULT_FILES_DIR, f"AES_{file_name}.key")
        if not os.path.exists(encrypted_file) or not os.path.exists(encrypted_key_file):
            msgbox("Encrypted file or AES key not found.")
            logging.info("Encrypted file or AES key not found.")
            return
        private_key = fileopenbox("Select your private key (key.pem):", default=PRIVATE_KEY_EXPORT)
        if not private_key:
            msgbox("You must select a private key to take out the file.")
            logging.info("No private key selected for taking out the file.")
            return
        dest_dir = diropenbox("Choose folder to save the decrypted file:")
        if not dest_dir:
            logging.info("No destination directory selected for saving the decrypted file.")
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
                logging.info("Take out operation cancelled by user.")
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
                    logging.info(f"Deleted encrypted file: {encrypted_file}")
                if os.path.exists(encrypted_key_file):
                    os.remove(encrypted_key_file)
                    logging.info(f"Deleted AES key file: {encrypted_key_file}")
            msgbox(f"File taken out and saved to: {dest_file}")
            logging.info(f"File taken out and saved to: {dest_file}")
        except Exception as e:
            msgbox(f"Take out failed: {e}")
            logging.error(f"Take out failed: {e}")

def main():
    """Main entry point."""
    if UserAuth.password_flow():
        Vault.open_vault()

if __name__ == "__main__":
    main()


