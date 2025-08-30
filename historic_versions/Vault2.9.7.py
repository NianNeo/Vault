import os
import stat
import logging
import time
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from easygui import buttonbox, fileopenbox, msgbox, multpasswordbox, diropenbox, passwordbox
from argon2 import PasswordHasher
import re
import paramiko
import base64

VAULT_META_DIR = ".Vault_files"
VAULT_FILES_DIR = ".files"
PUBLIC_KEY_FILE = os.path.join(VAULT_META_DIR, "vault_public_key.pem")
PASSWORD_HASH_FILE = os.path.join(VAULT_META_DIR, "vault_password_hash.txt")
PRIVATE_KEY_EXPORT = "key.pem"
LOCKOUT_INFO_FILE = os.path.join(VAULT_META_DIR, "lockout_info.enc")  # 改为加密文件扩展名
LOCKOUT_KEY_FILE = os.path.join(VAULT_META_DIR, ".lockout_key")  # 用于存储加密密钥
ssh = paramiko.SSHClient()

# Global timer variable
timer = None
failed_attempts = 0

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
        shutil.move(legacy_password_file, PASSWORD_HASH_FILE)
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

def get_lockout_key():
    """获取或创建锁定信息的加密密钥"""
    if not os.path.exists(LOCKOUT_KEY_FILE):
        # 生成新的随机密钥
        key = os.urandom(32)  # AES-256
        with open(LOCKOUT_KEY_FILE, "wb") as f:
            f.write(key)
        # 设置严格的文件权限
        try:
            os.chmod(LOCKOUT_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logging.warning(f"Could not set file permissions for lockout key: {e}")
        return key
    else:
        with open(LOCKOUT_KEY_FILE, "rb") as f:
            return f.read()

def encrypt_lockout_data(data):
    """加密锁定数据"""
    key = get_lockout_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_lockout_data(encrypted_data):
    """解密锁定数据"""
    key = get_lockout_key()
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted_data.decode()

def read_lockout_info():
    """Read lockout information from the encrypted lockout info file."""
    if not os.path.exists(LOCKOUT_INFO_FILE):
        return 0, 0
    try:
        with open(LOCKOUT_INFO_FILE, "rb") as f:
            encrypted_data = f.read()
        data = decrypt_lockout_data(encrypted_data)
        lines = data.splitlines()
        if len(lines) < 2:
            return 0, 0
        lockout_time = int(lines[0].strip())
        lockout_duration = int(lines[1].strip())
        return lockout_time, lockout_duration
    except Exception as e:
        logging.error(f"Failed to read lockout info: {e}")
        return 0, 0

def write_lockout_info(lockout_time, lockout_duration):
    """Write lockout information to the encrypted lockout info file."""
    data = f"{lockout_time}\n{lockout_duration}\n"
    encrypted_data = encrypt_lockout_data(data)
    with open(LOCKOUT_INFO_FILE, "wb") as f:
        f.write(encrypted_data)
    # 设置严格的文件权限
    try:
        os.chmod(LOCKOUT_INFO_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        logging.warning(f"Could not set file permissions for lockout info: {e}")

def reset_timer():
    """Reset the auto-logout timer."""
    global timer
    if timer is not None:
        timer.cancel()
    timer = threading.Timer(180, auto_logout)  # 3 minutes
    timer.daemon = True  # Ensure timer thread does not block program exit
    timer.start()
    
def auto_logout():
    """Perform actions when user is automatically logged out due to inactivity."""
    msgbox("You have been logged out due to inactivity.")
    logging.info("Auto logout triggered due to inactivity.")
    os._exit(0)  # Exit the program

def check_lock_status():
    """Check if the vault is currently locked based on lockout info."""
    lockout_time, lockout_duration = read_lockout_info()
    current_time = int(time.time())
    if current_time < lockout_time + lockout_duration:
        remaining_time = lockout_time + lockout_duration - current_time
        msgbox(f"Vault is currently locked. Please try again in {remaining_time} seconds.")
        logging.warning(f"Vault is locked for another {remaining_time} seconds.")
        os._exit(0)  # Exit the program
    return False

def lock_vault(lock_duration):
    """Lock the vault for a specified duration and update lockout info."""
    current_time = int(time.time())
    write_lockout_info(current_time, lock_duration)
    msgbox(f"Too many failed attempts. Vault locked for {lock_duration} seconds.")
    logging.warning(f"Vault locked for {lock_duration} seconds due to too many failed attempts.")

def validate_file_path(file_path, base_dir):
    """Validate that the file path is within the base directory."""
    normalized_path = os.path.normpath(file_path)
    if not normalized_path.startswith(base_dir):
        raise ValueError(f"Invalid file path: {file_path}")
    return normalized_path

class UserAuth:
    """Handles password and key management."""
    @staticmethod
    def hash_password(password):
        ph = PasswordHasher()
        return ph.hash(password)

    @staticmethod
    def save_password(password):
        """Save hashed password to file."""
        hash_val = UserAuth.hash_password(password)
        with open(PASSWORD_HASH_FILE, "w") as f:
            f.write(hash_val)
        # Set restrictive permissions
        try:
            os.chmod(PASSWORD_HASH_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logging.warning(f"Could not set file permissions for password file: {e}")
        logging.info("Password saved successfully.")

    @staticmethod
    def check_password(password):
        """Check if the provided password matches the stored hash."""
        if not os.path.exists(PASSWORD_HASH_FILE):
            return False
        with open(PASSWORD_HASH_FILE, "r") as f:
            hash_val = f.read().strip()
        ph = PasswordHasher()
        try:
            result = ph.verify(hash_val, password)
        except Exception:
            logging.error("Failed to verify password hash.")
            return False
        return result

    @staticmethod
    def password_flow():
        """Handles password setup and authentication."""
        global failed_attempts
        
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
                    pwd = multpasswordbox("Set password for private key encryption:", "Password Entry", ["Password", "Confirm Password"])
                    if pwd is None:
                        import shutil
                        logging.shutdown()
                        shutil.rmtree(VAULT_META_DIR)
                        return False
                    if not pwd[0] or not pwd[1]:
                        msgbox("Password cannot be empty.")
                    if pwd[0] == pwd[1]:
                        encryption_alg = serialization.BestAvailableEncryption(pwd[0].encode())
                        break
                    else:
                        msgbox("Passwords do not match. Try again.")
            elif encrypt_choice is None:
                import shutil
                logging.shutdown()
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
        if not os.path.exists(PASSWORD_HASH_FILE):
            while True:
                pwd = multpasswordbox("Set a password for your vault:", "Password Entry", ["Password", "Confirm Password"])
                if pwd is None:
                    logging.info("Password entry cancelled by user.")
                    return False
                if not pwd[0] or not pwd[1]:
                    msgbox("Password cannot be empty.")
                if pwd[0] == pwd[1]:
                    UserAuth.save_password(pwd[0])
                    msgbox("Password set! Please remember it.\nPlease restart the program to log in with your new password.")
                    logging.info("New password created successfully.")
                    logging.shutdown()
                    return False
                else:
                    msgbox("Passwords do not match. Try again.")
        else:
            while True:
                if check_lock_status():
                    time.sleep(1)
                    continue
                
                pwd = passwordbox("Enter your vault password:")
                if pwd is None:
                    logging.info("Password entry cancelled by user.")
                    return False
                
                if UserAuth.check_password(pwd):
                    logging.info("User authenticated successfully.")
                    reset_timer()  # Reset timer on successful login
                    failed_attempts = 0
                    return True
                else:
                    failed_attempts += 1
                    logging.warning(f"Incorrect password attempt {failed_attempts}.")
                    if failed_attempts >= 10:
                        lock_vault(20 * 60)  # Lock for 20 minutes
                    elif failed_attempts >= 5:
                        lock_vault(10 * 60)  # Lock for 10 minutes
                    else:
                        msgbox("Incorrect password.")
                        reset_timer()  # Reset timer on each incorrect attempt

class EncryptionManager:
    """Handles file encryption and decryption."""
    @staticmethod
    def encrypt_file_with_rsa(input_file, output_file, public_key_path, encrypted_key_file):
        """Encrypt a file using RSA and AES."""
        # Validate file paths
        input_file = validate_file_path(input_file, "")
        public_key_path = validate_file_path(public_key_path, VAULT_META_DIR)
        
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
            del aes_key
            del iv
            del encrypted_key
            logging.info(f"File encrypted successfully: {output_file}, Encrypted key saved to: {encrypted_key_file}")
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            raise

    @staticmethod
    def decrypt_file_with_rsa(encrypted_file, output_file, private_key_path, encrypted_key_file):
        """Decrypt a file using RSA and AES."""
        # Validate file paths
        encrypted_file = validate_file_path(encrypted_file, VAULT_FILES_DIR)
        encrypted_key_file = validate_file_path(encrypted_key_file, VAULT_FILES_DIR)
        private_key_path = validate_file_path(private_key_path, "")
        
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
            del aes_key
            del encrypted_key
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
            reset_timer()  # Reset timer on each action

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
        reset_timer()  # Reset timer on successful storage

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
        reset_timer()  # Reset timer on successful retrieval

def main():
    """Main entry point."""
    if check_lock_status():
        return
    
    if UserAuth.password_flow():
        reset_timer()  # Start timer on successful login
        Vault.open_vault()
        # Ensure timer is cancelled on exit
        global timer
        if timer is not None:
            timer.cancel()

if __name__ == "__main__":
    main()