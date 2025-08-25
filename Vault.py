import os
import stat
import logging
import time
import threading
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from easygui import buttonbox, fileopenbox, msgbox, multpasswordbox, passwordbox, filesavebox
from argon2 import PasswordHasher
import re
import paramiko
import base64
import traceback  # 添加traceback用于详细错误日志

VAULT_META_DIR = ".Vault_files"
VAULT_FILES_DIR = ".files"
PUBLIC_KEY_FILE = os.path.join(VAULT_META_DIR, "vault_public_key.pem")
PASSWORD_HASH_FILE = os.path.join(VAULT_META_DIR, "vault_password_hash.json")
PRIVATE_KEY_EXPORT = "key.pem"
LOCKOUT_INFO_FILE = os.path.join(VAULT_META_DIR, "lockout_info.enc")
LOCKOUT_KEY_FILE = os.path.join(VAULT_META_DIR, ".lockout_key")
ssh = paramiko.SSHClient()

# Global timer variable
timer = None
failed_attempts = 0

def setup_logging():
    """Setup enhanced logging configuration."""
    if not os.path.exists(VAULT_META_DIR):
        os.makedirs(VAULT_META_DIR)
    
    LOG_FILE = os.path.join(VAULT_META_DIR, "vault.log")
    
    # 创建logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # 清除已有的handler，避免重复
    if logger.handlers:
        logger.handlers.clear()
    
    # 创建formatter
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    
    # 文件handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    
    # 控制台handler（可选）
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    
    # 添加handler到logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logging.info("="*50)
    logging.info("Vault session started")
    logging.info("="*50)

def migrate_legacy_password():
    """Migrate legacy password file if it exists."""
    legacy_password_file_txt = os.path.join(VAULT_META_DIR, "vault_password_hash.txt")
    legacy_password_file_json = ".vault_password.json"
    
    # 迁移旧文本格式
    if os.path.exists(legacy_password_file_txt):
        try:
            with open(legacy_password_file_txt, "r") as f:
                hash_val = f.read().strip()
            
            # 保存为JSON格式
            with open(PASSWORD_HASH_FILE, "w") as f:
                json.dump({"hash": hash_val}, f)
            
            # 删除旧文件
            os.remove(legacy_password_file_txt)
            logging.info("Migrated legacy password file from text to JSON.")
        except Exception as e:
            logging.error(f"Failed to migrate legacy password file: {e}")
            logging.error(traceback.format_exc())
    
    # 迁移旧JSON格式
    if os.path.exists(legacy_password_file_json):
        try:
            import shutil
            shutil.move(legacy_password_file_json, PASSWORD_HASH_FILE)
            logging.info("Migrated legacy password file from JSON.")
        except Exception as e:
            logging.error(f"Failed to migrate legacy JSON password file: {e}")
            logging.error(traceback.format_exc())

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
    try:
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
            logging.info("Generated new lockout key")
            return key
        else:
            with open(LOCKOUT_KEY_FILE, "rb") as f:
                logging.debug("Using existing lockout key")
                return f.read()
    except Exception as e:
        logging.error(f"Failed to get lockout key: {e}")
        logging.error(traceback.format_exc())
        raise

def encrypt_lockout_data(data):
    """加密锁定数据"""
    try:
        key = get_lockout_key()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
        logging.debug("Lockout data encrypted successfully")
        return iv + encrypted_data
    except Exception as e:
        logging.error(f"Failed to encrypt lockout data: {e}")
        logging.error(traceback.format_exc())
        raise

def decrypt_lockout_data(encrypted_data):
    """解密锁定数据"""
    try:
        key = get_lockout_key()
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        logging.debug("Lockout data decrypted successfully")
        return decrypted_data.decode()
    except Exception as e:
        logging.error(f"Failed to decrypt lockout data: {e}")
        logging.error(traceback.format_exc())
        raise

def read_lockout_info():
    """Read lockout information from the encrypted lockout info file."""
    if not os.path.exists(LOCKOUT_INFO_FILE):
        logging.debug("No lockout info file found")
        return 0, 0
    try:
        with open(LOCKOUT_INFO_FILE, "rb") as f:
            encrypted_data = f.read()
        data = decrypt_lockout_data(encrypted_data)
        lines = data.splitlines()
        if len(lines) < 2:
            logging.warning("Lockout info file format invalid")
            return 0, 0
        lockout_time = int(lines[0].strip())
        lockout_duration = int(lines[1].strip())
        logging.info(f"Read lockout info: time={lockout_time}, duration={lockout_duration}")
        return lockout_time, lockout_duration
    except Exception as e:
        logging.error(f"Failed to read lockout info: {e}")
        logging.error(traceback.format_exc())
        return 0, 0

def write_lockout_info(lockout_time, lockout_duration):
    """Write lockout information to the encrypted lockout info file."""
    try:
        data = f"{lockout_time}\n{lockout_duration}\n"
        encrypted_data = encrypt_lockout_data(data)
        with open(LOCKOUT_INFO_FILE, "wb") as f:
            f.write(encrypted_data)
        # 设置严格的文件权限
        try:
            os.chmod(LOCKOUT_INFO_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logging.warning(f"Could not set file permissions for lockout info: {e}")
        logging.info(f"Wrote lockout info: time={lockout_time}, duration={lockout_duration}")
    except Exception as e:
        logging.error(f"Failed to write lockout info: {e}")
        logging.error(traceback.format_exc())

def reset_timer():
    """Reset the auto-logout timer."""
    global timer
    if timer is not None:
        timer.cancel()
        logging.debug("Auto-logout timer cancelled")
    timer = threading.Timer(180, auto_logout)  # 3 minutes
    timer.daemon = True  # Ensure timer thread does not block program exit
    timer.start()
    logging.debug("Auto-logout timer reset (3 minutes)")

def auto_logout():
    """Perform actions when user is automatically logged out due to inactivity."""
    msgbox("You have been logged out due to inactivity.")
    logging.warning("Auto logout triggered due to inactivity.")
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
    logging.debug("Vault is not locked")
    return False

def calculate_lockout_duration(failed_attempts):
    """Calculate lockout duration based on failed attempts."""
    if failed_attempts < 5:
        logging.debug(f"No lockout needed for {failed_attempts} failed attempts")
        return 0  # No lockout
    
    # Determine the tier and exponent
    tier = (failed_attempts - 1) // 10  # 0-based tier index
    exponent = tier + 2  # Start with n^2 for tier 0
    
    # Calculate lockout duration in minutes
    lockout_minutes = failed_attempts ** exponent
    
    # Convert to seconds
    result = lockout_minutes * 60
    logging.info(f"Calculated lockout duration: {result} seconds for {failed_attempts} failed attempts")
    return result

def lock_vault(failed_attempts):
    """Lock the vault based on the number of failed attempts."""
    lockout_duration = calculate_lockout_duration(failed_attempts)
    
    if lockout_duration == 0:
        logging.debug("No lockout needed")
        return  # No lockout needed
    
    current_time = int(time.time())
    write_lockout_info(current_time, lockout_duration)
    
    # Convert to minutes for display
    lockout_minutes = lockout_duration // 60
    msgbox(f"Too many failed attempts. Vault locked for {lockout_minutes} minutes.")
    logging.warning(f"Vault locked for {lockout_duration} seconds ({lockout_minutes} minutes) due to {failed_attempts} failed attempts.")

def validate_file_path(file_path, base_dir):
    """Validate that the file path is within the base directory."""
    normalized_path = os.path.normpath(file_path)
    if not normalized_path.startswith(base_dir):
        logging.error(f"Invalid file path: {file_path} (not in base directory: {base_dir})")
        raise ValueError(f"Invalid file path: {file_path}")
    logging.debug(f"File path validated: {file_path}")
    return normalized_path

class UserAuth:
    """Handles password and key management."""
    @staticmethod
    def hash_password(password):
        ph = PasswordHasher()
        return ph.hash(password)

    @staticmethod
    def save_password(password):
        """Save hashed password to JSON file."""
        hash_val = UserAuth.hash_password(password)
        password_data = {
            "hash": hash_val,
            "created": time.time(),
            "version": "1.0"
        }
        with open(PASSWORD_HASH_FILE, "w") as f:
            json.dump(password_data, f)
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
            logging.warning("Password hash file does not exist")
            return False
        
        try:
            with open(PASSWORD_HASH_FILE, "r") as f:
                password_data = json.load(f)
            
            # 支持旧格式和新格式
            if isinstance(password_data, dict) and "hash" in password_data:
                hash_val = password_data["hash"]
            else:
                # 旧格式（直接存储哈希值）
                hash_val = password_data
        
        except json.JSONDecodeError:
            # 如果JSON解析失败，尝试读取为纯文本
            try:
                with open(PASSWORD_HASH_FILE, "r") as f:
                    hash_val = f.read().strip()
                # 自动迁移到JSON格式
                UserAuth.save_password(password)  # 这会重新保存为JSON格式
            except Exception:
                logging.error("Failed to read password hash file.")
                logging.error(traceback.format_exc())
                return False
        
        ph = PasswordHasher()
        try:
            result = ph.verify(hash_val, password)
            logging.debug("Password verification successful" if result else "Password verification failed")
            return result
        except Exception as e:
            logging.error(f"Failed to verify password hash: {e}")
            logging.error(traceback.format_exc())
            return False

    @staticmethod
    def password_flow():
        """Handles password setup and authentication."""
        global failed_attempts
        
        if not os.path.exists(PUBLIC_KEY_FILE):
            logging.info("No public key found, starting key generation process")
            intensity_choice = buttonbox(
                "Choose encryption intensity (RSA key size):",
                "Encryption Intensity",
                choices=["1024 (Low)", "2048 (Standard)", "3072 (High)", "4096 (Higher)", "6144 (Ultimate)", "8192 (Extreme)", "10240 (Maximum)"]
            )
            if intensity_choice is None:
                logging.info("User cancelled encryption intensity selection")
                logging.shutdown()
                import shutil
                shutil.rmtree(VAULT_META_DIR)
                return False
            
            logging.info(f"User selected encryption intensity: {intensity_choice}")
            
            if intensity_choice == "1024 (Low)":
                msg = msgbox("Warning: 1024-bit RSA is not secure. Use only for quick experiments.")
                if msg is None:
                    logging.info("User cancelled after security warning")
                    logging.shutdown()
                    shutil.rmtree(VAULT_META_DIR)
                    return False
            
            key_size = {
                "1024 (Low)": 1024,
                "2048 (Standard)": 2048,
                "3072 (High)": 3072,
                "4096 (Higher)": 4096,
                "6144 (Ultimate)": 6144,
                "8192 (Extreme)": 8192,
                "10240 (Maximum)": 10240
            }.get(intensity_choice, 2048)
            
            logging.info(f"Generating RSA key with size: {key_size} bits")
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
            
            logging.info("Public key saved successfully")
            
            # Optionally encrypt private key with password
            encrypt_choice = buttonbox(
                "Do you want to encrypt your private key with your vault password?",
                "Private Key Protection",
                choices=["Yes", "No"]
            )
            if encrypt_choice == "Yes":
                logging.info("User chose to encrypt private key with password")
                while True:
                    pwd = multpasswordbox("Set password for private key encryption:", "Password Entry", ["Password", "Confirm Password"])
                    if pwd is None:
                        logging.info("User cancelled private key password entry")
                        import shutil
                        logging.shutdown()
                        shutil.rmtree(VAULT_META_DIR)
                        return False
                    if not pwd[0] or not pwd[1]:
                        msgbox("Password cannot be empty.")
                        continue
                    if pwd[0] == pwd[1]:
                        encryption_alg = serialization.BestAvailableEncryption(pwd[0].encode())
                        break
                    else:
                        msgbox("Passwords do not match. Try again.")
            elif encrypt_choice is None:
                logging.info("User cancelled private key encryption choice")
                import shutil
                logging.shutdown()
                shutil.rmtree(VAULT_META_DIR)
                return False
            else:
                logging.info("User chose not to encrypt private key")
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
            
            logging.info("Private key saved successfully")
            selection = msgbox(f"Your private key has been saved as '{PRIVATE_KEY_EXPORT}'. Please keep it safe!")
            if selection is None:
                logging.info("User dismissed private key safety message")
                return False
        
        if not os.path.exists(PASSWORD_HASH_FILE):
            logging.info("No password hash found, starting password setup")
            while True:
                pwd = multpasswordbox("Set a password for your vault:", "Password Entry", ["Password", "Confirm Password"])
                if pwd is None:
                    logging.info("Password setup cancelled by user")
                    return False
                if not pwd[0] or not pwd[1]:
                    msgbox("Password cannot be empty.")
                    continue
                if pwd[0] == pwd[1]:
                    UserAuth.save_password(pwd[0])
                    msgbox("Password set! Please remember it.\nPlease restart the program to log in with your new password.")
                    logging.info("New password created successfully")
                    logging.shutdown()
                    return False
                else:
                    msgbox("Passwords do not match. Try again.")
        else:
            logging.info("Starting authentication process")
            while True:
                if check_lock_status():
                    time.sleep(1)
                    continue
                
                pwd = passwordbox("Enter your vault password:")
                if pwd is None:
                    logging.info("Password entry cancelled by user")
                    return False
                
                if UserAuth.check_password(pwd):
                    logging.info("User authenticated successfully")
                    reset_timer()  # Reset timer on successful login
                    failed_attempts = 0
                    return True
                else:
                    failed_attempts += 1
                    logging.warning(f"Incorrect password attempt {failed_attempts}.")
                    
                    # Lock vault based on failed attempts
                    lock_vault(failed_attempts)
                    
                    # Check if vault is now locked
                    if check_lock_status():
                        continue
                    else:
                        msgbox("Incorrect password.")
                        reset_timer()  # Reset timer on each incorrect attempt

class EncryptionManager:
    """Handles file encryption and decryption."""
    @staticmethod
    def encrypt_file_with_rsa(input_file, output_file, public_key_path):
        """Encrypt a file using RSA and AES."""
        # Validate file paths
        input_file = validate_file_path(input_file, "")
        public_key_path = validate_file_path(public_key_path, VAULT_META_DIR)
        
        try:
            logging.info(f"Starting encryption of file: {input_file}")
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            
            aes_key = os.urandom(32)  # AES-256
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
                f_out.write(iv)
                file_size = os.path.getsize(input_file)
                processed = 0
                
                while True:
                    chunk = f_in.read(4096)
                    if not chunk:
                        break
                    f_out.write(encryptor.update(chunk))
                    processed += len(chunk)
                    # 每处理1MB记录一次进度
                    if processed % (1024*1024) < 4096:
                        progress = (processed / file_size) * 100
                        logging.info(f"Encryption progress: {progress:.1f}%")
                
                f_out.write(encryptor.finalize())
            
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Set restrictive permissions
            try:
                os.chmod(output_file, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as e:
                logging.warning(f"Could not set file permissions for encrypted files: {e}")
            # Zero sensitive data
            del aes_key
            del iv
            logging.info(f"File encrypted successfully: {input_file} -> {output_file}")
            return encrypted_key
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            logging.error(traceback.format_exc())
            raise

    @staticmethod
    def decrypt_file_with_rsa(encrypted_file, output_file, private_key_path, encrypted_key):
        """Decrypt a file using RSA and AES."""
        # Validate file paths
        encrypted_file = validate_file_path(encrypted_file, VAULT_FILES_DIR)
        private_key_path = validate_file_path(private_key_path, "")
        
        try:
            logging.info(f"Starting decryption of file: {encrypted_file}")
            with open(private_key_path, "rb") as key_file:
                # Try both encrypted and unencrypted private key
                try:
                    private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
                except TypeError:
                    pwd = passwordbox("Enter password for private key:")
                    key_file.seek(0)
                    private_key = serialization.load_pem_private_key(key_file.read(), password=pwd.encode(), backend=default_backend())
            
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
                    file_size = os.path.getsize(encrypted_file) - 16  # 减去IV的大小
                    processed = 0
                    
                    while True:
                        chunk = f_in.read(4096)
                        if not chunk:
                            break
                        f_out.write(decryptor.update(chunk))
                        processed += len(chunk)
                        # 每处理1MB记录一次进度
                        if processed % (1024*1024) < 4096:
                            progress = (processed / file_size) * 100
                            logging.info(f"Decryption progress: {progress:.1f}%")
                    
                    f_out.write(decryptor.finalize())
            
            # Set restrictive permissions
            try:
                os.chmod(output_file, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as e:
                logging.warning(f"Could not set file permissions for decrypted file: {e}")
            # Zero sensitive data
            del aes_key
            del encrypted_key
            logging.info(f"File decrypted successfully: {encrypted_file} -> {output_file}")
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            logging.error(traceback.format_exc())
            raise

class Vault:
    """Main vault logic and user interface."""
    @staticmethod
    def open_vault():
        ensure_dirs()
        logging.info("Vault opened")
        while True:
            files = os.listdir(VAULT_FILES_DIR)
            enc_files = [f for f in files if f.startswith("encrypted_")]
            choices = [os.path.basename(f)[len("encrypted_"): ] for f in enc_files]
            
            logging.info(f"Found {len(enc_files)} encrypted files in vault")
            
            action = buttonbox(
                "Vault Contents:", "Vault",
                choices=["In", "Out", "Exit"],
                default_choice="In"
            )
            
            if action == "In":
                logging.info("User selected 'In' action")
                Vault.store_file()
            elif action == "Out":
                logging.info("User selected 'Out' action")
                file_choice_path = fileopenbox("Select encrypted file to take out:", default=f"{VAULT_FILES_DIR}/encrypted_*")
                if not file_choice_path:
                    msgbox("No file selected.")
                    logging.info("No file selected for taking out.")
                    continue
                file_choice = os.path.basename(file_choice_path)[len("encrypted_"): ] if os.path.basename(file_choice_path).startswith("encrypted_") else os.path.basename(file_choice_path)
                Vault.take_out_file(file_choice)
            else:
                logging.info("User selected 'Exit' action")
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
        public_key = PUBLIC_KEY_FILE
        
        logging.info(f"Attempting to store file: {input_file}")
        
        # Overwrite protection
        if os.path.exists(output_file):
            confirm = buttonbox(
                f"Encrypted file already exists for {base_name}. Overwrite?",
                "Overwrite Protection",
                choices=["Yes", "No"]
            )
            if confirm != "Yes":
                msgbox("Store cancelled.")
                logging.info("Store operation cancelled by user (overwrite protection).")
                return
        
        try:
            encrypted_key = EncryptionManager.encrypt_file_with_rsa(input_file, output_file, public_key)
            
            # Let user save the AES key
            key_file_path = filesavebox("Save the AES key file", default=f"{base_name}_AES.key")
            if key_file_path:
                with open(key_file_path, "wb") as key_file:
                    key_file.write(encrypted_key)
                msgbox(f"File stored in vault!\nEncrypted file: {output_file}\nAES key saved to: {key_file_path}")
                logging.info(f"File stored in vault: {input_file} -> {output_file}, AES key saved to: {key_file_path}")
            else:
                msgbox("AES key not saved. File encryption completed but key was not saved.")
                logging.warning(f"File encrypted but AES key not saved: {input_file}")
        except Exception as e:
            msgbox(f"Storing failed: {e}")
            logging.error(f"Storing failed: {e}")
            logging.error(traceback.format_exc())
        reset_timer()  # Reset timer on successful storage

    @staticmethod
    def take_out_file(file_name):
        encrypted_file = os.path.join(VAULT_FILES_DIR, f"encrypted_{file_name}")
        if not os.path.exists(encrypted_file):
            msgbox("Encrypted file not found.")
            logging.error(f"Encrypted file not found: {encrypted_file}")
            return
        
        logging.info(f"Attempting to take out file: {file_name}")
        
        # Ask user for AES key file
        aes_key_file = fileopenbox("Select the AES key file:", default="*.key")
        if not aes_key_file:
            msgbox("You must select an AES key file to take out the file.")
            logging.info("No AES key file selected for taking out the file.")
            return
        
        # Read the AES key
        try:
            with open(aes_key_file, "rb") as key_file:
                encrypted_key = key_file.read()
            logging.info(f"AES key file read: {aes_key_file}")
        except Exception as e:
            msgbox(f"Failed to read AES key file: {e}")
            logging.error(f"Failed to read AES key file: {e}")
            logging.error(traceback.format_exc())
            return
        
        private_key = fileopenbox("Select your private key (key.pem):", default=PRIVATE_KEY_EXPORT)
        if not private_key:
            msgbox("You must select a private key to take out the file.")
            logging.info("No private key selected for taking out the file.")
            return
        
        # Use filesavebox for saving the decrypted file
        dest_file = filesavebox("Save the decrypted file:", default=file_name)
        if not dest_file:
            logging.info("No destination file selected for saving the decrypted file.")
            return
        
        # Overwrite protection
        if os.path.exists(dest_file):
            confirm = buttonbox(
                f"File {dest_file} already exists. Overwrite?",
                "Overwrite Protection",
                choices=["Yes", "No"]
            )
            if confirm != "Yes":
                msgbox("Take out cancelled.")
                logging.info("Take out operation cancelled by user (overwrite protection).")
                return
        
        try:
            EncryptionManager.decrypt_file_with_rsa(encrypted_file, dest_file, private_key, encrypted_key)
            
            confirm = buttonbox(
                f"Delete encrypted file from vault?\n\n{encrypted_file}",
                "Confirm Deletion",
                choices=["Yes", "No"]
            )
            if confirm == "Yes":
                if os.path.exists(encrypted_file):
                    os.remove(encrypted_file)
                    logging.info(f"Deleted encrypted file: {encrypted_file}")
            
            msgbox(f"File taken out and saved to: {dest_file}")
            logging.info(f"File taken out and saved to: {dest_file}")
        except Exception as e:
            msgbox(f"Take out failed: {e}")
            logging.error(f"Take out failed: {e}")
            logging.error(traceback.format_exc())
        reset_timer()  # Reset timer on successful retrieval

def main():
    """Main entry point."""
    logging.info("Vault application started")
    
    if check_lock_status():
        logging.warning("Vault is locked, exiting application")
        return
    
    if UserAuth.password_flow():
        reset_timer()  # Start timer on successful login
        Vault.open_vault()
        # Ensure timer is cancelled on exit
        global timer
        if timer is not None:
            timer.cancel()
            logging.debug("Auto-logout timer cancelled on exit")
    
    logging.info("Vault application exiting")
    logging.shutdown()

if __name__ == "__main__":
    main()