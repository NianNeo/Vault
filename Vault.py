import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from easygui import buttonbox, fileopenbox, msgbox, choicebox
import hashlib
import json
from cryptography.hazmat.backends import default_backend


VAULT_META_DIR = ".Vault_files"
if not os.path.exists(VAULT_META_DIR):
	os.makedirs(VAULT_META_DIR)
PUBLIC_KEY_FILE = os.path.join(VAULT_META_DIR, "vault_public_key.pem")
PASSWORD_FILE = os.path.join(VAULT_META_DIR, "vault_password.json")
PRIVATE_KEY_EXPORT = "key.pem"

# Migrate legacy password file if it exists
legacy_password_file = ".vault_password.json"
if os.path.exists(legacy_password_file):
	import shutil
	shutil.move(legacy_password_file, PASSWORD_FILE)

def hash_password(password):
	return hashlib.sha256(password.encode()).hexdigest()

def save_password(password):
	with open(PASSWORD_FILE, "w") as f:
		json.dump({"hash": hash_password(password)}, f)

def check_password(password):
	if not os.path.exists(PASSWORD_FILE):
		return False
	with open(PASSWORD_FILE, "r") as f:
		data = json.load(f)
	return hash_password(password) == data.get("hash")

def password_flow():
	# Generate RSA keys on first start
	if not os.path.exists(PUBLIC_KEY_FILE):
		intensity_choice = buttonbox(
			"Choose encryption intensity (RSA key size):",
			"Encryption Intensity",
			choices=["2048 (Standard)", "3072 (High)", "4096 (Maximum)"]
		)
		if intensity_choice == "4096 (Maximum)":
			key_size = 4096
		elif intensity_choice == "3072 (High)":
			key_size = 3072
		else:
			key_size = 2048
		private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
		public_key = private_key.public_key()
		# Save public key (hidden)
		with open(PUBLIC_KEY_FILE, "wb") as f:
			f.write(public_key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo
			))
		# Export private key for user
		with open(PRIVATE_KEY_EXPORT, "wb") as f:
			f.write(private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
				encryption_algorithm=serialization.NoEncryption()
			))
		msgbox(f"Your private key has been saved as '{PRIVATE_KEY_EXPORT}'. Please keep it safe!")
	if not os.path.exists(PASSWORD_FILE):
		from easygui import passwordbox
		while True:
			pwd1 = passwordbox("Set a password for your vault:")
			if not pwd1:
				return False
			pwd2 = passwordbox("Confirm password:")
			if pwd1 == pwd2:
				save_password(pwd1)
				msgbox("Password set! Please remember it.")
				return True
			else:
				msgbox("Passwords do not match. Try again.")
	else:
		from easygui import passwordbox
		attempts = 0
		while attempts < 3:
			pwd = passwordbox("Enter your vault password:")
			if pwd and check_password(pwd):
				return True
			else:
				msgbox("Incorrect password.")
				attempts += 1
		# After 3 failed attempts, offer reset
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

def encrypt_file_with_rsa(input_file, output_file, public_key_path, encrypted_key_file):
	# Load RSA public key
	with open(public_key_path, "rb") as key_file:
		public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

	# Generate AES key
	aes_key = os.urandom(32)  # AES-256
	iv = os.urandom(16)

	# Encrypt file with AES
	cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
		f_out.write(iv)  # Write IV at the start
		while True:
			chunk = f_in.read(4096)
			if not chunk:
				break
			f_out.write(encryptor.update(chunk))
		f_out.write(encryptor.finalize())

	# Encrypt AES key with RSA
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

def decrypt_file_with_rsa(encrypted_file, output_file, private_key_path, encrypted_key_file):
	# Load RSA private key
	with open(private_key_path, "rb") as key_file:
		private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

	# Load encrypted AES key
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

	# Decrypt file with AES
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

def open_vault():
	files_dir = "files"
	if not os.path.exists(files_dir):
		os.makedirs(files_dir)
	while True:
		files = os.listdir(files_dir)
		enc_files = [f for f in files if f.startswith("encrypted_")]
		choices = [os.path.basename(f)[len("encrypted_"): ] for f in enc_files]
		action = buttonbox(
			"Vault Contents:", "Vault",
			choices=["Store", "Take Out", "Reset Password", "Exit"],
			default_choice="Store"
		)
		if action == "Store":
			store_file()
		elif action == "Take Out":
			from easygui import fileopenbox
			file_choice_path = fileopenbox("Select encrypted file to take out:", default="files/encrypted_*")
			if not file_choice_path:
				msgbox("No file selected.")
				continue
			file_choice = os.path.basename(file_choice_path)[len("encrypted_"): ] if os.path.basename(file_choice_path).startswith("encrypted_") else os.path.basename(file_choice_path)
			take_out_file(file_choice)
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

def store_file():
	input_file = fileopenbox("Select file to store in vault:")
	if not input_file:
		return
	base_name = os.path.basename(input_file)
	files_dir = "files"
	output_file = os.path.join(files_dir, f"encrypted_{base_name}")
	encrypted_key_file = os.path.join(files_dir, f"AES_{base_name}.key")
	public_key = PUBLIC_KEY_FILE
	try:
		encrypt_file_with_rsa(input_file, output_file, public_key, encrypted_key_file)
		msgbox(f"File stored in vault!\nEncrypted file: {output_file}\nAES key: {encrypted_key_file}")
	except Exception as e:
		msgbox(f"Storing failed: {e}")

def take_out_file(file_name):
	files_dir = "files"
	encrypted_file = os.path.join(files_dir, f"encrypted_{file_name}")
	encrypted_key_file = os.path.join(files_dir, f"AES_{file_name}.key")
	if not os.path.exists(encrypted_file) or not os.path.exists(encrypted_key_file):
		msgbox("Encrypted file or AES key not found.")
		return
	private_key = fileopenbox("Select your private key (key.pem):", default="key.pem")
	if not private_key:
		msgbox("You must select a private key to take out the file.")
		return
	from easygui import diropenbox
	dest_dir = diropenbox("Choose folder to save the decrypted file:")
	if not dest_dir:
		return
	dest_file = os.path.join(dest_dir, file_name)
	try:
		decrypt_file_with_rsa(encrypted_file, dest_file, private_key, encrypted_key_file)
		# Confirm deletion
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

def main():
	if password_flow():
		open_vault()

if __name__ == "__main__":
	main()

