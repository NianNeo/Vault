from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.backends import default_backend
import os

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

from easygui import buttonbox, fileopenbox, msgbox

def main_menu():
	while True:
		choice = buttonbox(
			"Welcome to Vault!\nChoose an action:",
			"Vault",
			choices=["Encrypt File", "Decrypt File", "View Encrypted Files", "Help/About", "Exit"]
		)
		if choice == "Encrypt File":
			encrypt_gui()
		elif choice == "Decrypt File":
			decrypt_gui()
		elif choice == "View Encrypted Files":
			view_encrypted_files()
		elif choice == "Help/About":
			show_help()
		else:
			break
def view_encrypted_files():
	files_dir = "files"
	if not os.path.exists(files_dir):
		msgbox("No 'files' folder found.")
		return
	files = os.listdir(files_dir)
	enc_files = [f for f in files if f.startswith("encrypted_")]
	key_files = [f for f in files if f.endswith(".key")]
	if not enc_files:
		msgbox("No encrypted files found.")
		return
	msg = "Encrypted files and their AES keys:\n\n"
	for ef in enc_files:
		key_name = f"AES_{ef[len('encrypted_'):]}.key"
		msg += f"{ef}\n  Key: {key_name if key_name in key_files else 'Not found'}\n"
	msgbox(msg)

def show_help():
	msg = (
		"Vault - Digital File Encryption Tool\n\n"
		"Features:\n"
		"- Encrypt files using RSA and AES hybrid encryption.\n"
		"- Decrypt files (AES key auto-selected).\n"
		"- View all encrypted files and their AES keys.\n"
		"- Files are stored in the 'files' folder.\n"
		"- Encrypted files and keys are deleted after successful decryption.\n\n"
		"For best security, keep your RSA keys safe."
	)
	msgbox(msg, "Help/About")

def encrypt_gui():
	input_file = fileopenbox("Select file to encrypt:", default="*.*")
	if not input_file:
		return
	default_pubkey = "public_key.pem"
	if os.path.exists(default_pubkey):
		public_key = default_pubkey
	else:
		public_key = fileopenbox("Select RSA public key (.pem):", default="*.pem")
		if not public_key:
			return
	base_name = os.path.basename(input_file)
	files_dir = "files"
	if not os.path.exists(files_dir):
		os.makedirs(files_dir)
	output_file = os.path.join(files_dir, f"encrypted_{base_name}")
	encrypted_key_file = os.path.join(files_dir, f"AES_{base_name}.key")
	try:
		encrypt_file_with_rsa(input_file, output_file, public_key, encrypted_key_file)
		msgbox(f"File encrypted successfully!\nEncrypted file: {output_file}\nEncrypted AES key: {encrypted_key_file}")
	except Exception as e:
		msgbox(f"Encryption failed: {e}")

def decrypt_gui():
	encrypted_file = fileopenbox("Select encrypted file:", default="files/encrypted_*")
	if not encrypted_file:
		return
	private_key = fileopenbox("Select RSA private key (.pem):", default="*.pem")
	if not private_key:
		return
	# Automatically select AES key file based on encrypted file name
	base_name = os.path.basename(encrypted_file)
	files_dir = "files"
	if not os.path.exists(files_dir):
		os.makedirs(files_dir)
	key_name = base_name[len("encrypted_"):] if base_name.startswith("encrypted_") else base_name
	encrypted_key_file = os.path.join(files_dir, f"AES_{key_name}.key")
	if not os.path.exists(encrypted_key_file):
		msgbox(f"AES key file not found: {encrypted_key_file}")
		return
	if base_name.startswith("encrypted_"):
		output_file = os.path.join(files_dir, key_name)
	else:
		output_file = os.path.join(files_dir, f"decrypted_{base_name}")
	# Confirm deletion before proceeding
	confirm = buttonbox(
		f"After decryption, the following files will be deleted:\n\n{encrypted_file}\n{encrypted_key_file}\n\nContinue?",
		"Confirm Deletion",
		choices=["Yes", "No"]
	)
	if confirm != "Yes":
		msgbox("Decryption cancelled.")
		return
	try:
		decrypt_file_with_rsa(encrypted_file, output_file, private_key, encrypted_key_file)
		# Delete encrypted files after successful decryption
		if os.path.exists(encrypted_file):
			os.remove(encrypted_file)
		if os.path.exists(encrypted_key_file):
			os.remove(encrypted_key_file)
		msgbox(f"File decrypted successfully!\nDecrypted file: {output_file}\nEncrypted files deleted.")
	except Exception as e:
		msgbox(f"Decryption failed: {e}")

if __name__ == "__main__":
	main_menu()

