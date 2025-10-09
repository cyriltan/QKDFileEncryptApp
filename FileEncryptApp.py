import os
import time
import json
import subprocess
import base64
import requests
import oqs
from pprint import pprint
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from pathlib import Path

# Please change the location of the certs
enc_url = 'https://ec2-3-113-86-199.ap-northeast-1.compute.amazonaws.com/api/v1/keys/SA00000006/enc_keys --cacert /home/cyriltan/certificates/KMSEmulator/cacert.crt --cert /home/cyriltan/certificates/KMSEmulator/SA00000007.crt --key /home/cyriltan/certificates/KMSEmulator/SA00000007.key' 


# Build the curl command
curl_enc_command = f"curl -k {enc_url}"

# Function to generate and save a key
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Function to generate and save a Dilithium3 key pair (also known as ML-DSA now)
def generate_dilithium3_keypair():
    print("liboqs version:", oqs.oqs_version())
    print("liboqs-python version:", oqs.oqs_python_version())
    print("Enabled signature mechanisms:")
    sigs = oqs.get_enabled_sig_mechanisms()
    pprint(sigs, compact=True)

    # Specify the signing algorithm
    sigalg = "Dilithium3"
    with oqs.Signature(sigalg) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

    # Save the public key to a file
    with open("public_key.pem", "wb") as f:
        f.write(public_key)

    # Save the private key securely
    with open("private_key.pem", "wb") as f:
        f.write(private_key)

    print("Dilithium3 key pair generated and saved.")

# Function to load the key
def loadQKDkey():
#    return open("secret.key", "rb").read()
    # Run the curl command Get keys command and capture the output
    result = subprocess.run(curl_enc_command, shell=True, check=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#    print(result.stdout)

    data = json.loads(result.stdout)

#    key_value = data.get('"key"')
    key_value = data['keys'][0]['key']
    key_id = data['keys'][0]['key_ID']

    return (key_value, key_id)

# Function to decode the quantum key based on the key ID
def DecodeQKDkey(key_id):
    command = [
        "curl",
        f"https://ec2-52-197-156-199.ap-northeast-1.compute.amazonaws.com/api/v1/keys/SA00000007/dec_keys?key_ID={key_id}",
        "--cacert", "/home/cyriltan/certificates/KMSEmulator/cacert.crt",
        "--cert", "/home/cyriltan/certificates/KMSEmulator/SA00000006.crt",
        "--key", "/home/cyriltan/certificates/KMSEmulator/SA00000006.key"
    ]
# Please change the location of the certs above.

#    print(command)
    result = subprocess.run(command, capture_output=True, text=True)
#    print(result.stdout)
    data = json.loads(result.stdout)

    if "keys" in data and data["keys"]:
        key_value = data['keys'][0]['key']
        key_id = data['keys'][0]['key_ID']

    else:
        # If keys are not present, return the error message
        key_id = 0
        key_value = data['message']

    return (key_value, key_id)

# Function to encrypt a file
def encrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        key, key_id = loadQKDkey()
        f = Fernet(key)
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)

        # Zeroize the key in memory immediately since we no longer need it
        key = 0

        # Append key_id as a tag in a length-value format with tag 0xFF
        key_id_bytes = key_id.encode('utf-8')  # Convert key_id to bytes
        key_id_length = len(key_id_bytes).to_bytes(2, byteorder='big')  # Use 2 bytes for length
        tag = b'\xFF'
        tagged_encrypted_data = encrypted_data + tag + key_id_length + key_id_bytes

        with open(file_path + ".encrypted", "wb") as file:
            file.write(tagged_encrypted_data)

        print("liboqs version:", oqs.oqs_version())
        print("liboqs-python version:", oqs.oqs_python_version())
        print("Enabled signature mechanisms:")
        sigs = oqs.get_enabled_sig_mechanisms()
        pprint(sigs, compact=True)

        # message = "This is the message to sign".encode()
        # Convert the tagged encrypted data to a Base64-encoded string and encode
        tagged_encrypted_string = base64.b64encode(tagged_encrypted_data).decode('utf-8')
        message = tagged_encrypted_string.encode()

        # Set the public key paths
        directory_path = Path(file_path).parent
        public_key_path = directory_path / "public_key.pem"

        # Sign the encrypted file data
        sigalg = "Dilithium3"
        with oqs.Signature(sigalg) as signer:

            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()

            signature = signer.sign(message)
            # Save the public key to a file
            with open(public_key_path, "wb") as f:
                f.write(public_key)

        # Save the signature
        signature_file_path = file_path + ".signature"
        with open(signature_file_path, "wb") as f:
            f.write(signature)

        messagebox.showinfo("Success", "File encrypted and signed successfully!")
        print("Signature saved to:", signature_file_path)

# Function to encrypt all files in a folder
def encrypt_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                key, key_id = loadQKDkey()
                f = Fernet(key)
                with open(file_path, "rb") as file:
                    file_data = file.read()
                encrypted_data = f.encrypt(file_data)
                key = 0

                # Append key_id as a tag in a length-value format with tag 0xFF
                key_id_bytes = key_id.encode('utf-8')  # Convert key_id to bytes
                key_id_length = len(key_id_bytes).to_bytes(2, byteorder='big')  # Use 2 bytes for length
                tag = b'\xFF'
                tagged_encrypted_data = encrypted_data + tag + key_id_length + key_id_bytes

                with open(file_path + ".encrypted", "wb") as file:
                    file.write(tagged_encrypted_data)
                time.sleep(1)
        messagebox.showinfo("Success", "All files in the folder have been encrypted!")

# Function to decrypt a file
def decrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, "rb") as file:
            encrypted_data_with_tag = file.read()

        # Let's verify the signature first
        signature_path = file_path.replace(".encrypted", ".signature")
        if not os.path.exists(signature_path):
            messagebox.showerror("Error", "Signature file not found!")
            return

        # Convert to Base64 encoding (same format used during signing)
        encoded_message = base64.b64encode(encrypted_data_with_tag).decode('utf-8').encode()

        with open(signature_path, "rb") as file:
            signature = file.read()

        directory_path = Path(file_path).parent
        public_key_path = directory_path / "public_key.pem"

        with open(public_key_path, "rb") as file:
            public_key = file.read()

        # Verify signature
        sigalg = "Dilithium3"
        with oqs.Signature(sigalg) as verifier:
            is_valid = verifier.verify(encoded_message, signature, public_key)

        if is_valid:
            messagebox.showinfo("Success", "PQC Signature is valid!")
            print("Signature verified successfully!")
        else:
            messagebox.showerror("Error", "PQC Signature verification failed!")
            print("Invalid signature!")


        # Locate the 0xFF tag
        tag_index = encrypted_data_with_tag.rfind(b'\xFF')
        if tag_index == -1:
#            raise ValueError("Tag 0xFF not found in the file.")
             messagebox.showerror("Error", f"This file is not encrypted using NQSN+ keys")
        else:
            # Extract the key_id length and key_id using the tag location
            key_id_length = int.from_bytes(encrypted_data_with_tag[tag_index + 1:tag_index + 3], byteorder='big')
            key_id = encrypted_data_with_tag[tag_index + 3:tag_index + 3 + key_id_length]

            # The actual encrypted data is the remaining part before the tag
            encrypted_data = encrypted_data_with_tag[:tag_index]

            key, extracted_key_id = DecodeQKDkey(key_id.decode('utf-8'))
#            print(key)
#            print(extracted_key_id)

            if (extracted_key_id == 0):
                messagebox.showerror("Error", key) # key will store the error message
            else:
                f = Fernet(key)
                try:
                    decrypted_data = f.decrypt(encrypted_data)
                    key = 0 # zeroize the key in memory immediately since we no longer need it
                    with open(file_path.replace(".encrypted", ".decrypted"), "wb") as file:
                        file.write(decrypted_data)
                    messagebox.showinfo("Success", "File decrypted successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decrypt the file: {e}")

# Function to decrypt all files in a folder
def decrypt_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".encrypted"):
                    time.sleep(1)
                    file_path = os.path.join(root, file)
                    with open(file_path, "rb") as file:
                        encrypted_data_with_tag = file.read()

                    # Locate the 0xFF tag
                    tag_index = encrypted_data_with_tag.rfind(b'\xFF')
                    if tag_index == -1:
#                       raise ValueError("Tag 0xFF not found in the file.")
                        messagebox.showerror("Error", f"This file is not encrypted using NQSN+ keys")

                    else:
                        # Extract the key_id length and key_id using the tag location
                        key_id_length = int.from_bytes(encrypted_data_with_tag[tag_index + 1:tag_index + 3], byteorder='big')
                        key_id = encrypted_data_with_tag[tag_index + 3:tag_index + 3 + key_id_length]

                        # The actual encrypted data is the remaining part before the tag
                        encrypted_data = encrypted_data_with_tag[:tag_index]

                        key, extracted_key_id = DecodeQKDkey(key_id.decode('utf-8'))

                        if (extracted_key_id == 0):
                            messagebox.showerror("Error", key) # key will store the error message
                        else:
                            f = Fernet(key)
                            try:
                                decrypted_data = f.decrypt(encrypted_data)
                                key = 0 # zeroize the key in memory immediately since we no longer need it
                                with open(file_path.replace(".encrypted", ".decrypted"), "wb") as file:
                                    file.write(decrypted_data)
                            except Exception as e:
                                messagebox.showerror("Error", f"Failed to decrypt the file: {e}")
        messagebox.showinfo("Success", "All files in the folder have been decrypted!")


# Main application window
def create_app():
    app = tk.Tk()
    app.title("QKD-based File Encryptor/Decryptor Program")

    # Button configurations
    button_width = 50  # Increased button width
    button_height = 4  # Increased button height

    encrypt_button = tk.Button(app, text="Encrypt a File", command=encrypt_file, width=button_width, height=button_height)
    encrypt_button.pack(pady=10)

    decrypt_button = tk.Button(app, text="Decrypt a File", command=decrypt_file, width=button_width, height=button_height)
    decrypt_button.pack(pady=10)

    encrypt_folder_button = tk.Button(app, text="Encrypt a Folder", command=encrypt_folder, width=button_width, height=button_height)
    encrypt_folder_button.pack(pady=10)  # Increased padding around button

    decrypt_folder_button = tk.Button(app, text="Decrypt a Folder", command=decrypt_folder, width=button_width, height=button_height)
    decrypt_folder_button.pack(pady=10)  # Increased padding around button

    genkeypair_button = tk.Button(app, text="Generate a PQC keypair", command=generate_dilithium3_keypair, width=button_width, height=button_height)
    genkeypair_button.pack(pady=10)  # Increased padding around button

    app.geometry("700x500")
    app.mainloop()

# Generate the key (only once)
# generate_key()

# Start the app
create_app()
