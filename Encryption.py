from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

usernames = ["Johnson"]

# Read file main to code
with open('Secret_file.txt', 'r') as file:
    text = file.read()

# Hash the text
hash_data = SHA256.new(text.encode())
hashed_text = hash_data.digest()


# Function to sign the message
def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    hash_data = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(hash_data)
    return signature


for user in usernames:
    with open(user + "private.pem", "rb") as private_file:
        private_key = private_file.read()
        signature = sign_message(text, private_key)
    with open(user + "signature.txt", "wb") as signaturer:
        signaturer.write(signature)

# Save the text along with the signature
for user in usernames:
    with open(user + "encrypted_text.txt", "wb") as encrypted_file:
        encrypted_file.write(hashed_text)
        encrypted_file.write(b'\n')
        encrypted_file.write(signature)


# Funtion to Encrypt the message
def encrypt_message(message, public_key):
    key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    ciphertext = cipher_rsa.encrypt(message.encode())
    return ciphertext


# Encrypt the file
for user in usernames:
    with open(user + "encrypted_text.txt", "rb") as file_to_encrypt:
        public_key = open(user + "public.pem", "rb").read()
        encrypted_data = encrypt_message(text, public_key)
    with open(user + "encrypted_file.bin", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    print("Text signed,saved and encrypted for. " + user)

