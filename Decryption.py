from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

user = input("Enter Your Username: ")


# Function to Decrypt the message
def decrypt_message(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    decrypted_data = cipher_rsa.decrypt(ciphertext)
    return decrypted_data.decode('utf-8')


# read text to code
with open('Secret_file.txt', 'r') as file:
    text = file.read()

with open(user + 'signature.txt', 'rb') as file1:
    signature = file1.read()


# Function to verify the signed message
def Veryify_signature(message, public_key):
    key = RSA.import_key(public_key)
    hash_data = SHA256.new(message)
    response = pkcs1_15.new(key).verify(hash_data, signature)
    return response


try:
    public_key = open(user + "public.pem", "rb").read()
    Veryify_signature(text.encode(), public_key)
    print("Message is still intact")

    # Decrypt the file
    with open(user + "encrypted_file.bin", "rb") as decrypted_file:
        private_key = open(user + "private.pem", "rb").read()
        decrypted_data = decrypt_message(decrypted_file.read(), private_key)
    with open(user + "decrypted_file.txt", "w") as decrypted_file:
        decrypted_file.write(decrypted_data)
    print(f"Text decrypted by {user} to : {decrypted_data}")
except(ValueError, TypeError):
    print("Message has been altered and can not be decrypted \n kindly refer to sender for signature")
