from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64


# Function generate Key pairs for the n number of recepient users
def generate_keys(username):
    for user in username:
        key = RSA.generate(bits=2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        with open(user + "private.pem", "wb") as private_file:
            private_file.write(private_key)
        with open(user + "public.pem", "wb") as public_file:
            public_file.write(public_key)


# Generate RSA keys for as many number of users
usernames = ["Johnson"]
generate_keys(usernames)