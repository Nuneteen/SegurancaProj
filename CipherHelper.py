from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generateKeyPair(client):
    client.my_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client.my_public_key = client.my_private_key.public_key()

def exchangeSecret(client):
    client.sharedKey = client.my_private_key.exchange(ec.ECDH(), client.peer_public_key)

def serializeKey(client):
    return client.my_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)

def deserializeKey(client, serialized_key):
    client.peer_public_key = serialization.load_pem_public_key(serialized_key,
                                                  backend=default_backend())

def encrypt(client, data):
    client.iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(client.sharedKey), modes.CBC(client.iv), default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def decrypt(client, data):
    cipher = Cipher(algorithms.AES(client.sharedKey), modes.CBC(client.iv), default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()