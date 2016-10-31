from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64

def generateKeyPair(peer):
    peer.sa_data.my_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    peer.sa_data.my_public_key = peer.sa_data.my_private_key.public_key()

def exchangeSecret(peer):
    peer.sa_data.sharedKey = peer.sa_data.my_private_key.exchange(ec.ECDH(), peer.sa_data.peer_public_key)

def serializeKey(peer):
    return peer.sa_data.my_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)

def deserializeKey(peer, serialized_key):
    peer.sa_data.peer_public_key = serialization.load_pem_public_key(serialized_key,
                                                             backend=default_backend())

def encrypt(peer, data):
    peer.sa_data.iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(peer.sa_data.sharedKey), modes.CTR(peer.sa_data.iv), default_backend())
    encryptor = cipher.encryptor()
    encData = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(encData)

def decrypt(peer, data, iv):
    data = base64.b64decode(data)
    cipher = Cipher(algorithms.AES(peer.sa_data.sharedKey), modes.CTR(iv), default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def showPriv(peer):
    print peer.sa_data.my_private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PrivateFormat.PKCS8,
                                                                encryption_algorithm=serialization.BestAvailableEncryption(None)
                                                                )
    return

def showPub(peer):
    print peer.sa_data.my_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return