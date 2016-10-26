from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os

TEXT = "CENAS BUEDA CENAS"

my_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
peer_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())


my_public_key = my_private_key.public_key()
peer_public_key = peer_private_key.public_key()

shared_key1 = my_private_key.exchange(ec.ECDH(), peer_public_key)
shared_key2 = peer_private_key.exchange(ec.ECDH(), my_public_key)

iv = os.urandom(16)
cipher = Cipher(algorithms.AES(shared_key2), modes.CTR(iv), default_backend())
encryptor = cipher.encryptor()

ct = encryptor.update(TEXT) + encryptor.finalize()

print "Ciphered text: " + ct

#iv = os.urandom(16)
cipher = Cipher(algorithms.AES(shared_key1), modes.CTR(iv), default_backend())
decryptor = cipher.decryptor()
ot = decryptor.update(ct) + decryptor.finalize()

print "Original text: " + ot

serialized_key = my_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
print "serialized key: "
print serialized_key

loaded_public_key = serialization.load_pem_public_key(serialized_key,
                                                      backend=default_backend())

secret = peer_private_key.exchange(ec.ECDH(), loaded_public_key)
cipher = Cipher(algorithms.AES(secret), modes.CTR(iv), default_backend())
decryptor = cipher.decryptor()
ot = decryptor.update(ct) + decryptor.finalize()



shared3 = my_private_key + shared_key1
print  shared3