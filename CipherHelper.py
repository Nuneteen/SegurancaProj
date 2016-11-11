from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64, sys, json

def generateKeyPair(asAlg):
    if asAlg == 'ECDHE':
        privateK = ec.generate_private_key(ec.SECP256R1(), default_backend())
        publicK = privateK.public_key()
        publicK = serializeKey(publicK)

    elif asAlg == 'RSA':
        privateK = rsa.generate_private_key(public_exponent=655537,
                                            key_size=2048,
                                            backend=default_backend())
        publicK = privateK.public_key()
        publicK = publicK.public_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        print "Unknown Algoritm: " + asAlg
        sys.exit(1)

    return privateK, publicK

def exchangeSecret(privateK, publicK):
    return privateK.exchange(ec.ECDH(), publicK)

def serializeKey(key):
    return key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)

def deserializeKey(serialized_key):
    return serialization.load_pem_public_key(serialized_key,
                                             backend=default_backend())

def encrypt(peer, data):
    if isinstance(data, dict) or isinstance(data, str):
        try:
            data = json.dumps(data)
        except:
            # This code only executes if data is a key
            cipherText = peer.rsaKey.encrypt(data,
                                             padding.OAEP(
                                                 mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                 algorithm=hashes.SHA1(),
                                                 label=None
                                             ))
            return base64.b64encode(cipherText)
        else:
            mode = peer.cd.cipherSpec.split('-')[-2]
            iv = os.urandom(16)
            if mode == "CTR":
                cipher = Cipher(algorithms.AES(peer.cd.sharedKey), modes.CTR(iv), default_backend())
                encryptor = cipher.encryptor()
                encData = encryptor.update(data) + encryptor.finalize()
                return base64.b64encode(encData), base64.b64encode(iv)

            elif mode == "OFB":
                cipher = Cipher(algorithms.AES(peer.cd.sharedKey), modes.OFB(iv), default_backend())
                encryptor = cipher.encryptor()
                encData = encryptor.update(data) + encryptor.finalize()
                return base64.b64encode(encData), base64.b64encode(iv)

            elif mode == "CFB8":
                cipher = Cipher(algorithms.AES(peer.cd.sharedKey), modes.CFB8(iv), default_backend())
                encryptor = cipher.encryptor()
                encData = encryptor.update(data) + encryptor.finalize()
                return base64.b64encode(encData), base64.b64encode(iv)




def decrypt(peer, data, iv):
    data = base64.b64decode(data)
    mode = peer.cd.cipherSpec.split('-')[-2]
    if mode == 'CTR':
        cipher = Cipher(algorithms.AES(peer.cd.sharedKey), modes.CTR(iv), default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    elif mode == 'OFB':
        cipher = Cipher(algorithms.AES(peer.cd.sharedKey), modes.OFB(iv), default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    elif mode == 'CFB8':
        cipher = Cipher(algorithms.AES(peer.cd.sharedKey), modes.CFB8(iv), default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

def generateRSAPair():
    privateK = rsa.generate_private_key(public_exponent=655537,
                                        key_size=2048,
                                        backend=default_backend())
    publicK = privateK.public_key()
    serPublicK = publicK.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return (privateK, serPublicK)

def keyEncrypt(key, data):
    cipherText = key.encrypt(data,
                             padding.OAEP(
                                 mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                 algorithm=hashes.SHA1(),
                                 label = None
                             ))
    return base64.b64encode(cipherText)

def keyDecript(key, data):
    data = base64.b64decode(data)
    plaintext = key.decrypt(data,
                padding.OAEP(
                    mgf = padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm = hashes.SHA1(),
                    label = None
                )
    )
    return plaintext

def generateSymKey(size):
    return os.urandom(size/8)

def generateHMAC(peer,  message):
    mode = peer.cd.cipherSpec.split('-')[-1]
    key = peer.cd.sharedKey
    msg = json.dumps(message)
    if mode == 'SHA256':
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

    elif mode == 'SHA512':
        h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())

    else:
        print "Unsupported hash algorithm"
        return

    h.update(msg)
    return base64.b64encode(h.finalize())

def checkHMAC(peer, message, rcHMAC):
    mode = peer.cd.cipherSpec.split('-')[-1]
    key = peer.cd.sharedKey
    if mode == 'SHA256':
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

    elif mode == 'SHA512':
        h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())

    else:
        print "Unsupported hash algorithm"
        return

    try:
        del message['sa-data']['hash']
    except:
        try:
            del message['data']['hash']
        except:
            print "Error in dict"
        else:
            msg = json.dumps(message)
            h.update(msg)
            myHMAC = base64.b64encode(h.finalize())
            return myHMAC == rcHMAC
    else:
        msg = json.dumps(message)
        h.update(msg)
        myHMAC = base64.b64encode(h.finalize())
        return myHMAC == rcHMAC