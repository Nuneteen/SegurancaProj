# encoding: utf-8

import OpenSSL.crypto as openssl
import PyKCS11
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64, sys, json, copy
from oscrypto import asymmetric
from ocspbuilder import OCSPRequestBuilder
import urllib2
import asn1crypto
import uuid
import cpuinfo
import platform

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
        print "Unknown Algorithm: " + asAlg
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

def encrypt(peer, data, iv=None):
    if isinstance(data, dict) or isinstance(data, str):
        try:
            data = json.dumps(data, sort_keys=True)
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
            mode = peer.cipher_spec.split('-')[-2]
            if iv is None:
                iv = os.urandom(16)
            if mode == "CTR":
                cipher = Cipher(algorithms.AES(peer.shared_key), modes.CTR(iv), default_backend())
                encryptor = cipher.encryptor()
                encData = encryptor.update(data) + encryptor.finalize()
                return base64.b64encode(encData), base64.b64encode(iv)

            elif mode == "OFB":
                cipher = Cipher(algorithms.AES(peer.shared_key), modes.OFB(iv), default_backend())
                encryptor = cipher.encryptor()
                encData = encryptor.update(data) + encryptor.finalize()
                return base64.b64encode(encData), base64.b64encode(iv)

            elif mode == "CFB8":
                cipher = Cipher(algorithms.AES(peer.shared_key), modes.CFB8(iv), default_backend())
                encryptor = cipher.encryptor()
                encData = encryptor.update(data) + encryptor.finalize()
                return base64.b64encode(encData), base64.b64encode(iv)




def decrypt(peer, data, iv, key=None):
    if key is None:
        data = base64.b64decode(data)
        mode = peer.cipher_spec.split('-')[-2]
        if mode == 'CTR':
            cipher = Cipher(algorithms.AES(peer.shared_key), modes.CTR(iv), default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()

        elif mode == 'OFB':
            cipher = Cipher(algorithms.AES(peer.shared_key), modes.OFB(iv), default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()

        elif mode == 'CFB8':
            cipher = Cipher(algorithms.AES(peer.shared_key), modes.CFB8(iv), default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()
    else:
        data = base64.b64decode(data)
        plaintext = key.decrypt(data,
                                padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA1()),
                                             algorithm = hashes.SHA1(),
                                             label = None))
        return plaintext

def generateRSAPair():
    privateK = rsa.generate_private_key(public_exponent=655537,
                                        key_size=2048,
                                        backend=default_backend())
    publicK = privateK.public_key()
    serPublicK = publicK.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return (privateK, serPublicK)


def generateSymKey(size):
    return os.urandom(size/8)

def generateHMAC(peer,  message):
    mode = peer.cipher_spec.split('-')[-1]
    key = peer.shared_key
    msg = json.dumps(message, sort_keys=True)
    if mode == 'SHA256':
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

    elif mode == 'SHA512':
        h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())

    else:
        print "Unsupported hash algorithm"
        return

    h.update(msg)
    return base64.b64encode(h.finalize())

def generateHash(data):
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    hash =  digest.finalize()
    return base64.b64encode(hash)

def checkHash(message, rchmac):
    try:
        del message['sa-data']['hash']
        del message['sa-data']['signature']
    except:
        try:
            del message['data']['hash']
            del message['data']['signature']
        except:
            print "Error in dict"
        else:
            myHMAC = generateHash(message)
            return myHMAC == rchmac
    else:
        myHMAC = generateHash(message)
        return myHMAC == rchmac

def generateAck(message):
    h = generateHash(message)
    ack = {'type': 'ack', 'hash': h}
    return ack


def checkHMAC(peer, message, rcHMAC):
    m = copy.deepcopy(message)
    mode = peer.cipher_spec.split('-')[-1]
    key = peer.shared_key
    if mode == 'SHA256':
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

    elif mode == 'SHA512':
        h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())

    else:
        print "Unsupported hash algorithm"
        return

    try:
        del m['sa-data']['hash']
        del m['sa-data']['signature']
    except:
        try:
            del m['data']['hash']
            del m['data']['signature']
        except:
            print "Error in dict"
        else:
            msg = json.dumps(m, sort_keys=True)
            h.update(msg)
            myHMAC = base64.b64encode(h.finalize())
            return myHMAC == rcHMAC
    else:
        msg = json.dumps(m, sort_keys=True)
        h.update(msg)
        myHMAC = base64.b64encode(h.finalize())
        return myHMAC == rcHMAC

############################# SmartCard Stuff ###########################

def getSesion(pin=None, lib='libpteidpkcs11.so', slot=0):
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)

    slot = pkcs11.getSlotList()[slot]
    session = pkcs11.openSession(slot)
    if pin is not None:
        try:
            session.login(pin)
            return session
        except:
            print "Invalid pin"
            return None
    return session

def getCertificate(session, label='CITIZEN AUTHENTICATION CERTIFICATE'):

    all_attributes = [e for e in PyKCS11.CKA.keys() if isinstance(e, int)]
    o = session.findObjects(template=[(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_LABEL, label)])
    attributes = session.getAttributeValue(o[0], all_attributes)
    z = dict(zip(all_attributes, attributes))
    b = ''.join(map(chr, z[PyKCS11.CKA_VALUE]))
    return openssl.load_certificate(openssl.FILETYPE_ASN1, b)

def loadCertificate(data, b64enc=True):
    if b64enc:
        data = base64.b64decode(data)
    try:
        certificate = openssl.load_certificate(openssl.FILETYPE_ASN1, data)
    except:
        certificate = openssl.load_certificate(openssl.FILETYPE_PEM, data)
    return certificate

def loadRSAkey(filename, passphrase=None):
    f = open(filename, 'rb').read()
    try:
        key = openssl.load_privatekey(openssl.FILETYPE_ASN1, f, passphrase)
    except:
        key = openssl.load_privatekey(openssl.FILETYPE_PEM, f, passphrase)
    return key

def dumpCertificate(certificate, b64=True):
    cert = openssl.dump_certificate(openssl.FILETYPE_ASN1, certificate)
    if b64:
        return base64.b64encode(cert)
    return cert

def getName(certificate):
    name = certificate.get_subject().CN
    return name

def getId(certificate):
    sn = certificate.get_subject().serialNumber
    id = sn[2:]
    return int(id)

def signData(data, session=None, key=None):
    if session is not None:
        # key_handler = session.findObjects(template=[(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY")])
        key_handler = session.findObjects()[0]
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")
        signature =  session.sign(key_handler, data, mechanism)
        return base64.b64encode(''.join(map(chr, signature)))
    signature = openssl.sign(key, data, b"sha1")
    return base64.b64encode(signature)

def validateSignature(certificate, data, signature, session=None):
    signature = base64.b64decode(signature)
    # validate with SmartCard
    if session is not None:
        public_key = certificate.get_pubkey()
        return session.verify(public_key, data, signature)

    # validate with openssl
    try:
        openssl.verify(certificate,signature, data, b"sha1")
        return True
    except:
        return False

def loadStore():
    store = openssl.X509Store()
    store.set_flags(openssl.X509StoreFlags.POLICY_CHECK | openssl.X509StoreFlags.X509_STRICT)
    for filename in os.listdir('./CCCerts'):
        f = open('CCCerts/' + filename, 'rb')
        fbytes = f.read()
        try:
            cert = openssl.load_certificate(openssl.FILETYPE_ASN1, fbytes)
        except:
            cert = openssl.load_certificate(openssl.FILETYPE_PEM, fbytes)
        store.add_cert(cert)
    return store

def getIssuerCertificate(certificate):
    issuer = certificate.get_issuer()
    for filename in os.listdir('./CCCerts'):
        f = open('CCCerts/' + filename, 'rb')
        fbytes = f.read()
        try:
            cert = openssl.load_certificate(openssl.FILETYPE_ASN1, fbytes)
        except:
            cert = openssl.load_certificate(openssl.FILETYPE_PEM, fbytes)
        if issuer == cert.get_subject():
            return cert


def validateCert(store, cert, server=False):

    if not server:
        issuer = getIssuerCertificate(cert)

        subject_cert = asymmetric.load_certificate(dumpCertificate(cert, False))
        issuer_cert = asymmetric.load_certificate(dumpCertificate(issuer, False))

        builder = OCSPRequestBuilder(subject_cert, issuer_cert)
        ocsp_request_der = builder.build().dump()

        cert_name = cert.get_subject().commonName

        if cert_name in ('Baltimore CyberTrust Root', 'ECRaizEstado'):
            ocsp_url = 'http://ocsp.omniroot.com/baltimoreroot/'
        elif cert_name[:-4] == 'Cartao de Cidadao':
            ocsp_url = 'http://ocsp.ecee.gov.pt/'
        elif cert_name[:-5] == 'EC de Autenticacao do Cartao de Cidadao':
            ocsp_url = 'http://ocsp.root.cartaodecidadao.pt/publico/ocsp'
        else:
            ocsp_url = 'http://ocsp.auc.cartaodecidadao.pt/publico/ocsp'

        http_req = urllib2.Request(
            ocsp_url,
            data=ocsp_request_der,
            headers={'Content-Type': 'application/ocsp-request'}
        )
        http = urllib2.urlopen(http_req)
        ocsp_response_der = http.read()
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(ocsp_response_der)
        response_data = ocsp_response.basic_ocsp_response['tbs_response_data']
        cert_response = response_data['responses'][0]

        if cert_response['cert_status'].name != 'good':
            return False

    context_store = openssl.X509StoreContext(store, cert)
    try:
        context_store.verify_certificate()


        return True
    except:
        return False

def getDeviceId():
    cpu = cpuinfo.get_cpu_info()
    del cpu['hz_actual_raw']
    del cpu['hz_actual']
    macAdd = uuid.getnode()
    cpu['mac'] = macAdd
    cpu['platform'] = platform.platform()
    cpu = json.dumps(cpu, sort_keys=True)
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(cpu)
    hash = digest.finalize()
    return base64.b64encode(hash)


def searchingSmartCards():
    # flags = []
    # print 'searching for smartcards...'
    # while PyKCS11.CKF_TOKEN_PRESENT not in flags:
    #     slot_info = pkcs11.getSlotInfo(0)
    #     flags = slot_info.flags2text()
    #     if PyKCS11.CKF_TOKEN_PRESENT not in flags:
    #         time.sleep(0.1)
    pass
    return
