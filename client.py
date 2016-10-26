import socket
import json
import time
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

HOST = '127.0.0.1'  # The remote host
PORT = 8080         # The same port as used by the server

CLIENT_NAME = "Nuno"
CIPHERS = []
STATE_DISCONNECTED = 0
STATE_CONNECTED = 1
ACK = {'type': 'ack'}


BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# TODO Create Peer class: (id, sa_data, bufferin, bufferout, printBuffer())

class CipherHelper:
    def __init__(self, chipherSpec):
        self.cipherSpec = chipherSpec
        self.my_private_key = None
        self.my_public_key = None
        self.peer_public_key = None
        self.sharedKey = None
        self.iv = None

    def generateKeyPair(self):
        self.my_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.my_public_key = self.my_private_key.public_key()

    def exchangeSecret(self):
        self.sharedKey = self.my_private_key.exchange(ec.ECDH(), self.peer_public_key)

    def serialize(self):
        return self.my_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def deserialize(self, serialized_key):
        self.peer_public_key = serialization.load_pem_public_key(serialized_key,
                                                      backend=default_backend())

    def encrypt(self, data):
        self.iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.sharedKey), modes.CBC(self.iv), default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data):
        cipher = Cipher(algorithms.AES(self.sharedKey), modes.CBC(self.iv), default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

class Client:

    def __init__(self):
        self.connections = {}
        self.id = os.urandom(16)
        self.sa_data = None
        self.level = 0
        self.state = STATE_DISCONNECTED
        self.name = CLIENT_NAME

    # TODO def encapsulateSecure(message)
    # TODO def addPeer()
    # TODO def delPeer()

    def serverConnect(self, msg):
        while self.state == 0:
            try:
                print "CONNECT: "
                print msg
                self.send(msg)
            except:
                logging.exception("Could not send message: %s", msg)
                continue
            try:
                # waiting to receive data from server
                data = s.recv(BUFSIZE)
            except:
                logging.error("Received invalid data from Server")
                break

            try:
                data = self.parseReqs(data)
                response = json.loads(data[1])
            except:
                logging.exception("Connect messages received with errors")
                break
            else:
                if 'data' in response.keys():
                    # TODO Change function to the ones implemented in CipherHelper
                    # TODO Create a CipherHelper to this Peer
                    keys = self.generateKeyPair()
                    self.connections['server']['sa_data']['key'] = self.exchangeKey(keys[0], response['data']['key'])
                    self.connections['server']['sa_data']['cipher'] = response['ciphers'][0]
                    logging.info("Agreed cipher spec: " + response['ciphers'][0])
                    response['data']['key'] = keys[1]
                    self.send(response)
                    self.state = STATE_CONNECTED

                else:
                    i = 0
                    for cipher in response['ciphers']:
                        print(str(i) + ": " + cipher)
                        i += 1
                    cipher = raw_input()
                    msg['phase'] = response['phase'] + 1
                    msg['ciphers'] = response['ciphers'][int(cipher)]

    # TODO change this method to Peer class. Similary to Server's implementation
    def send(self, obj):
        try:
            s.send(json.dumps(obj) + TERMINATOR)
        except:
            logging.exception("Error send message: %s ", obj)


    def list(self):
        list = {'type':'list','data':[]}
        return list

    def clientconnect(self,dst):
        clientconn = {'type':'client-connect','src': self.id,'dst':dst,'phase':1,'ciphers':CIPHERS,'data':''}
        return clientconn

    def clientdisconnect(self,dst):
        clientdisc = {'type': 'client-disconnect', 'src': self.id, 'dst': dst, 'data': ''}
        return clientdisc

    def clientcom(self,dst,msg):
        #encrypt(msg)
        clientcom = {'type':'client-com','src': self.id, 'dst': dst, 'data':msg}
        return clientcom

    # TODO create func to parse the keyboard input. In resemblemse to the server's handleRequest. Name: handleKbInput

    def loop(self):
        # TODO finish this method. connect to server, exchange messages
        msg = {'type': 'connect', 'phase': 1, 'name': self.name, 'id': 1564654564, 'ciphers': CIPHERS}
        self.serverConnect(msg)
        print("SERVER CONNECT!")

        while 1:
            break

client = Client()
client.loop()