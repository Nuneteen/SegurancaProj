import socket
import json
import time
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
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

class Client:

    def __init__(self):
        self.connections = {}
        self.id = os.urandom(16)
        self.sa_data = None
        self.level = 0
        self.state = STATE_DISCONNECTED
        self.name = CLIENT_NAME

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

    def generateKeyPair(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return (private_key, public_key)

    def exchangeKey(self, private_key, peer_public_key):
        return private_key.exchange(ec.ECDH(), peer_public_key)

    def send(self, obj):
        try:
            s.send(json.dumps(obj) + TERMINATOR)
        except:
            logging.exception("Error send message: %s ", obj)

    def loop(self):
        while 1:
            msg = {'type': 'connect', 'phase': 1, 'name': self.name, 'id': 1564654564,  'ciphers': CIPHERS}
            self.serverConnect(msg)
            print("SERVER CONNECT!")
            break


    def parseReqs(self, data):
        return data.split(TERMINATOR)[:-1]

client = Client()
client.loop()