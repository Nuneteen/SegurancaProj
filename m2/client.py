# encoding: utf-8

import socket, select
import logging
from utils import *
import base64
import argparse
import random
import time
import json

HOST = '127.0.0.1'  # The remote host
CIPHERS = ["ECDHE-RSA-AES256-CTR-SHA512",  # default supported cipher specs
           "ECDHE-RSA-AES256-OFB-SHA256",
           "ECDHE-RSA-AES256-CTR-SHA512",
           "ECDHE-RSA-AES256-OFB-SHA512",
           ]
STATE_DISCONNECTED = 2
STATE_CONNECTED = 1
ACK = {'type': 'ack'}
ID = random.randint(0, 99999)
TERMINATOR = "\n\n"
SERVER = 0


def int_positive(value):
    ivalue = int(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return ivalue

def boolean(value):
    if value == 'true':
        return True
    elif value == 'false':
        return False
    raise argparse.ArgumentTypeError("%s is an invalid boolean value" % value)


parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('Name', metavar='NAME', type=str,
                    help='Username to use on app')
parser.add_argument('-p', '--port', help='set port to use', type=int_positive,
                    default=8080)
parser.add_argument('-s', '--slot', help='set slot to read data from', type=int_positive,
                    default=0)
parser.add_argument('-l', '--list', nargs='+', type=str)

parser.add_argument('--pin', help='require pin to login', type=str, default='true')

args = parser.parse_args()
PORT = args.port
PIN = args.pin
CLIENT_NAME = args.Name
SLOT = args.slot
STORE = loadStore()

if args.list:
    CIPHERS = []
    for i in args.list:
        CIPHERS += [i]

if args.list:
    SLOT = args.slot

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))


class ExchangeData:
    def __init__(self):
        self.my_private_key = None
        self.my_public_key = None
        self.peer_public_key = None

class Peer:
    def __init__(self, id, name='Unknown'):
        self.id = id
        self.state = None
        self.name = name
        self.rsaKey = None
        self.shared_key = None
        self.cipher_spec = ''
        self.level = 0
        self.certificate = None
        self.level = -1
        self.validated = False
        self.challenge = os.urandom(256)

    def __str__(self):
        return "Peer (id=%r name:%s level:%d cipher_spec:%s)" % (self.id, self.name, self.level, self.cipher_spec)


class Server(Peer):
    def __init__(self):
        Peer.__init__(self,0, 'Server')
        self.exchange_data = ExchangeData()
        self.client_ids = []

class Client:
    def __init__(self, session, pin):
        self.session = session
        self.certificate = getCertificate(self.session)
        self.id = getId(self.certificate)
        self.cd = None
        self.level = 0
        self.state = None
        self.name = getName(self.certificate)
        self.peer_list = {}
        self.rsaKeys = generateRSAPair()
        self.level = 0
        self.messages = {}
        self.device = getDeviceId()
        # This line is only to prompt for user pin
        if pin:
            signData("autenticate", self.session)
        print ("Welcome %s - %d") % (self.name, self.id)

    def addPeer(self, id, name='Unknown'):
        if id in self.peer_list.keys():
            logging.error("Peer NOT Added: %s already exists", self.peer_list[id])
            return
        if id == SERVER:
            peer = Server()
        else:
            peer = Peer(id, name)

        self.peer_list[peer.id] = peer
        print "Peer added. Waiting until a secure connection is established..." + str(id)
        return

    def delPeer(self, id):
        if id not in self.peer_list.keys():
            logging.error("Peer NOT deleted: %s not found", self.peer_list[id])
            return

        peer = self.peer_list[id]
        assert peer.id == id, "peer.id (%s) should match key (%s)" % (peer.id, id)
        name = peer.name
        del self.peer_list[peer.id]
        print "Peer disconnected: " + name
        return

    def send(self, obj):
        try:
            msg = json.dumps(obj, sort_keys=True)
            s.send(msg + TERMINATOR)
        except:
            logging.exception("Error send message: %s ", obj)

    def encapsulateSecure(self, message):
        server = self.peer_list[SERVER]
        # Generate a new secret for each message sent


        tmp_private_key, tmp_public_key = generateKeyPair('ECDHE')
        server.shared_key = exchangeSecret(tmp_private_key,
                                           server.exchange_data.peer_public_key)

        cipherText, iv = encrypt(server, message)
        secure = {'type': 'secure', 'payload': cipherText}
        secure['sa-data'] = {'iv': iv, 'public-key': tmp_public_key}
        hmac = generateHash(secure)
        secure['sa-data']['hash'] = hmac

        # TODO remove this
        if PIN:
            secure['sa-data']['signature'] = signData(hmac, self.session)
        else:
            secure['sa-data']['signature'] = "123456"

        if message['type'] != 'ack' and message['type'] != 'list':
            h = generateHash(message)
            self.messages[h] = message
        return secure

    def generateAck(self, message, peer):
        if peer.id == SERVER:
            h = generateHash(message)
            ack = {'type': 'ack', 'hash': h}
            return ack

        h = generateHash(message)
        msg = {'type': 'ack', 'src': self.id, 'dst': message['src'], 'hash' : h, 'data': {}}
        hmac = generateHash(msg)
        msg['data']['hash'] = hmac
        msg['data']['signature'] = signData(hmac, self.session)
        return msg

    def list(self):
        return {'type': 'list'}

    def clientConnect(self, dst):
        peer = self.peer_list[int(dst)]
        client_conn = {'type': 'client-connect', 'src': self.id, 'dst': dst, 'phase': 1, 'ciphers': CIPHERS, 'level': self.level}
        client_conn['data'] = {'key': self.rsaKeys[1], 'name': self.name, 'certificate': dumpCertificate(self.certificate),
                               'challenge': base64.b64encode(peer.challenge)}
        return client_conn

    def clientDisconnect(self, dst):
        client_disc = {'type': 'client-disconnect', 'src': self.id, 'dst': dst, 'data': {}}
        hmac = generateHash(client_disc)
        client_disc['data']['hash'] = hmac
        client_disc['data']['signature'] = signData(hmac, self.session)
        return client_disc

    def clientCom(self, dst, msg):
        peer = self.peer_list[int(dst)]
        # Generate new sym key
        key = generateSymKey(256)

        # Encrypting text with current sym key and encrypting the new sym key with peer's RSA key
        cipheredText, iv = encrypt(peer, msg)
        new_key = encrypt(peer, key)

        client_com = {'type': 'client-com', 'src': self.id, 'dst': dst, 'data': {'text': cipheredText, 'public-key': new_key,
                                                                                 'iv': iv, 'uuid': self.device}}
        hmac = generateHash(client_com)
        client_com['data']['hash'] = hmac
        client_com['data']['signature'] = signData(hmac, self.session)

        # Update shared key
        peer.shared_key = key

        return client_com

    def connect(self):
        # TODO make chalange
        if not SERVER in self.peer_list.keys():
            self.addPeer(SERVER)
        server = self.peer_list[SERVER]
        msg = {'type': 'connect', 'phase': 1, 'name': self.name, 'id': self.id, 'ciphers': CIPHERS}
        msg['data'] = {'certificate': dumpCertificate(self.certificate), 'challenge': base64.b64encode(server.challenge)}

        h = generateHash(msg)
        self.messages[h] = msg
        return msg

    def handleInput(self, input):
        fields = input.split()

        if fields[0] == 'quit':
            sys.exit(0)

        if fields[0] == 'connect':
            msg = self.connect()
            self.send(msg)
            return

        if self.state == STATE_DISCONNECTED:
            print "Can't communicate until a secure session is established with the server"
            return

        if fields[0] == 'list':
            data = self.encapsulateSecure(self.list())
            self.send(data)
            return

        elif fields[0] == 'client-connect':
            if self.id == int(fields[1]):
                print "cannot connect with yourself"
                return
            self.addPeer(int(fields[1]))
            msg = self.clientConnect(fields[1])
            if msg is not None:
                data = self.encapsulateSecure(msg)
                self.send(data)
            return

        elif fields[0] == 'client-com':
            if not int(fields[1]) in self.peer_list.keys():
                logging.exception("Peer not connected to client")
                return

            message = ' '.join(fields[2:])
            data = self.encapsulateSecure(self.clientCom(fields[1], message))
            self.send(data)
            return

        elif fields[0] == 'client-disconnect':
            data = self.encapsulateSecure(self.clientDisconnect(fields[1]))
            self.send(data)
            return

        elif fields[0] == 'peerlist':
            for peer in self.peer_list:
                print self.peer_list[peer]
            return

        elif fields[0] == 'messages':
            if len(self.messages) == 0:
                print "No messages waiting for ack"
                return
            print "Messages waiting for ack"
            for m in self.messages:
                print "%s - %s" % (m, self.messages[m])
            return

        else:
            logging.error("Invalid input")
            return

    def parseReqs(self, data):
        reqs = data.split(TERMINATOR)
        return reqs[:-1]

    def handleRequest(self, request):
        server = self.peer_list[SERVER]
        try:
            logging.info("HANDLING message from server: %r", repr(request))

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            if req['type'] == 'ack':
                self.processAck(req)
                return

            if req['type'] == 'connect':
                ack = {'type': 'ack', 'hash': generateHash(request)}
                self.send(ack)
                self.processConnect(req)

            elif req['type'] == 'secure':
                self.processSecure(server, req)

        except Exception, e:
            logging.exception("Could not handle request")

    def processConnect(self, response):
        msg = {'type': 'connect', 'phase': response['phase'] + 1, 'name': self.name, 'id': self.id, 'ciphers': CIPHERS}
        server = self.peer_list[SERVER]

        if len(response['ciphers']) == 0:
            logging.error("No ciphers supported between server and client")
            sys.exit(1)

        if 'error' in response['data']:
            print (response['data']['error'])
            sys.exit(1)

        if not server.validated:
            # validate Server Certificate
            cert = loadCertificate(response['data']['certificate'])
            if not validateCert(STORE, cert, server=True):
                logging.error("Server Certificate failed.\nSystem has been compromised. Shutting down...")
                sys.exit(1)
            server.certificate = cert

            # Validate Server Challenge
            challenge_response = response['data']['challenge_response']
            if not validateSignature(server.certificate, server.challenge, challenge_response):
                logging.error("Server Challenge failed.\nSystem has been compromised. Shutting down...")
                sys.exit(1)
                return

            challenge = base64.b64decode(response['data']['challenge'])
            msg['data'] = {'challenge_response': signData(challenge, self.session)}

            server.validated = True

        server.cipher_spec = response['ciphers'][0]
        self.level = int(response['level'])
        server.exchange_data.my_private_key, server.exchange_data.my_public_key = generateKeyPair(
            'ECDHE')

        server.exchange_data.peer_public_key = deserializeKey(str(response['data']['key']))

        server.shared_key = exchangeSecret(server.exchange_data.my_private_key,
                                                        server.exchange_data.peer_public_key)
        server.exchange_data.static_shared_key = server.shared_key

        msg['data']['key'] =  server.exchange_data.my_public_key
        logging.info("Agreed cipher spec: " + response['ciphers'][0])

        h = generateHash(msg)
        self.messages[h] = msg
        self.send(msg)
        server.state = STATE_CONNECTED


    def processSecure(self, sender, request):

        if sender.state != STATE_CONNECTED:
            logging.warning("SECURE from disconnected client: %s" % sender)
            return

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        # Update peer public key
        tmp_public_key = deserializeKey(str(request['sa-data']['public-key']))
        sender.shared_key = exchangeSecret(sender.exchange_data.my_private_key,
                                           tmp_public_key)

        # Verify message Signature
        signature = request['sa-data']['signature']
        rcHMAC = request['sa-data']['hash']
        if not validateSignature(sender.certificate, rcHMAC, signature):
            logging.error("Signature Validation failed on Secure Message")
            logging.error("System has been compromised. Shutting down...")
            sys.exit(1)

        # Verify HMAC from Server message
        rcHMAC = request['sa-data']['hash']
        if not checkHash(request, rcHMAC):
            logging.error("Integrity Validation failed on Secure Message")
            logging.error("System has been compromised. Shutting down...")
            sys.exit(1)

        iv = base64.b64decode(request['sa-data']['iv'])
        payload = decrypt(sender, request['payload'], iv)

        try:
            message = json.loads(payload)
        except:
            logging.exception("Error send message: %s ", payload)
        else:
            if 'type' not in message.keys():
                logging.warning("Secure message without inner frame type")
                return

            if message['type'] == 'list':
                # Send ACK
                self.send(self.encapsulateSecure(generateAck(payload)))

                print "List of clients connected to server:"
                for c in message['data']:
                    print c
                    self.peer_list[SERVER].client_ids.append(int(c['id']))
                return



            if not all(k in message.keys() for k in ("src", "dst", "type")):
                return

            if not int(message['src']) in self.peer_list.keys() and message['type'] == 'client-connect':
                self.addPeer(int(message['src']))

            peer = self.peer_list[int(message['src'])]

            if message['type'] == 'client-connect':
                # Send ACK
                self.send(self.encapsulateSecure(generateAck(payload)))
                self.send(self.encapsulateSecure(self.generateAck(message, peer)))
                self.handleClientConnect(message, peer)
                return

            if peer.validated:
                # Verify message Signature
                signature = message['data']['signature']
                rcHMAC = message['data']['hash']
                src = self.peer_list[int(message['src'])]

                if not validateSignature(src.certificate, rcHMAC, signature):
                    logging.error("Signature Validation failed on ACK/COM/Disconnect Message")

                    return

                # Verify HMAC from Cliente message
                tmp = copy.deepcopy(message)
                rcHMAC = message['data']['hash']
                if not checkHash(tmp, rcHMAC):
                    logging.error("Integrity Validation failed on ACK/COM/Disconnect Message")
                    return

            if message['type'] == 'ack':
                self.processAck(message)
                return

            # Send ACK
            self.send(self.encapsulateSecure(generateAck(payload)))
            self.send(self.encapsulateSecure(self.generateAck(message, peer)))

            if message['type'] == 'client-com':

                if not int(message['src']) in self.peer_list.keys():
                    logging.exception("Message from unknown peer")
                    return

                peer = self.peer_list[message['src']]

                iv = base64.b64decode(str(message['data']['iv']))
                plainTex = decrypt(peer, str(message['data']['text']), iv)
                deviceId = str(message['data']['uuid'])
                print '%s | %d - %s@%s : %s' % (time.strftime("%H:%M"), peer.id, peer.name.split(' ')[0], deviceId, plainTex)

                # Update peer key
                key = message['data']['public-key']
                peer.shared_key = decrypt(None, key, None, self.rsaKeys[0])

            elif message['type'] == 'client-disconnect':
                peer = self.peer_list[int(message['src'])]
                logging.info("%s has ended his connection with you", peer.name)
                self.delPeer(peer.id)

    def processAck(self, message):
        try:
            m = self.messages[message['hash']]
            if m['type'] == 'client-disconnect':
                self.delPeer(int(m['dst']))

            elif m['type'] == 'client-connect' and m['phase'] == 3:
                peer = self.peer_list[int(m['dst'])]
                peer.state = STATE_CONNECTED
                peer.validated = True
                print "Secure connection established with %s" % peer.name

            elif m['type'] == 'connect' and m['phase'] == 3:
                server = self.peer_list[SERVER]
                server.state = STATE_CONNECTED
                print "Secure connection established with %s" % server.name
            del self.messages[message['hash']]

        except:
            print "Received ack for unknown"

    def handleClientConnect(self, message, peer):
        returnMsg = {'type': 'client-connect',
                     'src': message['dst'],
                     'dst': message['src'],
                     'phase': message['phase'] + 1,
                     'ciphers': [],
                     'level': self.level,
                     'data' : {'name': self.name, 'certificate': dumpCertificate(self.certificate)}}

        peer.name = message['data']['name']

        if message['phase'] == 1:

            # validate certificate
            cert = loadCertificate(message['data']['certificate'])
            if not validateCert(STORE, cert):
                logging.error("Peer Certificate failed.\nSystem has been compromised. Shutting down...")
                sys.exit(1)
            peer.certificate = cert

            # Do the peer challenge
            challenge = base64.b64decode(message['data']['challenge'])
            returnMsg['data']['challenge_response'] = signData(challenge, self.session)

            # Create challenge for peer
            returnMsg['data']['challenge'] = base64.b64encode(peer.challenge)

            peer.rsaKey = deserializeKey(str(message['data']['key']))
            peer.state = STATE_DISCONNECTED
            combinedCiphers = []
            for cipher_spec in message['ciphers']:
                if cipher_spec in CIPHERS:
                    combinedCiphers.append(cipher_spec)
            returnMsg['ciphers'] = combinedCiphers
            returnMsg['data']['key'] = self.rsaKeys[1]
            self.send(self.encapsulateSecure(returnMsg))

            peer.name = message['data']['name']
            peer.level = message['level']
            print "loading... 33%"
            if len(combinedCiphers) == 0:
                self.delPeer(peer.id)
            return

        if message['phase'] == 2:
            # validate certificate received from other client
            cert = loadCertificate(message['data']['certificate'])
            if not validateCert(STORE, cert):
                logging.error("Peer Certificate failed.\nSystem has been compromised. Shutting down...")
                sys.exit(1)
            peer.certificate = cert

            # Validate Client response for challenge
            challenge_response = message['data']['challenge_response']
            if not validateSignature(peer.certificate, peer.challenge, challenge_response):
                logging.error("Peer Signature failed.\nSystem has been compromised. Shutting down...")
                sys.exit(1)

            # check the list of compatible cipher-spec
            if len(message['ciphers']) == 0:
                logging.exception("No compatible ciphers")
                self.delPeer(int(message['src']))
                return

            # Generating a new key and encrypting it with peers rsa public key
            peer.cipher_spec = message['ciphers'][0]
            peer.name = message['data']['name']
            peer.level = int(message['level'])
            peer.rsaKey = deserializeKey(str(message['data']['key']))
            peer.shared_key = generateSymKey(256)
            cipheredKey = encrypt(peer, peer.shared_key)
            returnMsg['data']['key'] = cipheredKey
            challenge = base64.b64decode(message['data']['challenge'])
            returnMsg['data']['challenge_response'] = signData(challenge, self.session)
            returnMsg['ciphers'] = [message['ciphers'][0]]
            print "loading... 66%"
            return self.send(self.encapsulateSecure(returnMsg))

        if message['phase'] == 3:
            print"Secure connection established with %s" % peer.name
            peer.state = STATE_CONNECTED
            peer.validated = True
            peer.cipher_spec = str(message['ciphers'][0])
            peer.shared_key = decrypt(None, message['data']['key'], None, self.rsaKeys[0])
            return

    def loop(self):
        while 1:
            socks = select.select([s, sys.stdin, ], [], [])[0]
            for sock in socks:
                if sock == s:
                    # information received from server
                    data = s.recv(4096 * 2)
                    if len(data) > 0:
                        reqs = self.parseReqs(data)
                        for req in reqs:
                            self.handleRequest(req)
                elif sock == sys.stdin:
                    # Information from keyboard input
                    input = raw_input()
                    if len(input) > 0:
                        self.handleInput(input)


if __name__ == '__main__':
    # SmartCardHelper.searchingSmartCards()
    print "Chat version 1.1"
    print SLOT
    client = Client(getSesion(slot=SLOT), PIN)
    client.loop()
