import socket, select, sys
import json
import logging
import CipherHelper
import base64
import argparse
import random
import time
import os

HOST = '127.0.0.1'  # The remote host

CIPHERS = ["ECDHE-RSA-AES256-CTR-SHA512",
           "ECDHE-RSA-AES256-OFB-SHA256",
           "ECDHE-RSA-AES256-CTR-SHA512",
           "ECDHE-RSA-AES256-OFB-SHA512",
           ]
STATE_NONE = 0
STATE_DISCONNECTED = 2
STATE_CONNECTED = 1
ACK = {'type': 'ack'}
ID = random.randint(0, 99999)

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

def int_positive(value):
    ivalue = int(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return ivalue


parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('Name', metavar='NAME', type=str,
                    help='Username to use on app')
parser.add_argument('-p', '--port', help='set port to use', type=int_positive,
                    default=8080)
parser.add_argument('-l', '--list', nargs='+', type=str)

args = parser.parse_args()
PORT = args.port
CLIENT_NAME = args.Name

if args.list:
    CIPHERS = []
    for i in args.list:
        CIPHERS += [i]


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))


class CipherData:
    def __init__(self, chipherSpec):
        self.cipherSpec = chipherSpec
        self.my_private_key = None
        self.my_public_key = None
        self.peer_public_key = None
        self.sharedKey = None
        self.iv = None
        self.signature = None


class Peer:
    def __init__(self, id):
        self.id = id
        self.state = STATE_NONE
        self.cd = None
        self.name = None
        self.rsaKey = None


class Client:
    def __init__(self):
        self.id = ID
        self.cd = None
        self.level = 0
        self.state = STATE_NONE
        self.name = CLIENT_NAME
        self.peerlist = {}
        self.rsaKeys = CipherHelper.generateRSAPair()

    def serverConnect(self):
        self.addPeer('server')
        server = self.peerlist['server']
        msg = {'type': 'connect', 'phase': 1, 'name': self.name, 'id': ID, 'ciphers': CIPHERS}

        while server.state == STATE_NONE:

            try:
                print "CONNECT: "
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
                if len(data) == 0:
                    continue
                response = json.loads(data[0])
            except:
                logging.exception("Connect messages received with errors")
                break
            else:
                print response['ciphers']
                if len(response['ciphers']) == 0:
                    logging.error("No ciphers supported between server and client")
                    sys.exit(1)

                if 'data' in response.keys():
                    server.cd = CipherData(response['ciphers'][0])
                    server.cd.my_private_key, server.cd.my_public_key = CipherHelper.generateKeyPair('ECDHE')
                    server.cd.peer_public_key = CipherHelper.deserializeKey(str(response['data']))
                    server.cd.sharedKey = CipherHelper.exchangeSecret(server.cd.my_private_key,
                                                                      server.cd.peer_public_key)
                    msg['data'] = server.cd.my_public_key
                    logging.info("Agreed cipher spec: " + response['ciphers'][0])
                    self.send(msg)
                    server.state = STATE_CONNECTED

                else:
                    i = 0
                    for cipher in response['ciphers']:
                        print(str(i) + ": " + cipher)
                        i += 1
                    cipher = raw_input()
                    msg['phase'] = response['phase'] + 1
                    msg['ciphers'] = response['ciphers'][int(cipher)]

    def addPeer(self, id):
        if id in self.peerlist:
            logging.error("Peer NOT Added: %s already exists", self.peerlist[id])
            return

        peer = Peer(id)
        self.peerlist[peer.id] = peer
        print "Peer connected:" + str(id)
        return

    def delPeer(self, id):

        if id not in self.peerlist:
            logging.error("Peer NOT deleted: %s not found", self.peerlist[id])
            return

        peer = self.peerlist[id]
        assert peer.id == id, "peer.id (%s) should match key (%s)" % (peer.id, id)
        del self.peerlist[peer.id]
        print "Peer disconnected:" + str(id)
        return

    # TODO change this method to Peer class. Similary to Server's implementation
    def send(self, obj):
        try:
            s.send(json.dumps(obj) + TERMINATOR)
        except:
            logging.exception("Error send message: %s ", obj)

    def encapsulateSecure(self, message):
        server = self.peerlist['server']

        # generate a new secret for each message sent
        server.cd.my_private_key, server.cd.my_public_key = CipherHelper.generateKeyPair('ECDHE')
        server.cd.sharedKey = CipherHelper.exchangeSecret(server.cd.my_private_key,
                                                               server.cd.peer_public_key)

        cipherText, iv = CipherHelper.encrypt(server, message)
        secure = {'type': 'secure', 'payload': cipherText}
        secure['sa-data'] = {'iv': iv,
                             'public-key': server.cd.my_public_key}
        hmac = CipherHelper.generateHMAC(server, secure)
        secure['sa-data']['hash'] = hmac

        return secure

    def list(self):
        return {'type': 'list'}

    def clientConnect(self, dst):
        clientconn = {'type': 'client-connect', 'src': ID, 'dst': dst, 'phase': 1, 'ciphers': CIPHERS}
        clientconn['data'] = {'key': self.rsaKeys[1]}
        return clientconn

    def clientDisconnect(self, dst):
        peer = self.peerlist[int(dst)]
        clientdisc = {'type': 'client-disconnect', 'src': ID, 'dst': dst}
        hmac = CipherHelper.generateHMAC(peer, clientdisc)
        clientdisc['data']['hash'] = hmac
        return clientdisc

    def clientcom(self, dst, msg):
        peer = self.peerlist[int(dst)]
        cipheredText, iv = CipherHelper.encrypt(peer, msg)
        clientcom = {'type': 'client-com', 'src': ID, 'dst': dst, 'data': {'text': cipheredText, 'iv': iv}}
        hmac = CipherHelper.generateHMAC(peer, clientcom)
        clientcom['data']['hash'] = hmac
        return clientcom

    def handleInput(self, input):
        fields = input.split()

        if fields[0] == 'quit':
            sys.exit(0)

        if fields[0] == 'list':
            data = self.encapsulateSecure(self.list())
            self.send(data)
            return

        elif fields[0] == 'client-connect':
            self.addPeer(int(fields[1]))
            data = self.encapsulateSecure(self.clientConnect(fields[1]))
            self.send(data)
            return

        elif fields[0] == 'client-com':
            if not int(fields[1]) in self.peerlist.keys():
                logging.exception("Peer not connected to client")
                return
            message = ' '.join(fields[2:])
            data = self.encapsulateSecure(self.clientcom(fields[1], message))
            self.send(data)
            return

        elif fields[0] == 'client-disconnect':
            self.delPeer(int(fields[1]))
            data = self.encapsulateSecure(self.clientDisconnect(fields[1]))
            self.send(data)
            return

        elif fields[0] == 'peerlist':
            for peer in self.peerlist:
                print peer
            return

        else:
            logging.error("Invalid input")
            return

    def parseReqs(self, data):
        reqs = data.split(TERMINATOR)
        ack = json.dumps(ACK)
        if ack in reqs:
            reqs.remove(ack)
        return reqs[:-1]

    def handleRequest(self, request):
        server = self.peerlist['server']
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
                return  # Ignore for now

            client.send({'type': 'ack'})

            if req['type'] == 'connect':
                return

            elif req['type'] == 'secure':
                self.processSecure(server, req)

        except Exception, e:
            logging.exception("Could not handle request")

    def processSecure(self, sender, request):

        if sender.state != STATE_CONNECTED:
            logging.warning("SECURE from disconnected client: %s" % sender)
            return

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        # Update peer public key
        sender.cd.peer_public_key = CipherHelper.deserializeKey(str(request['sa-data']['public-key']))
        sender.cd.sharedKey = CipherHelper.exchangeSecret(sender.cd.my_private_key,
                                                               sender.cd.peer_public_key)

        # Verify HMAC
        rcHMAC = request['sa-data']['hash']
        if not CipherHelper.checkHMAC(sender, request, rcHMAC):
            logging.error("Integrity Validation failed on Secure Message")
            return

        iv = base64.b64decode(request['sa-data']['iv'])
        payload = CipherHelper.decrypt(sender, request['payload'], iv)

        try:
            message = json.loads(payload)
        except:
            logging.exception("Error send message: %s ", payload)
        else:
            if 'type' not in message.keys():
                logging.warning("Secure message without inner frame type")
                return

            if message['type'] == 'list':
                print "List of clients connected to server:"
                for c in message['data']:
                    print c
                return

            if not all(k in message.keys() for k in ("src", "dst", "type")):
                return

            if not int(message['src']) in self.peerlist.keys() and message['type'] == 'client-connect':
                self.addPeer(int(message['src']))

            if message['type'] == 'client-connect':
                self.handleClientConnect(message)
                return

            # Verify HMAC
            rcHMAC = message['data']['hash']
            src = self.peerlist[int(message['src'])]
            if not CipherHelper.checkHMAC(src, message, rcHMAC):
                logging.error("Integrity Validation failed on COM/Disconnect Message")
                return

            elif message['type'] == 'client-com':

                if not int(message['src']) in self.peerlist.keys():
                    logging.exception("Message from unknown peer")
                    return

                peer = self.peerlist[message['src']]
                iv = base64.b64decode(str(message['data']['iv']))
                plainTex = CipherHelper.decrypt(peer, str(message['data']['text']), iv)
                print time.strftime("%H:%M | ") + str(peer.id) + " - " + plainTex


            elif message['type'] == 'client-disconnect':
                peer = self.peerlist[int(message['src'])]
                logging.info("%s has ended his connection with you", peer.name)
                self.delPeer(peer.id)


    def handleClientConnect(self, message):
        peer = self.peerlist[int(message['src'])]
        returnMsg = {'type': 'client-connect',
                     'src': message['dst'],
                     'dst': message['src'],
                     'phase': message['phase'] + 1,
                     'ciphers': []}

        if message['phase'] == 1:
            peer.rsaKey = CipherHelper.deserializeKey(str(message['data']['key']))
            peer.state = STATE_DISCONNECTED
            combinedCiphers = []
            for cipherspec in message['ciphers']:
                if cipherspec in CIPHERS:
                    combinedCiphers.append(cipherspec)
            returnMsg['ciphers'] = combinedCiphers
            returnMsg['data'] = {'key': self.rsaKeys[1]}
            self.send(self.encapsulateSecure(returnMsg))
            return

        if len(message['ciphers']) == 0:
            logging.exception("No compatible ciphers")
            self.delPeer(int(message['src']))
            return

        if len(message['ciphers']) == 1 and peer.state == STATE_DISCONNECTED:
            print("Agreement reached!")
            peer.state = STATE_CONNECTED
            peer.cd = CipherData(message['ciphers'][0])
            peer.cd.sharedKey = CipherHelper.keyDecript(self.rsaKeys[0], message['data']['key'])
            return


        # Generating a new key and encrypting it with peers rsa public key
        peer.cd = CipherData(message['ciphers'][0])
        peer.rsaKey = CipherHelper.deserializeKey(str(message['data']['key']))
        iv = os.urandom(16)
        peer.cd.sharedKey = CipherHelper.generateSymKey(256)
        cipheredKey = CipherHelper.encrypt(peer, peer.cd.sharedKey)
        returnMsg['data'] = {'key' : cipheredKey}
        returnMsg['ciphers'] = [message['ciphers'][0]]
        print("Agreement reached!")
        return self.send(self.encapsulateSecure(returnMsg))

    def loop(self):
        # initial connection to the server. Nothing more is allowed until connection is established
        self.serverConnect()
        logging.warning("Secure session with the server established")

        while 1:
            socks = select.select([s, sys.stdin, ], [], [])[0]
            for sock in socks:
                if sock == s:
                    # information received from server
                    data = s.recv(4096*2)
                    if len(data) > 0:
                        reqs = self.parseReqs(data)
                        for req in reqs:
                            self.handleRequest(req)
                elif sock == sys.stdin:
                    # Information from keyboard input
                    input = raw_input()
                    if len(input) > 0:
                        self.handleInput(input)


client = Client()
client.loop()
