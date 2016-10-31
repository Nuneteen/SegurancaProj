import socket, select, sys
import json
import time
import logging
import CipherHelper
import base64

HOST = '127.0.0.1'  # The remote host
PORT = 8080  # The same port as used by the server

CLIENT_NAME = "Nuno"
CIPHERS = []
STATE_NONE = 0
STATE_DISCONNECTED = 2
STATE_CONNECTED = 1
ACK = {'type': 'ack'}

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

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


class Peer:
    def __init__(self, id):
        self.id = id
        self.state = STATE_NONE
        self.sa_data = None
        self.bufin = ""
        self.bufout = ""
        self.signature = None

    def printbuffer(self, state):
        if self.state == 1:
            print self.bufin
        else:
            print "Peer not connected"
        return

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""
        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            logging.error("Client (%s) buffer exceeds MAX BUFSIZE. %d > %d",
                          (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(TERMINATOR)
        print "REQUESTS: "
        print reqs
        self.bufin = reqs[-1]
        return reqs[:-1]


class Client:
    def __init__(self):
        self.id = "fgjdkfbgkjdfg"
        self.sa_data = None
        self.level = 0
        self.state = STATE_NONE
        self.name = CLIENT_NAME
        self.peerlist = {}

    def serverConnect(self):
        self.addPeer('server')
        server = self.peerlist['server']
        msg = {'type': 'connect', 'phase': 1, 'name': self.name, 'id': self.id, 'ciphers': CIPHERS}
        while self.state == STATE_NONE:

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
                data = server.parseReqs(data)
                response = json.loads(data[1])
            except:
                logging.exception("Connect messages received with errors")
                break
            else:
                if 'data' in response.keys():
                    server.sa_data = CipherData(response['ciphers'][0])
                    CipherHelper.generateKeyPair(server)
                    CipherHelper.deserializeKey(server, str(response['data']))
                    CipherHelper.exchangeSecret(server)
                    msg['data'] = CipherHelper.serializeKey(server)
                    logging.info("Agreed cipher spec: " + response['ciphers'][0])
                    self.send(msg)
                    print msg
                    self.state = STATE_CONNECTED

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
        logging.info("Peer added: %s", peer)
        return

    def delPeer(self, id):
        if id not in self.peerlist:
            logging.error("Peer NOT deleted: %s not found", self.peerlist[id])
            return

        peer = self.peerlist[id]
        assert peer.id == id, "peer.id (%s) should match key (%s)" % (peer.id, id)
        del self.peerlist[peer.socket]
        peer.state = STATE_DISCONNECTED
        logging.info("Peer deleted: %s", peer)
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
        CipherHelper.generateKeyPair(server)
        CipherHelper.exchangeSecret(server)

        cipherText = CipherHelper.encrypt(server, message)
        secure = {'type': 'secure', 'payload': cipherText}
        secure['sa-data'] = {'iv': base64.b64encode(server.sa_data.iv),
                             'public-key': CipherHelper.serializeKey(server)}

        return secure

    def list(self):
        return json.dumps({'type': 'list'})

    def clientConnect(self, dst):
        clientconn = {'type': 'client-connect', 'src': self.id, 'dst': dst, 'phase': 1, 'ciphers': CIPHERS}
        return json.dumps(clientconn)

    def clientDisconnect(self, dst):
        clientdisc = {'type': 'client-disconnect', 'src': self.id, 'dst': dst}
        return json.dumps(clientdisc)

    def clientcom(self, dst, msg):
        cipherText = CipherHelper.encrypt(dst, msg)
        clientcom = {'type': 'client-com', 'src': self.id, 'dst': dst, 'data': cipherText}
        return json.dumps(clientcom)

    def handleInput(self, input):
        fields = input.splitlines()

        if fields[0] == 'list':
            data = self.encapsulateSecure(self.list())
            self.send(data)
            return

        elif fields[0] == 'client-connect':
            data = self.encapsulateSecure(self.clientConnect(fields[1]))
            self.send(data)
            return

        elif fields[0] == 'client-com':
            data = self.encapsulateSecure(self.clientcom(fields[1], fields[2:]))
            self.send(data)
            return

        elif fields[0] == 'client-disconnect':
            data = self.encapsulateSecure(self.clientConnect(fields[1]))
            self.send(data)
            return

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
        CipherHelper.deserializeKey(sender, str(request['sa-data']['public-key']))
        CipherHelper.exchangeSecret(sender)

        iv = base64.b64decode(request['sa-data']['iv'])
        payload = CipherHelper.decrypt(sender, request['payload'], iv)

        try:
            request['payload'] = json.loads(payload)
        except:
            logging.exception("Error send message: %s ", payload)
        else:
            if 'type' not in request['payload'].keys():
                logging.warning("Secure message without inner frame type")
                return

            if request['payload']['type'] == 'list':
                for c in request['payload']['data']:
                    print c
                return

            if not all(k in request['payload'].keys() for k in ("src", "dst", "type")):
                return

            if not request['payload']['dst'] in self.peerlist.keys():
                logging.warning("Message from unknown client: %s" % request['payload']['src'])
                return

            dst = self.peerlist[request['payload']['dst']]

            if request['payload']['type'] == 'client-com':
                pass
            elif request['payload']['type'] == 'client-connect':
                pass
            elif request['payload']['type'] == 'client-disconnect':
                pass

    def loop(self):
        # initial connection to the server. Nothing more is allowed until connection is established
        self.serverConnect()
        logging.warning("Secure session with the server established")

        while 1:
            socks = select.select([s, sys.stdin, ], [], [])[0]
            for sock in socks:
                if sock == s:
                    # information received from server
                    data = s.recv(4096)
                    self.handleRequest(data)
                elif sock == sys.stdin:
                    # Information from keyboard input
                    input = raw_input()
                    if len(input) > 0:
                        self.handleInput(input)


client = Client()
client.loop()
