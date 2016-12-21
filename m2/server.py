# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim setings:
# :set expandtab ts=4

from socket import *
from select import *
import random
import time
import logging
from utils import *
import base64
import copy

# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2

STORE = loadStore()
TIMEOUT_THRESHOLD = 120
LEVEL = {146790014: 2,
         147733189: 3}

# server supported cipher combinations in order of preference
CIPHERS = ["ECDHE-RSA-AES256-CTR-SHA256",
           "ECDHE-RSA-AES256-OFB-SHA256",
           "ECDHE-RSA-AES256-CFB8-SHA256",
           "ECDHE-RSA-AES256-CTR-SHA512",
           "ECDHE-RSA-AES256-OFB-SHA512",
           "ECDHE-RSA-AES256-CFB8-SHA512"
           ]

class ExchangeData:
    def __init__(self):
        self.my_private_key = None
        self.my_public_key = None
        self.peer_public_key = None

class Client:
    count = 0

    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = None
        self.level = random.randint(0, 5)
        self.state = STATE_NONE
        self.cipher_spec = ''
        self.shared_key = None
        self.name = "Unknown"
        self.exchange_data = ExchangeData()
        self.certificate = None
        self.validated = False
        self.certificate_check = None
        self.challenge = os.urandom(256)

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s name:%s level:%d state:%d)" % (self.id, str(self.addr), self.name, self.level, self.state)

    def asDict(self):
        return {'id': self.id, 'level': self.level, 'name': self.name}

    def setState(self, state):
        if state not in [STATE_CONNECTED, STATE_NONE, STATE_DISCONNECTED]:
            return

        self.state = state

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

    def send(self, obj):
        """Send an object to this client.
        """
        try:
            self.bufout += json.dumps(obj, sort_keys=True) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)", self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        logging.info("Client.close(%s)", self)
        try:
            # Shutdown will fail on a closed socket...
            self.socket.close()
        except:
            logging.exception("Client.close(%s)", self)

        logging.info("Client Closed")


class ChatError(Exception):
    """This exception should signal a protocol error in a client request.
    It is not a server error!
    It just means the server must report it to the sender.
    It should be dealt with inside handleRequest.
    (It should allow leaner error handling code.)
    """
    pass


def ERROR(msg):
    """Raise a Chat protocol error."""
    raise ChatError(msg)


class Server:
    def __init__(self, host, port):
        self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
        self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ss.bind((host, port))
        self.ss.listen(10)
        logging.info("Secure IM server listening on %s", self.ss.getsockname())
        # clients to manage (indexed by socket and by name):
        self.clients = {}       # clients (key is socket)
        self.id2client = {}   # clients (key is id)
        f = open("ServerCert.cer", 'rb')
        self.certificate =  loadCertificate(f.read(), False)
        self.key = loadRSAkey("serverKey.pem")

    def stop(self):
        """ Stops the server closing all sockets
        """
        logging.info("Stopping Server")
        try:
            self.ss.close()
        except:
            logging.exception("Server.stop")

        for csock in self.clients:
            try:
                self.clients[csock].close()  # Client.close!
            except:
                # this should not happen since close is protected...
                logging.exception("clients[csock].close")

        # If we delClient instead, the following would be unnecessary...
        self.clients.clear()
        self.id2client.clear()

    def addClient(self, csock, addr):
        """Add a client connecting in csock."""
        if csock in self.clients:
            logging.error("Client NOT Added: %s already exists", self.clients[csock])
            return

        client = Client(csock, addr)
        self.clients[client.socket] = client
        logging.info("Client added: %s", client)

    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.clients:
            logging.error("Client NOT deleted: %s not found", self.clients[csock])
            return

        client = self.clients[csock]
        assert client.socket == csock, "client.socket (%s) should match key (%s)" % (client.socket, csock)
        if client.id in self.id2client.keys():
            del self.id2client[client.id]
        del self.clients[client.socket]
        client.close()
        logging.info("Client deleted: %s", client)

    def accept(self):

        """Accept a new connection.
        """
        try:
            csock, addr = self.ss.accept()
            self.addClient(csock, addr)
        except:
            logging.exception("Could not accept client")

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """
        client = self.clients[s]
        data = None
        try:
            data = s.recv(BUFSIZE)
            logging.info("Received data from %s. Message:\n%r", client, data)
        except:
            logging.exception("flushin: recv(%s)", client)
            logging.error("Received invalid data from %s. Closing", client)
            self.delClient(s)
        else:
            if len(data) > 0:
                reqs = client.parseReqs(data)
                for req in reqs:
                    self.handleRequest(s, req)
            else:
                self.delClient(s)

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data."""
        if s not in self.clients:
            # this could happen before, because a flushin might have deleted the client
            logging.error("BUG: Flushing out socket that is not on client list! Socket=%s", str(s))
            return

        client = self.clients[s]
        try:
            sent = client.socket.send(client.bufout[:BUFSIZE])
            logging.info("Sent %d bytes to %s. Message:\n%r", sent, client, client.bufout[:sent])
            client.bufout = client.bufout[sent:]  # leave remaining to be sent later
        except:
            logging.exception("flushout: send(%s)", client)
            # logging.error("Cannot write to client %s. Closing", client)
            self.delClient(client.socket)

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + every open client connection)
            rlist = [self.ss] + self.clients.keys()
            # sockets to select for writing: (those that have something in bufout)
            wlist = [ sock for sock in self.clients if len(self.clients[sock].bufout)>0 ]
            logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist))
            (rl, wl, xl) = select(rlist, wlist, rlist)
            logging.debug("select: %s %s %s", rl, wl, xl)

            # Deal with incoming data:
            for s in rl:
                if s is self.ss:
                    self.accept()
                elif s in self.clients:
                    self.flushin(s)
                else:
                    logging.error("Incoming, but %s not in clients anymore", s)

            # Deal with outgoing data:
            for s in wl:
                if s in self.clients:
                    self.flushout(s)
                else:
                    logging.error("Outgoing, but %s not in clients anymore", s)

            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.delClient(s)

    def handleRequest(self, s, request):
        """Handle a request from a client socket.
        """
        client = self.clients[s]
        try:
            logging.info("HANDLING message from %s: %r", client, repr(request))

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            if req['type'] == 'ack':
                #verifyAck()
                return  # Ignore for now

            #client.send({'type': 'ack'})

            if req['type'] == 'connect':
                ack = {'type': 'ack', 'hash': generateHash(request)}
                client.send(ack)
                self.processConnect(client, req)

            elif req['type'] == 'secure':
                elipse_time = client.certificate_check - time.time()
                if elipse_time < TIMEOUT_THRESHOLD:
                    if not validateCert(STORE, client.certificate):
                        logging.error("%s Certificate was revoked")
                self.processSecure(client, req)

        except Exception, e:
            logging.exception("Could not handle request")

    def clientList(self, peer):
        """
        Return the client list
        Only add client that user can communicate to
        """
        cl = []
        for k in self.clients:
            c = self.clients[k]
            if c.level >= peer.level:
                cl.append(c.asDict())
        return cl

    def processConnect(self, sender, request):
        """
        Process a connect message from a client
        """
        if sender.state == STATE_CONNECTED:
            logging.warning("Client is already connected: %s" % sender)
            return


        if not all (k in request.keys() for k in ("name", "ciphers", "phase", "id")):
            logging.warning("Connect message with missing fields")
            return

        msg = {'type': 'connect', 'phase': request['phase'] + 1, 'ciphers': CIPHERS}

        if not sender.validated:
            cert = loadCertificate(request['data']['certificate'])
            if not validateCert(STORE, cert):
                msg['data'] = {'error': 'Client certificate was not validated by the Server'}
                self.delClient(sender.socket)
                sender.close()
                return
            sender.certificate_check = time.time()

            if getId(cert) in self.id2client.keys():
                msg['data'] = {'error': 'Client with id: %d already connected to the server' % request['id']}
                self.delClient(sender.socket)
                sender.close()
                return

            challenge = request['data']['challenge']
            msg['data'] = {'challenge_response': signData(challenge, key=self.key)}
            sender.validated = True
            sender.certificate = cert
            sender.level = LEVEL[int(request['id'])]
            msg['level'] = sender.level

        if len(request['ciphers']) == 0:
            logging.info("Client did not provide any list of cipherspec")
            logging.info("Connect continue to phase " + str(msg['phase']))
            sender.send(msg)
            return

        if 'error' in request['data']:
            return

        if 'data' in request.keys() and 'key' in request['data']:

            challenge_response = request['data']['challenge_response']
            if not validateSignature(sender.certificate, sender.challenge, challenge_response):
                msg['data'] = {'error': 'Client failed challenge!'}
                self.delClient(sender.socket)
                sender.close()
                return

            self.id2client[request['id']] = sender
            sender.id = request['id']
            sender.name = request['name']
            sender.state = STATE_CONNECTED
            sender.exchange_data.peer_public_key = deserializeKey(str(request['data']['key']))
            sender.shared_key = exchangeSecret(sender.exchange_data.my_private_key,
                                                            sender.exchange_data.peer_public_key)
            sender.exchange_data.static_shared_key = sender.shared_key

            logging.info("Client %s Connected" % request['id'])
            return

        # client send more than one cipher spec
        for cipher in request['ciphers']:
            if str(cipher) in CIPHERS:
                sender.cipher_spec = cipher
                msg['ciphers'] = [cipher]
                logging.info("Cipher spec agreement reached.\nGenerating keys.\nSending information to Client")
                sender.exchange_data.my_private_key, sender.exchange_data.my_public_key = generateKeyPair('ECDHE')

                challenge_response = signData(base64.b64decode(request['data']['challenge']), key=self.key)

                msg['data'] = {'key': sender.exchange_data.my_public_key,
                               'certificate': dumpCertificate(self.certificate),
                               'challenge_response': challenge_response,
                               'challenge': base64.b64encode(sender.challenge)}

                logging.info("Connect continue to phase " + str(msg['phase']))
                sender.send(msg)
                return

        # No cipher_spec supported in both sides
        msg['ciphers'] = []
        sender.send(msg)

    def processList(self, sender, request):
        """
        Process a list message from a client
        """
        if sender.state != STATE_CONNECTED:
            logging.warning("LIST from disconnected client: %s" % sender)
            return
        list = {'type': 'list', 'data': self.clientList(sender)}
        encapsulatedMessage = self.encapsulateSecure(sender, list)
        return sender.send(encapsulatedMessage)


    def processSecure(self, sender, request):
        """
        Process a secure message from a client
        """
        if sender.state != STATE_CONNECTED:
            logging.warning("SECURE from disconnected client: %s" % sender)
            return

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        # This is a secure message.

        # Update peer public key
        tmp_public_key = deserializeKey(str(request['sa-data']['public-key']))
        sender.shared_key = exchangeSecret(sender.exchange_data.my_private_key,
                                           tmp_public_key)

        # Verify message Signature
        signature = request['sa-data']['signature']
        rcHMAC = request['sa-data']['hash']
        if not validateSignature(sender.certificate, rcHMAC, signature):
            logging.error("Signature Validation failed on Secure Message")
            self.delClient(sender.socket)
            sender.close()
            return

        rcHMAC = request['sa-data']['hash']
        if not checkHash(request, rcHMAC):
            logging.error("Integrity Validation failed on Secure Message")
            self.delClient(sender.socket)
            sender.close()
            return

        # Decrypt message
        iv = base64.b64decode(request['sa-data']['iv'])
        payload = decrypt(sender, request['payload'], iv)
        tmp = json.loads(payload)
        innerMessages = tmp

        if 'type' not in innerMessages.keys():
            logging.warning("Secure message without inner frame type")
            return

        if innerMessages['type'] == 'ack' and 'dst' not in innerMessages.keys():
            return

        # Send ACK
        sender.send(self.encapsulateSecure(sender, generateAck(request)))

        if innerMessages['type'] == 'list':
            self.processList(sender, innerMessages)
            return


        if not all (k in innerMessages.keys() for k in ("src", "dst")):
            return


        dstId = int(innerMessages['dst'])
        if not dstId in self.id2client.keys():
            logging.warning("Message to unknown client: %s" % innerMessages['dst'])
            return

        dst = self.id2client[dstId]

        # if src.level < message.level:
        #     return

        # If sender's level is higher than destination level do not send message
        if sender.level > dst.level and innerMessages['type'] == 'client-com':
            logging.warning("Can not send message from %s to %s. Level informality" % (sender.name, dst.name))
            return

        dst_message = self.encapsulateSecure(dst,(innerMessages))
        dst.send(dst_message)

    def encapsulateSecure(self,sender, message):

        # Generate a new secret for each message sent
        tmp_private_key, tmp_public_key = generateKeyPair('ECDHE')
        sender.shared_key = exchangeSecret(tmp_private_key,
                                           sender.exchange_data.peer_public_key)

        # TODO ver o problema do nome da key do dicionario

        cipherText, iv = encrypt(sender, message)
        secure = {'type': 'secure', 'payload':cipherText}
        secure['sa-data'] = {'iv': iv, 'public-key': tmp_public_key}
        hmac = generateHash(secure)
        secure['sa-data']['hash'] = hmac
        secure['sa-data']['signature'] = signData(hmac, key=self.key)
        return secure

if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    serv = None
    while True:
        try:
            logging.info("Starting Secure IM Server v1.0")
            serv = Server(HOST, PORT)
            serv.loop()
        except KeyboardInterrupt:
            serv.stop()
            try:
                logging.info("Press CTRL-C again within 2 sec to quit")
                time.sleep(2)
            except KeyboardInterrupt:
                logging.info("CTRL-C pressed twice: Quitting!")
                break
        except:
            logging.exception("Server ERROR")
            if serv is not (None):
                serv.stop()
            time.sleep(10)
