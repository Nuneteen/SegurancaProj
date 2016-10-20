import socket
import json
import random
import time
import logging

HOST = '127.0.0.1'  # The remote host
PORT = 8080         # The same port as used by the server

CLIENT_NAME = "nuno"
CLIENT_STATE = 0    # Client has not connected to the server
ID = 214546
CIPHERS = []
SA_DATA = None

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

connectMsg = {'type': 'connect', 'phase': 0, 'name': CLIENT_NAME, 'id': ID,  'ciphers': CIPHERS}

while CLIENT_STATE == 0:
    s.send(json.dumps(connectMsg)+TERMINATOR)
    data = s.recv(BUFSIZE)

    try:
        response = json.dumps(data)
    except:
        logging.exception("Connect messages received with errors")
    else:
        connectMsg = {'type': 'connect', 'phase': response['phase'] + 1, 'name': CLIENT_NAME, 'id': ID,  'ciphers': CIPHERS}

print data
