import socket
import json
import random
import time
import logging

HOST = '127.0.0.1'  # The remote host
PORT = 8080         # The same port as used by the server

CLIENT_NAME = "Nuno"
CLIENT_STATE = 0    # Client has not connected to the server
ID = 214546
CIPHERS = []
SA_DATA = None

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

connectMsg = {'type': 'connect', 'phase': 1, 'name': CLIENT_NAME, 'id': ID,  'ciphers': CIPHERS}


def parseReqs(data):
    """Parse a chunk of data from this client.
    Return any complete requests in a list.
    Leave incomplete requests in the buffer.
    This is called whenever data is available from client socket."""
    bfin = ""
    bfin += data
    reqs = bfin.split(TERMINATOR)
    return reqs[:-1]

while CLIENT_STATE == 0:
    s.send(json.dumps(connectMsg)+TERMINATOR)
    data = s.recv(BUFSIZE)

    try:
        response = json.loads(parseReqs(data))
        print response
    except:
        logging.exception("Connect messages received with errors")
        break
    else:
        if len(response['ciphers']) == 1:
            SA_DATA = response['ciphers'][0]
            CLIENT_STATE = 1

        else:
            i = 0
            for cipher in response['ciphers']:
                print(str(i) + ": " + cipher)
                i += 1
            cipher = raw_input(prompt=">>")
            connectMsg['phase'] = response['phase'] + 1
            connectMsg['ciphers'] = response['ciphers'][cipher]

print data
