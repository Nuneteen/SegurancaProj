import socket
import json
import random
import time

HOST = '127.0.0.1'  # The remote host
PORT = 8080         # The same port as used by the server

clientname = "nuno"
phase = 1

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

rendezvous = {}
rendezvous['id'] = random.random()
rendezvous['name'] = clientname
rendezvous['socket'] = s.getsockname()
rendezvous['level'] = 0
rendezvous['sa-data'] = "security-association-data"


message = {}
message['type'] = 'connect'
message['phase'] = phase
message['name'] = clientname
message['id'] = random.random()
message['ciphers'] = ['NONE']
message['data'] = ''

s.send(json.dumps(message)+"\n\n")
data = s.recv(4096)
print data

s.close()
