import socket

HOST = '127.0.0.1'  # The remote host
PORT = 8080         # The same port as used by the server

msg = 'hello world'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

while 1:
    msg = raw_input("Message: ")
    s.sendall(msg)

s.close()
