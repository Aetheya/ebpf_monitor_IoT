import socket
import argparse
import json

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind(('', 10002))
    while True:
        print('Waiting data to collect...\n')
        data, server = sock.recvfrom(4096)
        print('Received message from %s:\n%s' % (server[0], data))

finally:
    print('Closing socket')
    sock.close()
