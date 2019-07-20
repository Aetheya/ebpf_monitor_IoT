import socket
import sys
import argparse
import json

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:

    # Receive response
    print ('Waiting an answer...\n')
    data, server = sock.recvfrom(4096)
    print('Received message from %s:\n%s' % (server[0],data) )

finally:
    print ('Closing socket')
    sock.close()

