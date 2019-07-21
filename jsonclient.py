import socket
import argparse
import json
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# TODO nargs
parser = argparse.ArgumentParser(description="Parser for cmd")
parser.add_argument("cmd", choices=['RUN', 'START', 'GET', 'STOP'])
parser.add_argument("-t", "--time", type=int, default=3)
parser.add_argument("-d", "--dest", default='192.168.1.8')  # ebpf machine
parser.add_argument("-s", "--server", default="192.168.1.13")
parser.add_argument("-p", "--port", default=10000)
args = parser.parse_args()

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

dest_address = (args.dest, args.port)
command = json.dumps({"cmd": args.cmd, "time": args.time, "server": args.server, "port": args.port})


def sign(plain_data):
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    signature = private_key.sign(
        data=plain_data.encode('utf-8'),
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )
    return json.dumps({"signature": base64.urlsafe_b64encode(signature), "message": command})

try:
    # Send data
    print('Signing message...')

    print('Sending message to host %s\n%s:' % (dest_address[0], command))
    sock.bind(('', 10001))
    # sent = sock.sendto(command, dest_address)
    sent = sock.sendto(sign(command), dest_address)

    # Receive response
    if args.cmd == 'RUN' or args.cmd == 'GET':
        print('Waiting an answer...\n')
        data, server = sock.recvfrom(4096)
        print('Received message from %s:\n%s' % (server[0], data))

    else:
        print('CMD sent')

finally:
    print('Closing socket')
    sock.close()
