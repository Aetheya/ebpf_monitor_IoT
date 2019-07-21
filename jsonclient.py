import socket
import argparse
import json
import logging

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# TODO nargs
logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.INFO)


def parse():
    """Parse user input command"""
    parser = argparse.ArgumentParser(description="Parser for cmd")
    parser.add_argument("cmd", choices=['RUN', 'START', 'GET', 'STOP'], help='command for the eBPF device')
    parser.add_argument("-t", "--time", type=int, default=3, help='period of stat gathering [RUN]')
    parser.add_argument("-d", "--dest", default='192.168.1.8', help='eBPF device ip address')  # ebpf machine
    parser.add_argument("-s", "--server", default="192.168.1.13", help='monitoring server ip address')
    parser.add_argument("-p", "--port", default=10000, help='destination port')
    args = parser.parse_args()
    logger.debug('PARSED: [%s]' % args)
    return args


def serialize_cmd(command):
    """Input command to JSON format"""
    return json.dumps({'cmd': command.cmd, 'time': command.time, 'server': command.server, 'port': command.port})


def sign(plain_data):
    try:
        with open('private_key.pem', 'rb') as key_file:
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
        logger.info('Message signed')
        return json.dumps({'signature': base64.urlsafe_b64encode(signature), "message": plain_data})
    except ValueError:
        logger.error('PEM data could not be decrypted or if its structure could not be decoded successfully.')
        return -1
    except TypeError:
        logger.error("TypeError")
        return -1


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    command = parse()

    dest_address = (command.dest, command.port)
    message = serialize_cmd(command)

    try:

        print('Sending message to host %s\n%s:' % (dest_address[0], message))
        sock.bind(('', 10001))
        sock.sendto(sign(message), dest_address)

        if command.cmd == 'RUN' or command.cmd == 'GET':
            print('Waiting an answer...\n')
            data, device = sock.recvfrom(4096)
            logger.info("Answer from %s: %s " % (device[0], data))
            print('Answer from %s:\n%s' % (device[0], data))

        else:
            logger.info("CMD sent")
            print('CMD sent')

    finally:
        logger.info("Closing socket")
        sock.close()


if __name__ == '__main__':
    main()
