"""
Administrator interface to send commands to eBPF device
"""
import socket
import argparse
import json
import logging

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

admin_address = ('', 10001)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.ERROR)


def parse():
    """Parse user input command"""
    parser = argparse.ArgumentParser(description="Parser for cmd")
    parser.add_argument("cmd",
                        choices=['RUN', 'START', 'GET', 'STOP', 'PERIOD', 'THRESH'],
                        help='command for the eBPF device'
                        )
    parser.add_argument("dest",
                        nargs=2,
                        help='eBPF device ip address'
                        )
    parser.add_argument("-t",
                        "--time",
                        type=int,
                        default=10,
                        help='period of stat gathering [RUN], [PERIOD], [THRESH]')
    parser.add_argument("-i",
                        "--interval",
                        type=int, default=5,
                        help='<=time, period interval between two stat gathering [PERIOD]\\'
                             'maximum period interval for stat gathering [THRESH]')
    parser.add_argument("-s",
                        "--server",
                        nargs=2,
                        help='monitoring server ip address and port [RUN] [GET] [PERIOD] [THRESH]')
    parser.add_argument("-r",
                        "--rate",
                        type=float,
                        default=0.05,  # 5% loss
                        help='max rate of loss accepted (pkt_retrans/pkt_sent >rate) [THRESH]')
    args = parser.parse_args()
    logger.info('PARSED: [%s]' % args)
    return args


def serialize_cmd(command):
    """Input command to JSON format"""
    if command.cmd == 'RUN':
        if command.server:
            return json.dumps({'cmd': command.cmd,
                               'server': command.server,
                               'time': command.time
                               })
        else:
            return json.dumps({'cmd': command.cmd,
                               'time': command.time
                               })
    elif command.cmd == 'START' or command.cmd == 'STOP':
        return json.dumps({'cmd': command.cmd
                           })
    elif command.cmd == 'GET':
        if command.server:
            return json.dumps({'cmd': command.cmd,
                               'server': command.server
                               })
        else:
            return json.dumps({'cmd': command.cmd
                               })
    elif command.cmd == 'PERIOD' and command.server:
        if command.time < command.interval:
            return -1
        else:
            return json.dumps({'cmd': command.cmd,
                               'server': command.server,
                               'time': command.time,
                               'interval': command.interval
                               })
    elif command.cmd == 'THRESH' and command.server:
        return json.dumps({'cmd': command.cmd,
                           'server': command.server,
                           'time': command.time,
                           'rate': command.rate,
                           'interval': command.interval
                           })
    else:
        logger.error("Malformed input")
        return -1


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

    dest_address = (command.dest[0], int(command.dest[1]))
    message = serialize_cmd(command)
    if message == -1:
        print('Malformed input, use --help')
        return -1
    try:

        print('Sending message to host %s:%d\n%s' % (dest_address[0], dest_address[1], message))
        sock.bind(admin_address)
        signed_message = sign(message)
        if signed_message == -1:
            print('Error while signing')
            return -1
        sock.sendto(signed_message, dest_address)
        logger.info('Message to %s on port %s' % dest_address)

        # Receive one message
        if not command.server and command.cmd in ['GET', 'RUN']:
            print('Waiting an answer...\n')
            data, device = sock.recvfrom(4096)
            parsed = json.loads(data)
            printable = json.dumps(parsed, indent=4, sort_keys=True)
            logger.info("Answer from %s: %s " % (device[0], printable))
            print('Answer from %s:\n%s' % (device[0], printable))

    finally:
        logger.info("Closing socket")
        sock.close()


if __name__ == '__main__':
    main()
