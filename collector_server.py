"""
Naive statistics collector server
"""
import socket
import json


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('', 10002))
        while True:
            print('Waiting data to collect...\n')
            data, server = sock.recvfrom(4096)
            if data:
                parsed = json.loads(data)
                printable = json.dumps(parsed, indent=4, sort_keys=True)
                print('Received message from %s:\n%s' % (server[0], printable))

    finally:
        print('Closing socket')
        sock.close()


if __name__ == '__main__':
    main()
