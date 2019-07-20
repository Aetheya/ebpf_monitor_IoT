import socket
import sys
import argparse
import json

#TODO nargs
parser = argparse.ArgumentParser(description="Parser for cmd")
parser.add_argument("cmd", choices=['RUN', 'START', 'GET', 'STOP'])
parser.add_argument("-t","--time", type=int, default=3)
parser.add_argument("dest", default='192.168.1.8')#ebpf machine
parser.add_argument("-s","--server",default="192.168.1.13")
parser.add_argument("-p","--port",default=10000)
args = parser.parse_args()

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

dest_address = (args.dest, args.port)
message=json.dumps({"cmd" : args.cmd, "time" : args.time, "server" : args.server, "port" : args.port})
try:

    # Send data
    print('Sending message to host %s\n%s:' % (dest_address[0],message))
    sock.bind(('', 10000))
    sent = sock.sendto(message, dest_address)

    # Receive response
    if args.cmd == 'RUN' or args.cmd == 'GET':
        print ('Waiting an answer...\n')
        data, server = sock.recvfrom(4096)
        print('Received message from %s:\n%s' % (server[0],data) )

    else:
        print('CMD sent')

finally:
    print ('Closing socket')
    sock.close()

