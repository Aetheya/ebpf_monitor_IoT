import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('192.168.1.10', 8888)
print('starting up on %s port %s' % server_address)
sock.bind(server_address)
# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        print('connection from', client_address)

        # Receive the data in small chunks and retransmit it
        incr = 0
        while True:
            data = connection.recv(16)
            incr = incr+1
            print('received msg' + incr)
            if not data:
                print('no more data from', client_address)
                break

    finally:
        # Clean up the connection
        connection.close()
