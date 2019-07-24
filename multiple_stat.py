#!/usr/bin/python

from bcc import BPF
import socket
import time
import json
import logging

import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

stats_global = 0
running_global = 0
b = BPF(src_file="ebpf.c")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host_address = ('', 10000)


def serialize_stats():
    """Gathered statistics to JSON format"""
    global stats_global
    serialized = json.dumps({"rcv_packets": stats_global.rcv_packets,
                             "snt_packets": stats_global.snt_packets,
                             })
    return serialized


def update_stats(cpu, data, size):
    """Callback fun triggered when buffer_poll"""
    global stats_global
    event = b["events"].event(data)
    stats_global = event


def send_stats(initiator, server, port):
    """Sends statistics to server and ack to the initiator"""
    b.perf_buffer_poll()
    dst = (server, port)
    json_stats = serialize_stats()

    sock.sendto(json_stats, dst)
    logger.info('STATS to %s: \n%s\n' % (dst[0], json_stats))
    print('STATS to %s: \n%s\n' % (dst[0], json_stats))

    if dst[0] != initiator[0]:
        sock.sendto('ACK: Stats sent to: %s' % dst[0], initiator)
        logger.info('ACK to %s ' % initiator[0])
        print('ACK to %s ' % initiator[0])


def start_ebpf():
    """Start eBPF statistic gathering"""
    global running_global
    running_global = 1

    b.attach_kprobe(event="ip_rcv", fn_name="detect_rcv_pkts")
    b.attach_kprobe(event="ip_output", fn_name="detect_snt_pkts")

    b["events"].open_perf_buffer(update_stats)


def stop_ebpf():
    """Stop eBPF statistic gathering"""
    global running_global
    running_global = 0

    b.detach_kprobe("ip_rcv")
    b.detach_kprobe("ip_output")

    b["stats_map"].clear()


def cmd_run(init_address, command):
    """Run eBPF statistic gathering for x seconds"""
    logger.info('RUN for %s sec' % command['time'])

    start_ebpf()
    future = time.time() + command['time']
    while time.time() < future:
        time.sleep(0.01)

    send_stats(init_address, command['server'], command['port'])
    stop_ebpf()


def cmd_start(command):
    """START command process"""
    logger.info('START')
    start_ebpf()


def cmd_get(init_address, command):
    """GET command process"""
    logger.info('GET')
    send_stats(init_address, command['server'], command['port'])


def cmd_stop(command):
    """STOP command process"""
    logger.info('STOP')
    stop_ebpf()


def send_error(error_msg, address):
    """Send error to the indicated address"""
    logger.info('Error message sent to %s: %s' % (address[0], error_msg))
    sock.sendto(error_msg, address)


def verify_signature(signed_data):
    """Verification of signature"""
    data_tab = json.loads(signed_data)
    try:
        with open('public_key.pem', 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        public_key.verify(
            signature=base64.urlsafe_b64decode(str(data_tab['signature'])),
            data=data_tab['message'].encode('utf-8'),
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        logger.info('Verified host')
        return data_tab['message']
    except InvalidSignature:
        logger.error('Wrong signature - Spoofing attempt')
        return -1
    except ValueError:
        logger.error('Malformed signature')
        return -1


def main():
    try:
        sock.bind(host_address)
        logger.info('Socket binded to (addr:[%s],port:[%s])' % host_address)
        while True:
            print('Waiting to receive message...')
            data, init_address = sock.recvfrom(4096)
            logger.info('Message received')

            verified_data = verify_signature(data)
            if verified_data == -1:
                send_error('Bad signature', init_address)
            else:
                j = json.loads(verified_data)
                print('\nReceived message from %s:\n%s\n' % (init_address[0], verified_data))

                cmd = j['cmd']
                if cmd == 'RUN' and not running_global:
                    cmd_run(init_address, j)
                elif (cmd == 'START' or cmd == 'RUN') and running_global:
                    logger.warning('Already running')
                elif (cmd == 'GET' or cmd == 'STOP') and not running_global:
                    logger.error('Must first start the stat gathering with cmd: START')
                    send_error('ERROR: Must first start the stat gathering with cmd: START', init_address)
                elif cmd == 'START' and not running_global:
                    cmd_start(j)
                elif cmd == 'GET' and running_global:
                    cmd_get(init_address, j)
                elif cmd == 'STOP' and running_global:
                    cmd_stop(j)
                else:
                    logger.error('Wrong command')
                    print('ERROR: Wrong command')

    finally:
        logger.info('Closing socket')
        sock.close()


if __name__ == '__main__':
    main()
