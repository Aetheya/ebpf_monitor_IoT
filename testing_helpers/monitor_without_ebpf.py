from __future__ import division  # Get float instead of int for div
import socket
import time
import json
import logging
import random

import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

b = {'stats_map': [0] * 100, 'proto_map': [0] * 100, 'ports_map': [0] * 100}

running_global = 0
losing_rate_global = 0
start_time_global = 0

host_address = ('', 10000)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def serialize_stats():
    """Parse gathered statistics to JSON format"""
    global start_time_global
    serialized = json.dumps({'time_start': start_time_global,
                             'time_end': time.time(),
                             'rcv_packets': b.get('stats_map')[0],
                             'snt_packets': b.get('stats_map')[1],
                             'tcp_packets': b.get('proto_map')[socket.IPPROTO_TCP],
                             'udp_packets': b.get('proto_map')[socket.IPPROTO_UDP],
                             'icmp_packets': b.get('proto_map')[socket.IPPROTO_ICMP],
                             'arp_packets': b.get('stats_map')[2],
                             'ports': port_map_to_list(),
                             'ipv4_packets': b.get('stats_map')[3],
                             'ipv6_packets': b.get('stats_map')[4],
                             'retrans_packets': b.get('stats_map')[5]
                             })
    return serialized


def port_map_to_list():
    """Gather ports numbers and make a list"""
    port_list = []
    ports = b.get('ports_map')
    for k in ports:
        if k != 0:
            port_list.append(k)
    return port_list


def send_error(error_msg, address):
    """Send error to the indicated address"""
    logger.info('Error message sent to %s: %s' % (address[0], error_msg))
    sock.sendto(error_msg, address)


def random_wait():
    """Wait for x seconds"""
    val = random.uniform(0, 101) / 100  # Between 0 and 1 seconds
    time.sleep(val)


def send_stats(initiator, command):
    """Sends statistics to server or initiator"""
    json_stats = serialize_stats()
    logger.info('Gathered stats:%s' % json_stats)

    if 'server' in command:  # Send stats to server
        stat_dst = (command['server'][0], int(command['server'][1]))
    else:  # Send stats to initiator
        stat_dst = initiator

    #random_wait()  # Avoid sync between eBPF devices
    sock.sendto(json_stats, stat_dst)
    logger.info('Stats sent to %s' % (stat_dst[0]))
    print('Stats sent to %s' % (stat_dst[0]))

    clean_maps()


def clean_maps():
    b['stats_map'] = [0] * 256
    b['proto_map'] = [0] * 256
    b['ports_map'] = [0] * 256


def start_ebpf():
    """Start eBPF statistic gathering"""
    global running_global
    running_global = 1


def stop_ebpf():
    """Stop eBPF statistic gathering"""
    global running_global
    running_global = 0

    clean_maps()


def cmd_run(init_address, command):
    """RUN command process"""
    global start_time_global
    logger.info('RUN for %s sec' % command['time'])
    start_ebpf()

    start_time_global = time.time()  # eBPF starting timestamp
    time.sleep(command['time'])  # Period of stat gathering

    send_stats(init_address, command)
    stop_ebpf()


def cmd_start():
    """START command process"""
    global start_time_global
    logger.info('START')
    start_ebpf()
    start_time_global = time.time()


def cmd_get(init_address, command):
    """GET command process"""
    global start_time_global
    logger.info('GET')
    send_stats(init_address, command)
    start_time_global = time.time()


def cmd_stop():
    """STOP command process"""
    logger.info('STOP')
    stop_ebpf()


def cmd_period(init_address, command):
    """PERIOD command process"""
    global start_time_global
    logger.info('PERIOD for %s sec, interval %s sec' % (command['time'], command['interval']))
    start_ebpf()

    future = time.time() + command['time']
    while time.time() < future:  # Total period of stats gathering
        print('Next period')
        start_time_global = time.time()  # eBPF starting timestamp
        time.sleep(command['interval'])  # Interval between two stats gathering
        send_stats(init_address, command)

    stop_ebpf()




def verify_signature(signed_data):
    """Verification of signature"""
    data_tab = json.loads(signed_data)
    try:
        with open('public_key.pem', 'rb') as key_file:  # Public key file
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
        logger.error('Wrong signature')
        return -1
    except ValueError:
        logger.error('Malformed signature')
        return -1


def main():
    try:
        sock.bind(host_address)
        logger.info('Socket binded to (addr:[%s],port:[%s])' % host_address)
        while True:
            print('Waiting for message...')
            data, init_address = sock.recvfrom(4096)
            logger.info('Message received')

            verified_data = verify_signature(data)
            if verified_data == -1:
                send_error('Bad signature', init_address)
            else:
                j = json.loads(verified_data)
                print('\nMessage received from %s:\n%s\n' % (init_address[0], verified_data))

                # Processing the command
                cmd = j['cmd']
                # Wrong command
                if (cmd == 'START' or cmd == 'PERIOD' or cmd == 'THRESH') and running_global:
                    logger.error('Already running')
                elif (cmd == 'RUN') and running_global:
                    logger.error('Already running')
                    send_error('ERROR: Already running', init_address)
                elif cmd == 'GET' and not running_global:
                    logger.error('Must first start the stat gathering with cmd: START')
                    send_error('ERROR: Must first start the stat gathering with cmd: START', init_address)
                elif cmd == 'STOP' and not running_global:
                    logger.error('Must first start the stat gathering with cmd: START')

                # Normal behavior
                elif cmd == 'RUN' and not running_global:
                    cmd_run(init_address, j)
                elif cmd == 'START' and not running_global:
                    cmd_start()
                elif cmd == 'GET' and running_global:
                    cmd_get(init_address, j)
                elif cmd == 'STOP' and running_global:
                    cmd_stop()
                elif cmd == 'PERIOD' and not running_global:
                    cmd_period(init_address, j)
                else:
                    logger.error('Wrong command')
                    print('ERROR: Wrong command')

    except (KeyboardInterrupt, SystemExit):
        print("\nClosed.")
    finally:
        logger.info('Closing socket')
        sock.close()


if __name__ == '__main__':
    main()
