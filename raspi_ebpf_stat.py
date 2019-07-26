# !/usr/bin/python
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

running_global = 0
b = BPF(src_file="ebpf_map_stat.c")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host_address = ('', 10000)


def gather_data():
    data_map = b["ports_map"]
    for k, v in data_map.items():
        if v.value != 0:
            print(k.value, v.value)
    return 0


def port_map_to_list():
    data_map = b["ports_map"]
    port_list = []
    for k, v in data_map.items():
        if v.value != 0:
            port_list.append(k.value)
    return port_list


def serialize_stats():
    """Gathered statistics to JSON format"""
    serialized = json.dumps({"rcv_packets": b["stats_map"][0].value,
                             "snt_packets": b["stats_map"][1].value,
                             "tcp_packets": b["proto_map"][socket.IPPROTO_TCP].value,
                             "udp_packets": b["proto_map"][socket.IPPROTO_UDP].value,
                             "icmp_packets": b["proto_map"][socket.IPPROTO_ICMP].value,
                             "arp_packets": b["stats_map"][2].value,
                             "snd_ports": port_map_to_list(),
                             "ipv4_packets": b["stats_map"][3].value,
                             "ipv6_packets": b["stats_map"][4].value,
                             "lost_packets": b["stats_map"][5].value,
                             })
    return serialized


def send_error(error_msg, address):
    """Send error to the indicated address"""
    logger.info('Error message sent to %s: %s' % (address[0], error_msg))
    sock.sendto(error_msg, address)


def send_stats(initiator, command):
    """Sends statistics to server and ack to the initiator"""

    json_stats = serialize_stats()

    if 'server' in command:  # Send stats to server
        stat_dst = (command['server'][0], int(command['server'][1]))
        ack_dst = initiator

        sock.sendto(json_stats, stat_dst)
        logger.info('STATS to %s: \n%s' % (stat_dst[0], json_stats))
        print('STATS to %s: \n%s\n' % (stat_dst[0], json_stats))
        ack_msg = 'ACK: Stats sent to: %s:%s' % (stat_dst[0], stat_dst[1])
        sock.sendto(ack_msg, ack_dst)
        logger.info('ACK to %s:%s' % (ack_dst[0], ack_dst[1]))
        print('ACK to %s:%s ' % (ack_dst[0], ack_dst[1]))

    else:  # Send stats to initiator
        stat_dst = initiator
        sock.sendto(json_stats, stat_dst)
        logger.info('STATS to %s: \n%s' % (stat_dst[0], json_stats))
        print('STATS to %s: \n%s\n' % (stat_dst[0], json_stats))


def start_ebpf():
    """Start eBPF statistic gathering"""
    global running_global
    running_global = 1

    b.attach_kprobe(event="ip_rcv", fn_name="detect_rcv_pkts")
    b.attach_kprobe(event="ip_rcv", fn_name="detect_protocol")
    b.attach_kprobe(event="ip_output", fn_name="detect_snt_pkts")
    b.attach_kprobe(event="ip_output", fn_name="detect_protocol")
    b.attach_kprobe(event="arp_rcv", fn_name="detect_arp")
    b.attach_kprobe(event="arp_send", fn_name="detect_arp")
    b.attach_kprobe(event="ip_output", fn_name="detect_dport")
    b.attach_kprobe(event="ip_output", fn_name="detect_family")
    b.attach_kprobe(event="ip_rcv", fn_name="detect_family")
    b.attach_kprobe(event="tcp_enter_loss", fn_name="detect_lost_pkts")


def stop_ebpf():
    """Stop eBPF statistic gathering"""
    global running_global
    running_global = 0

    b.detach_kprobe("ip_rcv")
    b.detach_kprobe("ip_output")
    b.detach_kprobe("arp_rcv")
    b.detach_kprobe("arp_send")

    b["stats_map"].clear()
    b["proto_map"].clear()


def cmd_run(init_address, command):
    """Run eBPF statistic gathering for x seconds"""
    logger.info('RUN for %s sec' % command['time'])

    start_ebpf()
    future = time.time() + command['time']
    while time.time() < future:
        time.sleep(0.01)

    send_stats(init_address, command)
    stop_ebpf()


def cmd_start(command):
    """START command process"""
    logger.info('START')
    start_ebpf()


def cmd_get(init_address, command):
    """GET command process"""
    logger.info('GET')
    send_stats(init_address, command)


def cmd_stop(command):
    """STOP command process"""
    logger.info('STOP')
    stop_ebpf()


def cmd_period(init_address, command):
    """PERIOD command process"""
    logger.info('PERIOD')
    start_ebpf()

    future = time.time() + command['time']
    while time.time() < future:
        logger.info('Interval: %s sec' % command['interval'])
        time.sleep(int(command['interval']))
        send_stats(init_address, command)

    stop_ebpf()


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
                elif (cmd == 'START' or cmd == 'RUN' or cmd == 'PERIOD') and running_global:
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
                elif cmd == 'PERIOD' and not running_global:
                    cmd_period(init_address, j)
                else:
                    logger.error('Wrong command')
                    print('ERROR: Wrong command')

    finally:
        logger.info('Closing socket')
        sock.close()


if __name__ == '__main__':
    main()
