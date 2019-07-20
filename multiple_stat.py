#!/usr/bin/python

from bcc import BPF
import ctypes as ct
import datetime
import socket
import sys
from bcc.utils import printb
import time
from time import sleep
import json

import base64
import logging

from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes


stats_global = 0
running_global = 0
b = BPF(src_file="ebpf.c")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host_address = ('', 10000)


def update_stats(cpu, data, size):
    global stats_global
    event = b["events"].event(data)
    stats_global = event


def send_stats(initiator, server, port):
    global stats_global
    b.perf_buffer_poll()
    data = json.dumps({"rcv_packets": stats_global.rcv_packets, "snt_packets": stats_global.snt_packets, })
    server = (server, port)
    sock.sendto(data, server)
    if server[0] != initiator[0]:
        sock.sendto('ACK: Stats sent to: %s' % server[0], initiator)
    print('Message sent to %s: \n%s\n' % (server[0], data))


def start_eBPF():
    global running_global
    running_global = 1

    b.attach_kprobe(event="ip_rcv", fn_name="detect_rcv_pkts")
    b.attach_kprobe(event="ip_output", fn_name="detect_snt_pkts")

    b["events"].open_perf_buffer(update_stats)


def cmd_RUN(command):
    global running_global
    running_global = 1
    interval = command['time']
    print('Gathering statistics for %s seconds...' % interval)

    start_eBPF()
    future = time.time() + interval
    while time.time() < future:
        sleep(0.01)
    send_stats(init_address, command['server'], command['port'])
    b["stats_map"].clear()
    b.detach_kprobe("ip_rcv")
    b.detach_kprobe("ip_output")
    running_global = 0


def cmd_START(command):
    print('Gathering of statistics started')
    global running_global
    running_global = 1
    start_eBPF()

    b.attach_kprobe(event="ip_rcv", fn_name="detect_rcv_pkts")
    b.attach_kprobe(event="ip_output", fn_name="detect_snt_pkts")

    b["events"].open_perf_buffer(update_stats)


def cmd_GET(command):
    send_stats(init_address, command['server'], command['port'])

def cmd_STOP(command):

    b.detach_kprobe("ip_rcv")
    b.detach_kprobe("ip_output")
    b["stats_map"].clear()
    global running_global
    running_global = 0

def verify_signature(signed_data):
    data_tab = json.loads(signed_data);
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    try:
        public_key.verify(
            signature=data_tab['signature'],
            data=data_tab['message'].encode('utf-8'),
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        #Signature is correct
        return data_tab['message']
    except InvalidSignature:
        #Wrong signature
        print("Wrong signature")

try:
    print('Listening on address: %s port: %s' % host_address)
    sock.bind(host_address)

    while True:
        print('Waiting to receive message...')
        data, init_address = sock.recvfrom(4096)

        print('\nReceived message from %s:\n%s\n' % (init_address[0], data))
        #j = json.loads(data);
        j = json.loads(verify_signature(data));
        cmd = j['cmd']
        if cmd == 'RUN' and not running_global:
            cmd_RUN(j)
        elif (cmd == 'START' or cmd =='RUN') and running_global:
            print("ERROR: Already running")
        elif cmd == 'START' and not running_global:
            cmd_START(j)
        elif (cmd == 'GET' or cmd == 'STOP') and not running_global:
            error_msg = "ERROR: Must first start the stat gathering with cmd: START"
            print(error_msg)
            sock.sendto(error_msg, init_address)
        elif cmd == 'GET' and running_global:
            cmd_GET(j)
        elif cmd == 'STOP' and running_global:
            cmd_STOP(j)
        else:
            print("ERROR: Wrong command")

finally:
    print('Closing socket')
    sock.close()
