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

prog = """
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

struct stats {
    u64 rcv_packets;
    u64 snt_packets;
};

BPF_HASH(stats_map,u64,struct stats);

BPF_PERF_OUTPUT(events);

int detect_rcv_pkts(struct pt_regs *ctx, void *skb){
    struct stats stats_data = {};
    u64 socket_index = 0, rcv_packets_nb_inter=1;
    struct stats *rcv_packets_nb_ptr;

    rcv_packets_nb_ptr = stats_map.lookup(&socket_index);

    if(rcv_packets_nb_ptr != 0){
        rcv_packets_nb_inter = (*rcv_packets_nb_ptr).rcv_packets;
        
        rcv_packets_nb_inter++;

        stats_data=*rcv_packets_nb_ptr;
        stats_data.rcv_packets = rcv_packets_nb_inter;

        events.perf_submit(ctx, &stats_data, sizeof(stats_data));
        
    }
    stats_map.delete(&socket_index);
    stats_map.update(&socket_index, &stats_data);
    return 0;
}

int detect_snt_pkts(struct pt_regs *ctx, void *skb){
    struct stats stats_data = {};
    u64 socket_index = 0, snt_packets_nb_inter=1;
    struct stats *snt_packets_nb_ptr;

    snt_packets_nb_ptr = stats_map.lookup(&socket_index);

    if(snt_packets_nb_ptr != 0){
        snt_packets_nb_inter = (*snt_packets_nb_ptr).snt_packets;
        
        snt_packets_nb_inter++;

        stats_data=*snt_packets_nb_ptr;
        stats_data.snt_packets = snt_packets_nb_inter;

        events.perf_submit(ctx, &stats_data, sizeof(stats_data));
        
    }
    stats_map.delete(&socket_index);
    stats_map.update(&socket_index, &stats_data);
    return 0;
}
"""
stats_global=0
# Loads eBPF program
b = BPF(text=prog)

def update_stats(cpu, data, size):
    global stats_global
    event = b["events"].event(data)
    stats_global=event;

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host_address = ('', 10000)

print('Listening on address: %s port: %s' % host_address)
sock.bind(host_address)

while True:
    print('Waiting to receive message...')
    data, init_address = sock.recvfrom(4096)
    
    print('\nReceived message from %s:\n%s\n' % (init_address[0], data))
    j = json.loads(data);

    if j['cmd'] == 'RUN':
	interval = j['time']
        print('Gathering statistics for %s seconds...' % interval)
        
	b = BPF(text=prog)

	b.attach_kprobe(event="ip_rcv", fn_name="detect_rcv_pkts")
	b.attach_kprobe(event="ip_output", fn_name="detect_snt_pkts")	

	future = time.time() + interval
	b["events"].open_perf_buffer(update_stats)
	while time.time() < future:
	    a=0
	b.perf_buffer_poll()
	data=json.dumps({"rcv_packets" : stats_global.rcv_packets, "snt_packets" : stats_global.snt_packets,})
	server = (j['server'],j['port'])

        sock.sendto(data, server)
	sock.sendto('ACK: Stats sent to: %s' % server[0] , init_address)
        print('Message sent to %s: \n%s\n' % (server[0],data))
        b.detach_kprobe("ip_rcv")
	b.detach_kprobe("ip_output")
    if j['cmd'] == 'START':
        print('Gathering statistics...')
        
	b = BPF(text=prog)

	b.attach_kprobe(event="ip_rcv", fn_name="detect_rcv_pkts")
	b.attach_kprobe(event="ip_output", fn_name="detect_snt_pkts")	

	future = time.time() + interval
	b["events"].open_perf_buffer(update_stats)

	data, init_address = sock.recvfrom(4096)
	while time.time() < future:
	    b.perf_buffer_poll()

	data=json.dumps({"rcv_packets" : stats_global.rcv_packets, "snt_packets" : stats_global.snt_packets,})
	server = (j['server'],j['port'])

        sock.sendto(data, server)
	sock.sendto('ACK: Stats sent to: %s' % server[0] , init_address)
        print('Message sent to %s: \n%s\n' % (server[0],data))
        b.detach_kprobe("ip_rcv")
	b.detach_kprobe("ip_output")


