#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

BPF_HASH(stats_map,u64);
/*
stats_map[0]=rcv_packets
stats_map[1]=snt_packets
stats_map[2]=udp_rcv_packets
stats_map[3]=tcp_rcv_packets
*/

int detect_rcv_pkts(struct pt_regs *ctx, void *skb){
    u64 key= 0;
    stats_map.increment(key);
    return 0;
}

int detect_snt_pkts(struct pt_regs *ctx, void *skb){
    u64 key= 1;
    stats_map.increment(key);
    return 0;
}
