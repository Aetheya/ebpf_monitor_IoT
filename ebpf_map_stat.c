#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

#include <uapi/linux/ip.h>
#include <linux/types.h>
#include <uapi/linux/if_ether.h>
#include <net/sock.h>

BPF_ARRAY(stats_map, u8,256);
BPF_ARRAY(proto_map, u8, 256);
BPF_ARRAY(ports_map, u16, 65536);

/*
stats_map[0]=rcv_packets
stats_map[1]=snt_packets
stats_map[2]=arp_packets
stats_map[3]=ipv4_packets
stats_map[4]=ipv6_packets

proto_map[x]=y x= protocol number
ports_map[x]=y x= port number

*/

int detect_rcv_pkts(struct pt_regs *ctx,struct sk_buff *skb,struct sock *sk){

    u8 key= 0;
    stats_map.increment(key);
    return 0;
}

int detect_protocol(struct pt_regs *ctx, struct sk_buff *skb,struct sock *sk){
    u8 protocol = 0;

    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);
    if (sk_lingertime_offset - gso_max_segs_offset == 4)
        // 4.10+ with little endian
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        protocol = *(u8 *)((u64)&sk->sk_gso_max_segs - 3);
    else
        /// pre-4.10 with little endian
        protocol = *(u8 *)((u64)&sk->sk_wmem_queued - 3);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        // 4.10+ with big endian
        protocol = *(u8 *)((u64)&sk->sk_gso_max_segs - 1);
    else
        // pre-4.10 with big endian
        protocol = *(u8 *)((u64)&sk->sk_wmem_queued - 1);
#else
# error "Fix your compiler's __BYTE_ORDER__"
#endif
    proto_map.increment(protocol);
    return 0;
}

int detect_arp(struct pt_regs *ctx, struct sk_buff *skb,struct sock *sk){
    u8 key= 2;
    stats_map.increment(key);
    return 0;
}


int detect_snt_pkts(struct pt_regs *ctx, struct sk_buff *skb,struct sock *sk){

    u8 key= 1;
    stats_map.increment(key);
    return 0;
}

int detect_dport(struct pt_regs *ctx, struct sk_buff *skb,struct sock *sk){

    u16 dport = 0;
    dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    ports_map.increment(dport);
    return 0;

}

int detect_family(struct pt_regs *ctx, struct sk_buff *skb,struct sock *sk){
    u8 key_ipv4= 3;
    u8 key_ipv6= 4;
    u16 family = sk->__sk_common.skc_family;
    if (family == AF_INET) stats_map.increment(key_ipv4);
    else if (family == AF_INET6) stats_map.increment(key_ipv6);
    return 0;
}

int detect_lost_pkts(struct pt_regs *ctx, struct sk_buff *skb,struct sock *sk){

    u8 key= 5;
    stats_map.increment(key);
    return 0;
}