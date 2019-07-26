#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

#include <uapi/linux/ip.h> // struct iphdr
#include <linux/types.h> //eth_head
#include <uapi/linux/if_ether.h>
//#include <net/sock.h>
#include <net/sock.h>

BPF_HASH(stats_map,u64);

BPF_ARRAY(proto_map, u8, 256);
//BPF_HASH(proto_map,u8);
/*
stats_map[0]=rcv_packets
stats_map[1]=snt_packets
stats_map[2]=udp_rcv_packets
stats_map[3]=tcp_rcv_packets
d
*/
/*
int detect_protocol(struct __sk_buff *skb){

   int key1 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));

    u8 *value = proto_map.lookup(&key1);
    if (value)
	    proto_map.increment(key1);
    return 0;
}*/

int detect_rcv_pkts(struct pt_regs *ctx,struct sk_buff *skb,struct sock *sk){

    u8 protocol = 0;
    //struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);µ
        struct sock *newsk = sk;


    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);
    if (sk_lingertime_offset - gso_max_segs_offset == 4)
        // 4.10+ with little endian
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 3);
    else
        /// pre-4.10 with little endian -> renvoie 0 tt ltemps
        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 3);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        // 4.10+ with big endian
        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 1);
    else
        // pre-4.10 with big endian -> renvoie 0 tt ltemps
        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 1);
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
    proto_map.increment(protocol);
    u8 key2 = 7;

    if (protocol == IPPROTO_TCP) { proto_map.increment(key2);}

    u64 key= 0;
    stats_map.increment(key);
    return 0;
}

int detect_snt_pkts(struct pt_regs *ctx, struct sk_buff *skb){


    u64 key= 1;
    stats_map.increment(key);
    return 0;
}
