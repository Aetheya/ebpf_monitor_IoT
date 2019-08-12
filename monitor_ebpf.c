#include <linux/skbuff.h>
#include <linux/types.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>

/* Channel to userspace for events */
BPF_PERF_OUTPUT(events);//

/* Maps shared between kernel and userspace */
BPF_ARRAY(stats_map, u64, 8);
BPF_ARRAY(proto_map_snd, u64, 256);
BPF_ARRAY(ports_map, u64, 65536);


/*
stats_map[0]=rcv_packets
stats_map[1]=snt_packets
stats_map[2]=arp_packets
stats_map[3]=ipv4_packets
stats_map[4]=ipv6_packets
stats_map[5]=retrans_packets

proto_map_snd[x]=y [x= protocol number y = counter]
ports_map[x]=y [x= port number, y= counter]
*/

struct losing_rate {
    u64 snt_packets;
    u64 retrans_packets;
};

static int process_loss(struct pt_regs *ctx){

    struct losing_rate rate = {};  // Object to be sent to userspace
    int rcv_packets_index = 0, tcp_packets_index = IPPROTO_TCP,  retrans_packets_index=5;
    u64 *snt_packets_ptr, *retrans_packets_ptr, zero=0 ;

        /* Retrieve current stats linked to data loss */
        snt_packets_ptr = proto_map_snd.lookup_or_init(&tcp_packets_index,&zero);
        retrans_packets_ptr = stats_map.lookup_or_init(&retrans_packets_index,&zero);

    if(snt_packets_ptr != 0 && retrans_packets_ptr !=0 ){
        /* Fill object to be sent to userspace */
        rate.snt_packets = *snt_packets_ptr;
        rate.retrans_packets =*retrans_packets_ptr;

        events.perf_submit(ctx, &rate, sizeof(rate)); // Send data to userspace
    }
        return 0;
}

int detect_rcv_pkts(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
    int rcv_pkts_index = 0;
    u64 rcv_packets_nb_inter = 0, *rcv_packets_nb_ptr;

    //Could also use stats_map.increment(rcv__pkts_index);
    rcv_packets_nb_ptr = stats_map.lookup(&rcv_pkts_index);

    if(rcv_packets_nb_ptr != 0){
        rcv_packets_nb_inter = *rcv_packets_nb_ptr;
        rcv_packets_nb_inter++;
    }
    stats_map.delete(&rcv_pkts_index);
    stats_map.update(&rcv_pkts_index, &rcv_packets_nb_inter);

    return 0;
}

int detect_snt_pkts(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb){
    int snt_pkts_index = 1;
    u64 snt_packets_nb_inter = 0, *snt_packets_nb_ptr;

    //Could also use stats_map.increment(snt__pkts_index);
    snt_packets_nb_ptr = stats_map.lookup(&snt_pkts_index);

    if(snt_packets_nb_ptr != 0){
        snt_packets_nb_inter = *snt_packets_nb_ptr;
        snt_packets_nb_inter++;
    }
    stats_map.delete(&snt_pkts_index);
    stats_map.update(&snt_pkts_index, &snt_packets_nb_inter);
    return 0;
}

int detect_dport(struct pt_regs *ctx, struct sk_buff *skb, struct sock *sk){
    u16 dport = -1;
    dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    ports_map.increment(dport);
    return 0;
}

int detect_protocol_snd(struct pt_regs *ctx, struct sk_buff *skb, struct sock *sk){
    u8 protocol = -1;//protocol number

    // Workaround to get bitfield of protocol number found on official BCC Github.
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
    proto_map_snd.increment(protocol);
    return 0;
}

int detect_arp(struct pt_regs *ctx, struct sk_buff *skb, struct sock *sk){
    u8 key= 2;
    stats_map.increment(key);
    return 0;
}

int detect_family(struct pt_regs *ctx, struct sk_buff *skb, struct sock *sk){
    u8 index_ipv4= 3;
    u8 index_ipv6= 4;
    u16 family = sk->__sk_common.skc_family;
    if (family == AF_INET) stats_map.increment(index_ipv4);
    else if (family == AF_INET6) stats_map.increment(index_ipv6);
    return 0;
}

int detect_retrans_pkts(struct pt_regs *ctx, struct sk_buff *skb, struct sock *sk){
    u8 index= 5;
    stats_map.increment(index);
    return 0;
}

int detect_thresh_pkts(struct pt_regs *ctx, struct sk_buff *skb, struct sock *sk){
    u8 index= 5;
    stats_map.increment(index);
    process_loss(ctx);
    return 0;
}