#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

struct stats {
    u64 rcv_packets;
    u64 snt_packets;
    u64 udp_rcv_packets;
    u64 tcp_rcv_packets;
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

int detect_protocol(struct pt_regs *ctx, void *skb){

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