//go:build ignore

#include "../config/config.h"
#include "bpf/bpf_helpers.h"

#define SCALE_MS_TO_NS 1000000

char _license[] SEC("license") = "GPL";

// artificial latency
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} delay_map SEC(".maps");

// jitter of latency
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} jitter_map SEC(".maps");

// drop horizon (after how many seconds should packet be dropped?) -> if enabled, needs to be smaller than delay
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} drop_horizon_map SEC(".maps");

SEC("tc")
int egress_delay(struct __sk_buff *skb) {
    void *data   = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 key = 0;

    __u8 proto;
    __u16 ip_proto;
    union ip_address src_addr = {0};
    int ip_hdr_length = 0;

    if (!parse_packet(data, data_end, &proto, &ip_proto, &src_addr, &ip_hdr_length)) {
        goto done;
    }

    // skip if packets are neither ICMP, TCP nor UDP
    if (!process_protocols(proto)) {
        goto done;
    }

    __u32 *delay = bpf_map_lookup_elem(&delay_map, &key);
    if(!(delay && *delay)) {
        // no delay specified ... do not delay packet!
        goto done;
    }
    // schedule time in future to send packet (e.g. 100ms)
    __u64 delay_ns = *delay * SCALE_MS_TO_NS;

    __u32 *jitter = bpf_map_lookup_elem(&jitter_map, &key);
    if(jitter && *jitter) {
        // possible variation of delay
        __u64 jitter_ns = *jitter * SCALE_MS_TO_NS;
        // determine if positive or negative jitter
        __u8 jitter_pos_neg = bpf_get_prandom_u32() % 2;
        if(jitter_pos_neg) {
            delay_ns += (bpf_get_prandom_u32() % (jitter_ns + 1));
        } else if (jitter_ns < delay_ns) {
            delay_ns -= (bpf_get_prandom_u32() % (jitter_ns + 1));
        } else {
            delay_ns = 0;
        }
    }

    // current time in nano seconds
    __u64 now_ns = bpf_ktime_get_ns();

    // scheduled time to send packet
    __u64 sched_time = now_ns + delay_ns;

    // update scheduled time to send packet
    skb->tstamp = sched_time;

    if(!(jitter && *jitter)) {
        goto done;
    }

    // skip this part if jitter is not set to avoid invalid mem access
    __u32 *drop_horizon = bpf_map_lookup_elem(&drop_horizon_map, &key);
    if(drop_horizon && *drop_horizon && (*drop_horizon < (*delay + *jitter))) {
        if(delay_ns > (*drop_horizon * SCALE_MS_TO_NS)) {
            return TC_ACT_SHOT;
        }
    }

done:
    return TC_ACT_OK;
}