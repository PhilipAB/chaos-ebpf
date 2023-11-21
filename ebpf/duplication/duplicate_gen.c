//go:build ignore

#include "../config/config.h"
#include "bpf/bpf_helpers.h"

char _license[] SEC("license") = "GPL";

/**
 * duplication probability in % --- default is 5%
*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} duplication_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} traffic_direction SEC(".maps");

SEC("tc")
int duplicate_pkt(struct __sk_buff *skb) {
    // To prevent infinite cloning, let's classify our packets in cloned/not cloned packets
    if (skb->mark == CLONED_PKT) {
        skb->mark = 0;
        return TC_ACT_OK;
    }

    skb->mark = CLONED_PKT;
    void *data   = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u8 proto;
    __u16 ip_proto;
    union ip_address src_addr = {0};
    __u32 key = 0;
	int ip_hdr_length = 0;

	if (!parse_packet(data, data_end, &proto, &ip_proto, &src_addr, &ip_hdr_length)) {
		goto done;
	}

    // skip if packets are neither ICMP, TCP nor UDP
    if (!process_protocols(proto)) {
        goto done;
    }

    __u32 *pkt_dupl_rate = bpf_map_lookup_elem(&duplication_rate_map, &key);
    if(!pkt_dupl_rate || *pkt_dupl_rate > 100) {
        // The drop rate is invalid. Therefore we can not drop any packets.
        goto done;
    }
    // determine if a packet should be duplicated
    if (bpf_get_prandom_u32() % 100 < *pkt_dupl_rate) {
        // if so determine if on ingress or egress and redirect
        __u8 *traffic_dir = bpf_map_lookup_elem(&traffic_direction, &key);
        if(traffic_dir && *traffic_dir) {
            bpf_clone_redirect(skb, skb->ifindex, 0);
        } else {
            bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
        }
    }

done:
    // pass original packet
    return TC_ACT_OK;
}