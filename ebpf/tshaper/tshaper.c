//go:build ignore

#include "../config/config.h"
#include "bpf/bpf_helpers.h"

/* Need to be GPL so that we can use the map helpers. */
char __license[] SEC("license") = "GPL";

/**
 * Reference for ebpf map definitions: https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/test_pinning.c
*/

/**
 * Maps for debugging purposes
 * 
 * total_pkts_map counter for total packets
 * dropped_pkts_map counter for dropped packets
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} total_pkts_map SEC(".maps"), dropped_pkts_map SEC(".maps");

/**
 * drop_rate probability in % that a packet is dropped --- default is 5%
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} drop_rate SEC(".maps");

/**************************************************************************************************************
 * XDP programs
 *
 * This section contains eBPF programs at eXpress Data Path level (XDP).
 **************************************************************************************************************/

/**
 * XDP program for traffic shaping
*/
SEC("xdp")
int xdp_traffic_shaper(struct xdp_md *ctx) {
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u8 proto;
	__u16 ip_proto; // unused here but may used in other programs
	union ip_address src_addr; // unused here but may used in other programs
	__u32 key = 0;
	int ip_hdr_length = 0;

	if (!parse_packet(data, data_end, &proto, &ip_proto, &src_addr, &ip_hdr_length)) {
		goto done;
	}

	// skip if packets are neither ICMP, TCP nor UDP
	if (!process_protocols(proto)) {
		goto done;
	}

	__u32 *total_pkts = bpf_map_lookup_elem(&total_pkts_map, &key);
	if (!total_pkts) {
		__u32 initial_total_pkts = 1;
		bpf_map_update_elem(&total_pkts_map, &key, &initial_total_pkts, BPF_ANY);
	} else {
		__sync_fetch_and_add(total_pkts, 1);
	}

	__u32 *pkt_drop_rate = bpf_map_lookup_elem(&drop_rate, &key);
	if(!pkt_drop_rate || *pkt_drop_rate > 100) {
		// The drop rate is invalid. Therefore we can not drop any packets.
		goto done;
	}
	if (bpf_get_prandom_u32() % 100 < *pkt_drop_rate) {
		__u32 *dropped_pkts = bpf_map_lookup_elem(&dropped_pkts_map, &key);
		if (!dropped_pkts) {
			__u32 initial_dropped_pkts = 1;
			bpf_map_update_elem(&dropped_pkts_map, &key, &initial_dropped_pkts, BPF_ANY);
		} else {
			__sync_fetch_and_add(dropped_pkts, 1);
		}
		return XDP_DROP;
	}

done:
	return XDP_PASS;
}