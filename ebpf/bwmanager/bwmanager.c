//go:build ignore

#include "bw.h"
#include "state_tables.h"
#include "../config/config.h"
#include "bpf/bpf_helpers.h"

/* Need to be GPL so that we can use the map helpers. */
char __license[] SEC("license") = "GPL";

/**
 * Reference for ebpf map definitions: https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/test_pinning.c
*/

/* Rate limit / burst capacity in bytes per second */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} bytes_per_second SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} next_progr_fd SEC(".maps");

/**************************************************************************************************************
 * TC programs
 *
 * This section contains eBPF programs attached to the traffic control layer (tc).
 **************************************************************************************************************/

/**
 * program is heavily(!!!) inspired by: https://github.com/qmonnet/tbpoc-bpf/blob/master/tokenbucket.c
 * it is modified in a way that it works with libbpf and that the bandwidth can be restricted to 
 * certain protocols, ports, ips etc.
*/
SEC("tc")
int tc_limit_bandwidth(struct __sk_buff *skb) {
	void *data   = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	// Retrieving the size of the incoming packet in bytes...
	int packet_size = skb->len;

	__u8 proto;
	__u16 ip_proto;
	union ip_address src_addr = {0};
	__u32 key = 0;
	int ip_hdr_length = 0;

	if (!parse_packet(data, data_end, &proto, &ip_proto, &src_addr, &ip_hdr_length)) {
		goto done;
	}

	if(!ip_proto) {
		goto done;
	}

	// skip if packets are neither ICMP, TCP nor UDP
	if (!process_protocols(proto)) {
		goto done;
	}

	__u32 current_state;

	/* Initialize most fields to 0 in case we do not parse associated headers.
	* The alternative is to set it to 0 once we know we will not meet the header
	* (e.g. when we see ARP, we won't have dst IP / port...). It would prevent
	* to affect a value twice in some cases, but it is prone to error when
	* adding parsing for other protocols.
	*/
	struct StateTableKey state_idx = {0};
	state_idx.ether_type = ip_proto;
	state_idx.ip_src = src_addr;
	struct StateTableLeaf *state_val;

	// To properly initialize padding, we need to "zero out" the struct during initialization
	// This ensures, that it has the correct struct length
	struct XFSMTableKey xfsm_idx = {0};
	// xfsm_idx.state // Will be set anyway before XFSM lookup
	struct XFSMTableLeaf *xfsm_val;

	// struct ethhdr *eth = data;
	// struct iphdr *iph;

	__u64 tnow = bpf_ktime_get_ns();
	// __u64 tmin, tmax;
	__u64 bucket_size, time_stamp;

	/* Rate limit lookup */
	__u64 *rate_limit = bpf_map_lookup_elem(&bytes_per_second, &key);
	if (!(rate_limit && *rate_limit)) {
		goto done;
	}
	/* State table lookup */
	state_val = bpf_map_lookup_elem(&state_table, &state_idx);
	/* current time in ns */


	if (state_val && !state_empty(state_val)) {
		current_state = state_val->state;
		bucket_size = state_val->r1;
		time_stamp = state_val->r2;
	} else {
		current_state = ZERO;
		bucket_size = *rate_limit;
		time_stamp = tnow;
	}

	/* Calculate new bucket size */

	__u64 diff_ns = tnow - time_stamp;
	__u64 new_bucket_size = bucket_size + ((*rate_limit * diff_ns) / SCALE_FACTOR);
	if (new_bucket_size > *rate_limit) {
		new_bucket_size = *rate_limit;
	}

	/* Evaluate conditions */

	__u8 cond1 = check_condition(GE, new_bucket_size, packet_size);
	if (cond1 == ERROR) {
		goto error;
	}

	/* XFSM table lookup */

	xfsm_idx.state = current_state;
	xfsm_idx.ether_type = ETH_P_IP;
	xfsm_idx.cond1 = cond1;
	xfsm_val = bpf_map_lookup_elem(&xfsm_table, &xfsm_idx);
	if (!xfsm_val) {
		goto error;
	}

	/* Apply update functions */

	struct StateTableLeaf updated_state = {0};
	updated_state.state = xfsm_val->next_state;
	updated_state.r1 = new_bucket_size;
	updated_state.r2 = tnow;

	/* Run update function we obtained from the XFSM table. */
	switch (xfsm_val->update_function) {
		/* State is ZERO and packet too big */
		case UPDATE_CASE_1: // 0
			updated_state.r1 = *rate_limit;
			updated_state.r2 = tnow;
			break;
		/* State is ZERO and there are enough tokens available to process token */
		case UPDATE_CASE_2: // 1
			updated_state.r1 = *rate_limit - packet_size;
			updated_state.r2 = tnow;
			break;
		/* State is ONE and packet too big -> we need to recalculate new bucket size */
		case UPDATE_CASE_3: // 2
			updated_state.r1 = new_bucket_size;
			updated_state.r2 = tnow;
			break;
		/* State is ONE and there are enough tokens available to process token */
		case UPDATE_CASE_4: // 3
			updated_state.r1 = new_bucket_size - packet_size;
			updated_state.r2 = tnow;
			break;
		default:
			goto error;
	}

	/* Update state table. We re-use the StateTableKey we had initialized
	* already. We update this rule with the new state provided by XFSM
	* table, and with the registers updated as stated by the XFSM table as well.
	*/
	bpf_map_update_elem(&state_table, &state_idx, &updated_state, BPF_ANY);

	/* Process packet */

	/* At last, execute the action for the current state, that we obtained
	* from the XFSM table.
	* Users should add new actions here.
	*/
	switch (xfsm_val->packet_action) {
		case ACTION_DROP:
			return TC_ACT_SHOT;
		case ACTION_FORWARD:
			goto done;
		default:
			goto error;
	}

done:
	// if fd does not exist for next program, this silently fails
	// Reference: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
	bpf_tail_call(skb, &next_progr_fd, key);
	return TC_ACT_OK;

error:
	/* For cases that should not be reached. */
	return TC_ACT_UNSPEC;
}