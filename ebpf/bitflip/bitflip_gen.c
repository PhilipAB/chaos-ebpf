//go:build ignore

#include "../config/config.h"
#include "bpf/bpf_helpers.h"
#include "bitflip_gen.h"

// Reference: https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmp.h
#define ICMP_ECHOREPLY  0       /* Echo Reply			*/
#define ICMP_ECHO       8       /* Echo Request			*/

// Reference: https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmpv6.h
#define ICMPV6_ECHO_REQUEST     128
#define ICMPV6_ECHO_REPLY       129

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} bitflip_probability SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} recalculate_checksum SEC(".maps");

SEC("tc")
int bitflip(struct __sk_buff *skb) {
    __u32 key = 0;
    __u32 *bitflip_prob = bpf_map_lookup_elem(&bitflip_probability, &key);
    if(!bitflip_prob || *bitflip_prob > 100) {
        // the bitflip probability is invalid -> skip processing
        goto done;
    }
    // determine if we should flip a byte or not
    if (!(bpf_get_prandom_u32() % 100 < *bitflip_prob)) {
        goto done;
    }
    void *data   = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u8 proto;
    __u16 ip_proto;
    union ip_address src_addr = {0};
    int ip_hdr_length = 0;

    if (!parse_packet(data, data_end, &proto, &ip_proto, &src_addr, &ip_hdr_length)) {
        goto done;
    }

    if(!ip_hdr_length) {
        goto done;
    }

    // skip if packets are neither ICMP, TCP nor UDP
    if (!process_protocols(proto)) {
        goto done;
    }

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return 0;
    }

    // specify if we should recalculate the checksum
    __u8 *recalc = bpf_map_lookup_elem(&recalculate_checksum, &key);

    // To calculate the payload, the following program was used as reference...
    // to understand the header length calculation for ipv4 and tcp ... instead of bitshifts we simply multiply * 4
    // Reference: https://github.com/netgroup-polito/ebpf-test/blob/master/http-parse-complete.c
    if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmph = data + sizeof(*eth) + ip_hdr_length;
        if (data + sizeof(*eth) + ip_hdr_length + sizeof(*icmph) > data_end) {
            // Could not parse ICMP header
            return TC_ACT_OK;
        }

        // Let's restrict this to echo requests/replies to ensure a fixed size header
        // Since we mainly use icmp for testing with the ping command, this should be fine
        if (icmph->type != ICMP_ECHO && icmph->type != ICMP_ECHOREPLY) {
            // skip processing if type is different than ICMP_ECHO/ICMP_ECHOREPLY
            return TC_ACT_OK;
        }

        __u32 icmp_hdr_len = sizeof(*icmph);
        __u8 *payload = (__u8 *)icmph + icmp_hdr_len; // pointer to first payload byte
        __u32 payload_offset = sizeof(*eth) + ip_hdr_length + icmp_hdr_len;
        if(skb->len <= payload_offset) {
            // no payload?
            return TC_ACT_OK;
        }
        __u32 payload_size = skb->len - payload_offset;
        // if (data + sizeof(*eth) + ip_hdr_length + sizeof(*icmph) + sizeof(*payload) > data_end) {
        //     // Could not parse payload (maybe it is empty?)
        //     return TC_ACT_OK;
        // }

        process_bitflip(data, skb, data_end, payload, payload_offset, payload_size, recalc);
    } else if (proto == IPPROTO_ICMPV6) {
        struct icmp6hdr *icmp6h = data + sizeof(*eth) + ip_hdr_length;
        if (data + sizeof(*eth) + ip_hdr_length + sizeof(*icmp6h) > data_end) {
            // Could not parse ICMP header
            return TC_ACT_OK;
        }

        // Let's restrict this to echo requests/replies to ensure a fixed size header
        // Since we mainly use icmp for testing with the ping command, this should be fine
        if (icmp6h->icmp6_type != ICMPV6_ECHO_REQUEST && icmp6h->icmp6_type != ICMPV6_ECHO_REPLY) {
            // skip processing if type is different than ICMP_ECHO/ICMP_ECHOREPLY
            return TC_ACT_OK;
        }

        __u32 icmp_hdr_len = sizeof(*icmp6h);
        __u8 *payload = (__u8 *)icmp6h + icmp_hdr_len; // pointer to first payload byte
        __u32 payload_offset = sizeof(*eth) + ip_hdr_length + icmp_hdr_len;
        if(skb->len <= payload_offset) {
            // no payload?
            return TC_ACT_OK;
        }
        __u32 payload_size = skb->len - payload_offset;
        // if (data + sizeof(*eth) + ip_hdr_length + sizeof(*icmp6h) + sizeof(*payload) > data_end) {
        //     // Could not parse payload (maybe it is empty?)
        //     return TC_ACT_OK;
        // }

        process_bitflip(data, skb, data_end, payload, payload_offset, payload_size, recalc);
    } else if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = data + sizeof(*eth) + ip_hdr_length;
        if (data + sizeof(*eth) + ip_hdr_length + sizeof(*tcph) > data_end) {
            // Could not parse TCP header
            return TC_ACT_OK;
        }

        __u16 tcp_hdr_len = tcph->doff * 4;
        __u8 *payload = (__u8 *)tcph + tcp_hdr_len; // pointer to first payload byte
        __u32 payload_offset = sizeof(*eth) + ip_hdr_length + tcp_hdr_len;
        if(skb->len <= payload_offset) {
            // no payload?
            return TC_ACT_OK;
        }
        __u32 payload_size = skb->len - payload_offset;
        // if (data + sizeof(*eth) + ip_hdr_length + sizeof(*tcph) + sizeof(*payload) > data_end) {
        //     // Could not parse payload (maybe it is empty?)
        //     return TC_ACT_OK;
        // }

        process_bitflip(data, skb, data_end, payload, payload_offset, payload_size, recalc);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = data + sizeof(*eth) + ip_hdr_length;
        if (data + sizeof(*eth) + ip_hdr_length + sizeof(*udph) > data_end) {
            // Could not parse UDP header
            return TC_ACT_OK;
        }

        __u32 udp_hdr_len = sizeof(*udph);
        __u8 *payload = (__u8 *)udph + udp_hdr_len; // pointer to first payload byte
        __u32 payload_offset = sizeof(*eth) + ip_hdr_length + udp_hdr_len;
        if(skb->len <= payload_offset) {
            // no payload?
            return TC_ACT_OK;
        }
        __u32 payload_size = skb->len - payload_offset;
        // if (data + sizeof(*eth) + ip_hdr_length + sizeof(*udph) + sizeof(*payload) > data_end) {
        //     // Could not parse payload (maybe it is empty?)
        //     return TC_ACT_OK;
        // }

        process_bitflip(data, skb, data_end, payload, payload_offset, payload_size, recalc);
    }
done:
    return TC_ACT_OK;
}