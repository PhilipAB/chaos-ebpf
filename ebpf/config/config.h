//go:build ignore
/**
 * This file defines the ebpf maps which configure the parameters a chaos engineering function needs to be restricted to
*/

#ifndef CONFIG_H
#define CONFIG_H

#include "config_bpf_maps.h"
#include "ip_addr.h"
#include "../linux/linux_helpers.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"

#define CLONED_PKT 0x1234 // Let's classify cloned packets with the hex number 0x1234

/**************************************************************************************************************
 * IPv4 Address Handling
 *
 * This section contains function(s) and/or definition(s) for IPv4 address processing.
 * This particulary includes a method for evaluating,
 * if a packet is routed from or to an exempted IP from the traffic shaper.
 **************************************************************************************************************/

/**
 * @src: the source IPv4 ip address of a packet
 * @dst: the destination IPv4 ip address of a packet
 * @returns 1 if mask is invalid or packet is not on exempt list, else 0
*/
static __always_inline int process_exempt_ip_ranges(__u32 src_ip, __u32 dst_ip) {
	__u32 key = 0;
	__u32 *ip_range;
	__u32 *mask = bpf_map_lookup_elem(&ipv4_mask, &key);
	if (!mask) {
		// If there's no ip mask provided, we can not process the exempt list and hence, the exempt list has no effect.
		return 1;
	}
	for (int i = 0; i < MAX_MAP_ENTRIES; i++) {
		ip_range = bpf_map_lookup_elem(&ipv4_range_exempt_list, &key);
		if (!ip_range) {
			// We iterated through all valid entries -> stop the loop
			// Return 1 because the IP is not on our exempt list
			return 1;
		}
		if ((src_ip & *mask) == *ip_range || (dst_ip & *mask) == *ip_range) {
			// The packet is either routed from or to the pod IP range -> do not drop it!
			return 0;
		}
		key++;
	}
	// No exempted ip found -> further process packet
	return 1;
}

/**************************************************************************************************************
 * IPv6 Address Handling
 *
 * This section contains function(s) and/or definition(s) for IPv6 address processing.
 * This particulary includes a method for evaluating,
 * if a packet is routed from or to an exempted IP from the traffic shaper.
 **************************************************************************************************************/

/**
 * @current_hdr: the currently examined (extension) header
 * @data_end: pointer to end of packet data
 * @return 1 if accessed memory for the next header is valid and within the bounds of the packet, 0 otherwise
*/
static __always_inline int next_header_valid_header_range(struct ipv6_opt_hdr *current_hdr, void *data_end) {
	if ((void *)(current_hdr + 1) > data_end) {
		// An extension header needs a pointer to the next header for further processing ... it does not seem to exist
		return 0;
	}
	// valid memory range
	return 1;
}

/**
 * @ip6h: a pointer to an IPv6 header
 * @data_end: pointer to end of packet data
 * @return IPPROTO_NONE if no non-extension type header can be found, else the non-extension type header
 * Inspired by: https://github.com/xdp-project/xdp-tools/blob/master/headers/xdp/parsing_helpers.h
*/
static __always_inline __u8 skip_ip6hdrext(struct ipv6hdr *ip6h, void *data_end, int *hdr_length) {
	// Example ... an IPv6 header always looks like this:
	// | <-- 40 bytes IPv6 Base Header -->|<-- Optional Extension Headers -->| <--         Data         -->|
	// +----------------------------------+----------------------------------+-----------------------------+
	// |            Fixed Fields          |          Extension Headers       |  IPPROTO_ICMP/-TCP/UDP/...  |
	// +----------------------------------+----------------------------------+-----------------------------+
	// To start at extension headers...   ^
	// ... we need to jump here --------->ip6h + 1
	// ... potentially we already reached the ICMP-/TCP-/UDP-header if no extension headers are present
	void *tmp_hdr = (void *)(ip6h + 1);
	__u8 hdr_type = ip6h->nexthdr;

	// let's track the iph6 header length + extension header length (for port processing etc. later)
	*hdr_length = sizeof(struct ipv6hdr);

	for (int i = 0; i < IPV6_EXT_MAX_CHAIN; ++i) {
		struct ipv6_opt_hdr *hdr = tmp_hdr;
		switch (hdr_type) {
			case IPPROTO_HOPOPTS:
			case IPPROTO_DSTOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_MH:
				if (!next_header_valid_header_range(hdr, data_end)) {
					return IPPROTO_NONE;
				}
				*hdr_length += (hdr->hdrlen + 1) * 8;
				tmp_hdr = (char *)hdr + (hdr->hdrlen + 1) * 8;
				hdr_type = hdr->nexthdr;
				break;
			case IPPROTO_AH:
				if (!next_header_valid_header_range(hdr, data_end)) {
					return IPPROTO_NONE;
				}
				*hdr_length += (hdr->hdrlen + 2) * 4;
				tmp_hdr = (char *)hdr + (hdr->hdrlen + 2) * 4;
				hdr_type = hdr->nexthdr;
				break;
			case IPPROTO_FRAGMENT:
				if (!next_header_valid_header_range(hdr, data_end)) {
					return IPPROTO_NONE;
				}
				*hdr_length += 8;
				tmp_hdr = (char *)hdr + 8;
				hdr_type = hdr->nexthdr;
				break;
			default:
				// Found a header that is not an IPv6 extension header, return it
				return hdr_type;
		}

		if (tmp_hdr > data_end) {
			// The next header is beyond the end of the packet
			return IPPROTO_NONE;
		}
	}

	// Exceeded max number of extension headers without finding a non-extension header
	return IPPROTO_NONE;
}

/**
 * @ip: an IPv6 ip address (e. g. source or destination address of a packet)
 * @range: an IPv6 ip address space that the @ip value should be compared against, e. g. "2001:cafe:42:0::"
 * @mask: an IPv6 mask to compare x number of significant bits.
 * E. g. the mask "FFFF:FFFF:FFFF:0::" would mean the first 16 bits of an IPV6 address will be compared
 * @returns 1 if @ip is in address space of @range under consideration of ip mask @mask, else 0
*/
static __always_inline int ipv6_addr_equals(struct in6_addr *ip, struct in6_addr *range, struct in6_addr *mask) {
	for (int i = 0; i < 4; i++) {
		if ((ip->in6_u.u6_addr32[i] & mask->in6_u.u6_addr32[i]) != (range->in6_u.u6_addr32[i] & mask->in6_u.u6_addr32[i])) {
			return 0;
		}
	}
	return 1;
}

/**
 * @ip: an IPv6 ip address
 * @returns 1 if the ip address (::) only contains zeros, else 0
*/
static __always_inline int ipv6_addr_is_empty(const struct in6_addr *ip) {
	struct in6_addr empty_mask = {0};
	for (int i = 0; i < 4; i++) {
		if (ip->in6_u.u6_addr32[i] != empty_mask.in6_u.u6_addr32[i]) {
			return 0;
		}
	}
	return 1;
}

/**
 * @src: the source IPv6 ip address of a packet
 * @dst: the destination IPv6 ip address of a packet
 * @returns 1 if mask is invalid or packet is not on exempt list, else 0
*/
static __always_inline int process_exempt_ipv6_ranges(struct in6_addr *src, struct in6_addr *dst) {
	__u32 key = 0;
	struct in6_addr *ip_range;
	struct in6_addr *mask = bpf_map_lookup_elem(&ipv6_mask, &key);
	// We need to use the ipv6_addr_is_empty() function to check if an ip is empty...
	// ... because an IP with only zeros is an unspecified IP and therefore invalid
	if (!mask || ipv6_addr_is_empty(mask)) {
		// If there's no ip mask provided, we can not process the exempt list and hence, the exempt list has no effect.
		return 1;
	}
	for (int i = 0; i < MAX_MAP_ENTRIES; i++) {
		ip_range = bpf_map_lookup_elem(&ipv6_range_exempt_list, &key);
		if (!ip_range || ipv6_addr_is_empty(ip_range)) {
			// We iterated through all valid entries -> stop the loop
			// Return 1 because the IP is not on our exempt list
			return 1;
		}
		if (ipv6_addr_equals(src, ip_range, mask) || ipv6_addr_equals(dst, ip_range, mask)) {
			// The packet is either routed from or to the exempted IP range -> do not drop it!
			return 0;
		}
		key++;
	}
	// No exempted ip found -> further process packet
	return 1;
}

/**************************************************************************************************************
 * Port processing
 *
 * This section contains function(s) and/or definition(s) to process ports
 * and evaluate if a packet is routed from or to a whitelisted port.
 **************************************************************************************************************/

/**
 * @src_port: the source port of a packet
 * @dst_port: the destination port of a packet>
 * @return 1 if port is whitelisted (or no whitelist exists), else 0
*/
static __always_inline int lookup_ports(__u32 src_port, __u32 dst_port) {
	__u32 key = 0;
	__u32 *allowed_port;

	for (int i = 0; i < MAX_MAP_ENTRIES; i++) {
		allowed_port = bpf_map_lookup_elem(&port_map, &key);
		if (!(allowed_port && *allowed_port)) {
			// We iterated through all valid entries -> stop the loop
			// Return 0 because the port is not on our whitelist
			return 0;
		}
		if (*allowed_port == src_port || *allowed_port == dst_port) {
			// The packet is either sent from or to a whitelisted port -> further process it
			return 1;
		}
		key++;
	}
	// Return 0 because the port is not on our whitelist -> do not drop it!
	return 0;
}

/**
 * @data: pointer to start of packet data
 * @eth: ethernet header of packet
 * @ip_header_size: size of ip header -> important to verify parsing of upd/tcp headers
 * @data_end: pointer to end of packet data
 * @return 1 if port is on port map, port map does not exist or packet is not of type tcp/udp. Else 0.
*/
static __always_inline int process_ports(void *data, struct ethhdr *eth, int ip_header_size, __u8 ip_protocol, void *data_end) {
	// Important: If port_map is empty, all ports are affected!
	// Let's take a shortcut then, and directly return 1 for further processing.
	__u32 key = 0;
	__u32 *first_port_map_entry = bpf_map_lookup_elem(&port_map, &key);
	if (!(first_port_map_entry && *first_port_map_entry)) {
		return 1;
	} else if (ip_protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = data + sizeof(*eth) + ip_header_size;
		if (data + sizeof(*eth) + ip_header_size + sizeof(*tcph) > data_end) {
			// Could not parse TCP header
			return 0;
		}
		__u32 src_port = bpf_ntohs(tcph->source);
		__u32 dst_port = bpf_ntohs(tcph->dest);
		if (!lookup_ports(src_port, dst_port)) {
			return 0;
		}
	} else if (ip_protocol == IPPROTO_UDP) {
		struct udphdr *udph = data + sizeof(*eth) + ip_header_size;
		if (data + sizeof(*eth) + ip_header_size + sizeof(*udph) > data_end) {
			// Could not parse UDP header
			return 0;
		}
		__u32 src_port = bpf_ntohs(udph->source);
		__u32 dst_port = bpf_ntohs(udph->dest);
		if (!lookup_ports(src_port, dst_port)) {
			return 0;
		}
	}
	// Either the port is allowed or the packet's protocol we're processing is neither TCP nor UDP
	// Further process protocol ...
	return 1;
}

/**************************************************************************************************************
 * Protocol processing
 *
 * This section contains function(s) and/or definition(s) to process determine if packet processing
 * for certain protocols is actived and if the packet's protocol type is one of our supported types.
 * The supported types are: IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP and IPPROTO_UDP
 **************************************************************************************************************/

/**
 * @protocol: protocol type of packet
 * @returns 1 if protocol type is enabled and IPPROTO_ICMP / IPPROTO_ICMPV6 / IPPROTO_TCP / IPPROTO_UDP ... else 0
*/
static __always_inline int process_protocols(__u8 protocol) {
	// skip if packets are neither ICMP, TCP nor UDP
	if (protocol != IPPROTO_ICMP && protocol != IPPROTO_ICMPV6 && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
		return 0;
	}

	int icmp_key = IPPROTO_ICMP;
	int tcp_key = IPPROTO_TCP;
	int udp_key = IPPROTO_UDP;
	__u32 *icmp_filter = bpf_map_lookup_elem(&supported_protocols, &icmp_key);
	__u32 *tcp_filter = bpf_map_lookup_elem(&supported_protocols, &tcp_key);
	__u32 *udp_filter = bpf_map_lookup_elem(&supported_protocols, &udp_key);
	// skip if packet filter for protocol is not activated
	// Note: ICMP has a seperate protocol header for IPv6
	if(!(icmp_filter && *icmp_filter) && (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) ||
		!(tcp_filter && *tcp_filter) && protocol == IPPROTO_TCP ||
		!(udp_filter && *udp_filter) && protocol == IPPROTO_UDP) {
		return 0;
	}

	return 1;
}

/**************************************************************************************************************
 * Protocol processing
 *
 * This section contains the packet parsing logic in general.
 **************************************************************************************************************/

/**
 * @ctx: a pointer to a xdp struct containing information about the incoming packet
 * @proto: a pointer to the protocol that is being parsed
 * @returns 1 if the packet could be successfully parsed as ipv4 or ipv6 packet and is not exempt from packet filtering, else 0
*/
static __always_inline int parse_packet(void *data, void *data_end, __u8 *proto, __u16 *ip_protocol, union ip_address *src_addr, int *ip_hdr_len) {
	__u32 key = 0;

	struct ethhdr *eth = data;
	// Let's try parsing the packet with an ethernet header.
	if (data + sizeof(*eth) > data_end) {
		return 0;
	}
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
		__u32 *enabled = bpf_map_lookup_elem(&enable_ipv4, &key);
		if (!enabled || !*enabled) {
			// If IPv4 traffic is disabled for traffic shaping, we do not further process it
			return 0;
		}
		struct iphdr *iph = data + sizeof(*eth);
		if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
			return 0;
		}
		__u32 src_ip = bpf_ntohl(iph->saddr);
		__u32 dst_ip = bpf_ntohl(iph->daddr);

		if (!process_exempt_ip_ranges(src_ip, dst_ip)) {
			return 0;
		}

		*ip_hdr_len = iph->ihl * 4;
		if(!process_ports(data, eth, *ip_hdr_len, iph->protocol, data_end)) {
			return 0;
		}

		*ip_protocol = ETH_P_IP;
		src_addr->ipv4 = src_ip;
		*proto = iph->protocol;
		return 1;
	} else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
		__u32 *enabled = bpf_map_lookup_elem(&enable_ipv6, &key);
		if (!enabled || !*enabled) {
			// If IPv6 traffic is disabled for traffic shaping, we do not further process it
			return 0;
		}

		struct ipv6hdr *ip6h = data + sizeof(*eth);
		if (data + sizeof(*eth) + sizeof(*ip6h) > data_end) {
			// Unable to parse IPv6 header ...
			return 0;
		}

		if (!process_exempt_ipv6_ranges(&ip6h->saddr, &ip6h->daddr)) {
			return 0;
		}

		*ip_protocol = ETH_P_IPV6;
		src_addr->ipv6 = ip6h->saddr;
		*proto = skip_ip6hdrext(ip6h, data_end, ip_hdr_len);
		if(*proto == IPPROTO_NONE) {
			return 0;
		}

		if (!process_ports(data, eth, *ip_hdr_len, *proto, data_end)) {
			return 0;
		}

		return 1;
	}
	return 0;
}

#endif /* CONFIG_H */