//go:build ignore
/**
 * Reference for ebpf map definitions: https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/test_pinning.c
 * 
 * This file defines the ebpf maps which configure the parameters a chaos engineering function needs to be restricted to
*/

#ifndef CONFIG_BPF_MAPS_H
#define CONFIG_BPF_MAPS_H

#include "../linux/vmlinux.h"
#include "bpf/bpf_helpers.h"

#define MAX_MAP_ENTRIES 10 // Max number of map entries for IP ranges and affected ports

/**
 * enable_ipv4 boolean to enable/disable the traffic shaper for IPv4 traffic --- default is true
 * enable_ipv6 boolean to enable/disable the traffic shaper for IPv6 traffic --- default is false
 * ipv4_mask mask for the IPv4 range comparision --- default is 0xFFFF0000
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} enable_ipv4 SEC(".maps"), enable_ipv6 SEC(".maps"), ipv4_mask SEC(".maps");

/**
 * ipv4_range_exempt_list Blacklisting IP ranges, that should not be affected by the packet filtering --- default is 0x0A2A0000
 * port_map Whitelisting ports, which should be affected by packet filtering. If empty, all ports are affected --- default is empty
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);
	__type(value, __u32);
} ipv4_range_exempt_list SEC(".maps"), port_map SEC(".maps");

/**
 * A map with 3 boolean entries to define whether traffic filtering for the respective protocol is enabled
 * key = 1 -> index for ICMP
 * key = 6 -> index for TCP
 * key = 17 -> index for UDP
*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u32);
} supported_protocols SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);
	__type(value, struct in6_addr);
} ipv6_range_exempt_list SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct in6_addr);
} ipv6_mask SEC(".maps");

#endif /* CONFIG_BPF_MAPS_H */