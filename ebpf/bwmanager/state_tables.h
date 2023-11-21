//go:build ignore
/**
 * State tables ... always needs to be imported with struct definitions in bw.h
*/
#ifndef STATE_TABLES_H
#define STATE_TABLES_H

#include "../linux/vmlinux.h"

/* State table for rate limiting */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct StateTableKey);
	__type(value, struct StateTableLeaf);
	__uint(pinning, LIBBPF_PIN_BY_NAME); // pin to default location /sys/fs/bpf
} state_table SEC(".maps");

/* XFSM table for rate limiting */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct XFSMTableKey);
	__type(value, struct XFSMTableLeaf);
	__uint(pinning, LIBBPF_PIN_BY_NAME); // pin to default location /sys/fs/bpf
} xfsm_table SEC(".maps");

#endif /* STATE_TABLES_H */