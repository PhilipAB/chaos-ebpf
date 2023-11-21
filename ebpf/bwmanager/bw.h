//go:build ignore
/**
 *    GNU GENERAL PUBLIC LICENSE, Version 2
 *
 *    Copyright (C) 2017, 6WIND S.A.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License along
 *    with this program; if not, write to the Free Software Foundation, Inc.,
 *    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * This header file defines the tables and the structures for conditions for Open Packet Processor interface.
 * File is heavily(!!!) inspired by: https://github.com/qmonnet/tbpoc-bpf/blob/master/opp.h
 * On top of that, this file contains helper functions for the bandwidth manager.
 */

#ifndef BW_H
#define BW_H

#include "ip_addr.h"
#include "bpf/bpf_helpers.h"

/* Default available actions. Other user-defined action codes can be appended
 * here or defined in the main program, with higher values.
 */
#define ACTION_DROP 0
#define ACTION_FORWARD 1
#define SCALE_FACTOR 1000000000 // 1 second = 10^9 nanoseconds

// Note: It seems like, we need to do manual padding to align with the biggest data type...

/* Structures for index and value (a.k.a key and leaf) for state table. */
struct StateTableKey {
    __u16 ether_type;
    __u16 __padding16;
    union ip_address ip_src;
};

struct StateTableLeaf {
    __u32 state;
    __u32 __padding32;
    __u64 r1;
    __u64 r2;
};

/* Structures for index and value (a.k.a key and leaf) for XFSM stable. */
struct XFSMTableKey {
    __u8 cond1;
    __u8 __padding1; // 8bit / 1Byte padding
    __u16 __padding2; // 16bit / 2Byte padding
    __u16 ether_type;
    __u16 __padding3; // 16bit / 2Byte padding
    __u32 state;
};

struct XFSMTableLeaf {
    __u32 next_state;
    __u32 packet_action;
    __u32 update_function;
};

/* Encode conditions: condition evaluation result. */
enum evalcond {
    TRUE  = 1,
    FALSE = 2,
    ANY   = 3, /* Unused for now, we have no wildcard mechanism. */
    ERROR = 0,
};

/* Encode conditions: condition operator. */
enum opcond {
    EQ,
    NE,
    LT,
    LE,
    GT,
    GE,
};

enum updates {
    UPDATE_CASE_1, // 0
    UPDATE_CASE_2, // 1
    UPDATE_CASE_3, // 2
    UPDATE_CASE_4, // 3
};

enum states {
  ZERO,
  ONE,
};

static __always_inline int check_condition(__u64 op, __u64 a, __u64 b) {
    switch (op) {
        case EQ:
            if (a == b) return TRUE; else return FALSE;
        case NE:
            if (a != b) return TRUE; else return FALSE;
        case LT:
            if (a <  b) return TRUE; else return FALSE;
        case LE:
            if (a <= b) return TRUE; else return FALSE;
        case GT:
            if (a >  b) return TRUE; else return FALSE;
        case GE:
            if (a >= b) return TRUE; else return FALSE;
        default:
            return -1;
    }
}

/**
 * Calculate bucket_size
 * Only needed if, state table was already initialized
 * @time_now: current time stamp
 * @time_stamp: time stamp from state table
 * @bucket_size: current bucket_size
 * @rate_limit: current rate limit
 * @returns new bucket_size or rate_limit if calculated bucket_size exceeds rate_limit
*/
static __always_inline int calculate_bucket_size(__u64 time_now, __u64 time_stamp, __u64 bucket_size, __u64 rate_limit) {
	__u64 diff_ns = time_now - time_stamp;
	__u64 new_bucket_size = bucket_size + ((rate_limit * diff_ns) / SCALE_FACTOR);
	if (new_bucket_size > rate_limit) {
		return rate_limit;
	}
	return new_bucket_size;
}

/**
 * @state: a state reference
 * @returns 1 if the state timestamp is 0 ... an initialized state should never have a timestamp of 0
*/
static __always_inline int state_empty(const struct StateTableLeaf *state) {
    return state->r2 == 0;
}

#endif /* BW_H */