//go:build ignore

#ifndef BITFLIP_GEN_H
#define BITFLIP_GEN_H

#include "../linux/linux_helpers.h"
#include "bpf/bpf_helpers.h"

/**
 * @state: a state reference
 * @returns 1 if the state timestamp is 0 ... an initialized state should never have a timestamp of 0
*/
static __always_inline void process_bitflip(void *data, struct __sk_buff *skb, void *data_end, __u8 *payload, __u32 payload_offset, __u32 payload_size, __u8 *recalc) {
    // Ensure the payload is within the packet boundaries
    if ((void *)(payload + payload_size) > data_end)
    {
        return;
    }

    // perform bit flip for random byte of payload
    if (payload_size > 0)
    {
        // generate random number inclusive between 0 and 7 for bit shift operation on mask
        __u8 bit_shift_val = bpf_get_prandom_u32() % 8;

        // mask to flip byte at random position
        __u8 mask = 1 << bit_shift_val;

        // the index where we flip the bit
        __u32 flip_index = bpf_get_prandom_u32() % payload_size;
        // random flipped bit at random byte in payload
        if((void *)(payload + flip_index) > data_end) {
            return;
        }
        __u8 *target_byte = payload + flip_index;
        __u8 flipped_byte = *target_byte ^ mask;

        int ret = bpf_skb_load_bytes(skb, payload_offset, &target_byte, 1);
        if (ret < 0) {
            return;
        }

        // if ((void *)(data + payload_offset + sizeof(flipped_byte)) > data_end) {
        //     return;
        // }

        if(!(recalc && *recalc)) {
            // do not recalculate checksum but store the modified packet
            bpf_skb_store_bytes(skb, payload_offset, &flipped_byte, 1, 0);
        } else {
            // recalculate checksum and store the modified packet
            // bpf_skb_store_bytes(skb, payload_offset, &flipped_byte, sizeof(flipped_byte), BPF_F_RECOMPUTE_CSUM);
            return;
        }
    }
}

#endif /* BITFLIP_GEN_H */