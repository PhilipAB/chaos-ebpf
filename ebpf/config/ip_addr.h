//go:build ignore
#ifndef IP_ADDR_H
#define IP_ADDR_H

#include "../linux/vmlinux.h"

/**
 * in6_addr definition from vmlinux.h 
*/
// struct in6_addr {
// 	union {
// 		__u8 u6_addr8[16];
// 		__be16 u6_addr16[8];
// 		__be32 u6_addr32[4];
// 	} in6_u;
// };

/**
 * Union type to differentiate between ipv4 and ipv6 addresses
*/
union ip_address {
    __u32 ipv4;  // IPv4
    struct in6_addr ipv6;  // IPv6
};

#endif /* IP_ADDR_H */