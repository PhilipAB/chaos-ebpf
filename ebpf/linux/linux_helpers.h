//go:build ignore
/**
 * This file defines the necessary structs and macros to avoid direct dependencies from the linux kernel
 * These are the headers that we would need without this helper file an vmlinux.h:
 * #include <linux/bpf.h> // inludes <linux/types.h> and bpf related definitions
 * #include <linux/if_ether.h> // Contains ETH_P_IP and ETH_P_IPV6 macro to differentiate between IPv4 and IPv6
 * #include <linux/ip.h> // IPv4 support
 * #include <linux/ipv6.h> // IPv6 support ... includes in6.h and hence definition for struct in6_addr
 * #include <linux/tcp.h> // TCP support
 * #include <linux/udp.h> // UDP support
 * #include <linux/pkt_cls.h> // TC macros
*/
#ifndef LINUX_HELPER_H
#define LINUX_HELPER_H

#define IPV6_EXT_MAX_CHAIN 6 // Longest chain of IPv6 extension headers to resolve
/**
 * Reference for general IP Protocol headers: https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h
 * Already defined in vmlinux.h
*/
// #define IPPROTO_ICMP 	1 	/* Internet Control Message Protocol	*/
// #define IPPROTO_TCP 	6 	/* Transmission Control Protocol		*/
// #define IPPROTO_UDP 	17 	/* User Datagram Protocol				*/

// #define IPPROTO_AH 		51 	/* Authentication Header protocol		*/

/**
 * Reference for IPv6 Protocol (extension) headers: https://github.com/torvalds/linux/blob/master/include/uapi/linux/in6.h
*/
#define IPPROTO_HOPOPTS 	0	/* IPv6 hop-by-hop options 		*/
#define IPPROTO_ROUTING 	43	/* IPv6 routing header 			*/
#define IPPROTO_FRAGMENT 	44	/* IPv6 fragmentation header	*/

#define IPPROTO_ICMPV6 		58	/* IPv6 ICMPv6 					*/
#define IPPROTO_NONE 		59	/* IPv6 no next header 			*/

#define IPPROTO_DSTOPTS 	60	/* IPv6 destination options 	*/
#define IPPROTO_MH 			135	/* IPv6 mobility header 		*/


/**
 * Reference: https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h
*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

/**
 * Reference: https://github.com/torvalds/linux/blob/master/include/uapi/linux/pkt_cls.h
*/
#define TC_ACT_UNSPEC   (-1)
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2

#endif /* LINUX_HELPER_H */