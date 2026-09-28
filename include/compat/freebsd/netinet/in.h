/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NETINET_IN_H_
#define _NETINET_IN_H_

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>

typedef uint32_t in_addr_t;

struct in_addr {
    in_addr_t s_addr;
};

struct sockaddr_in {
    uint8_t sin_len;
    sa_family_t sin_family;
    uint16_t sin_port;
    struct in_addr sin_addr;
    uint8_t sin_zero[8];
};

struct in6_addr {
    union {
        uint8_t __u6_addr8[16];
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
    } __u6_addr;
};

struct sockaddr_in6 {
    uint8_t sin6_len;
    sa_family_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};

#define s6_addr __u6_addr.__u6_addr8
#define s6_addr8 __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32

/* EdgeOS currently supports little-endian x86_64 and AArch64 targets. */
#define IPV6_ADDR_INT32_ONE 0x01000000U
#define IPV6_ADDR_INT16_MLL 0x02ffU

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_IPV6 41
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ESP 50
#define IPPROTO_AH 51
#define IPPROTO_ICMPV6 58
#define IPPROTO_NONE 59
#define IPPROTO_DSTOPTS 60
#define IPPROTO_IPCOMP 108
#define IPPROTO_SCTP 132
#define IPPROTO_DONE 257
#define IP_MAXPACKET 65535
#define IPPORT_EPHEMERALFIRST 10000
#define IPPORT_EPHEMERALLAST 65535
#define INADDR_ANY ((in_addr_t)0x00000000)
#define INADDR_LOOPBACK ((in_addr_t)0x7f000001)
#define INADDR_BROADCAST ((in_addr_t)0xffffffff)
#define IPPORT_RESERVED 1024
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#define IN_MULTICAST(address) \
    ((((uint32_t)(address)) & 0xf0000000U) == 0xe0000000U)
#define IN_ZERONET(address) ((((uint32_t)(address)) & 0xff000000U) == 0)
#define IN_LOOPBACK(address) ((((uint32_t)(address)) & 0xff000000U) == 0x7f000000U)
#define IN6_IS_ADDR_UNSPECIFIED(address) \
    (((address)->s6_addr32[0] | (address)->s6_addr32[1] | \
    (address)->s6_addr32[2] | (address)->s6_addr32[3]) == 0)
#define IN6_IS_ADDR_MULTICAST(address) ((address)->s6_addr[0] == 0xff)
#define IN6_IS_ADDR_LOOPBACK(address) \
    ((address)->s6_addr32[0] == 0 && (address)->s6_addr32[1] == 0 && \
    (address)->s6_addr32[2] == 0 && (address)->s6_addr32[3] == IPV6_ADDR_INT32_ONE)
#define IN6_IS_SCOPE_LINKLOCAL(address) \
    ((address)->s6_addr[0] == 0xfe && (((address)->s6_addr[1] & 0xc0) == 0x80))
#define IN6_IS_ADDR_MC_INTFACELOCAL(address) \
    (IN6_IS_ADDR_MULTICAST(address) && (((address)->s6_addr[1] & 0x0f) == 0x01))

#define satosin(address) ((struct sockaddr_in *)(address))
#define sintosa(address) ((struct sockaddr *)(address))
#define satosin6(address) ((struct sockaddr_in6 *)(address))
#define sin6tosa(address) ((struct sockaddr *)(address))

#ifndef htons
#define htons(value) __builtin_bswap16((uint16_t)(value))
#endif
#ifndef ntohs
#define ntohs(value) __builtin_bswap16((uint16_t)(value))
#endif
#ifndef htonl
#define htonl(value) __builtin_bswap32((uint32_t)(value))
#endif
#ifndef ntohl
#define ntohl(value) __builtin_bswap32((uint32_t)(value))
#endif

char *inet_ntop(int family, const void *address, char *buffer,
    size_t buffer_length);
char *ip6_sprintf(char *buffer, const struct in6_addr *address);

#endif
