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
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
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
#define INADDR_ANY ((in_addr_t)0x00000000)
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

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

#endif
