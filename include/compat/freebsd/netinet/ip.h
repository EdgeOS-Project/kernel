/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef EDGEOS_COMPAT_FREEBSD_NETINET_IP_H
#define EDGEOS_COMPAT_FREEBSD_NETINET_IP_H
#ifndef _NETINET_IP_H_
#define _NETINET_IP_H_
#endif

#include <stdint.h>
#include <netinet/in.h>

#define IPVERSION 4
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

struct ip {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t ip_hl : 4;
    uint8_t ip_v : 4;
#else
    uint8_t ip_v : 4;
    uint8_t ip_hl : 4;
#endif
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

#endif
