/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NETINET_TCP_H_
#define _NETINET_TCP_H_

#include <stdint.h>

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_AE 0x100
#define TH_FLAGS \
    (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG | TH_ECE | \
     TH_CWR | TH_AE)

struct tcphdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t th_x2 : 4;
    uint8_t th_off : 4;
#else
    uint8_t th_off : 4;
    uint8_t th_x2 : 4;
#endif
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

static inline uint16_t
tcp_get_flags(const struct tcphdr *header)
{
    return header ?
        ((uint16_t)header->th_x2 << 8) | header->th_flags : 0;
}

static inline void
tcp_set_flags(struct tcphdr *header, uint16_t flags)
{
    if (!header)
        return;
    header->th_x2 = (uint8_t)((flags >> 8) & 0x0f);
    header->th_flags = (uint8_t)(flags & 0xff);
}

#endif
