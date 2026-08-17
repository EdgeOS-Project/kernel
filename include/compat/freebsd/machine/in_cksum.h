/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _MACHINE_IN_CKSUM_H_
#define _MACHINE_IN_CKSUM_H_

#include <stdint.h>

struct ip6_hdr;

static inline uint16_t
in_addword(uint16_t sum, uint16_t word)
{
    uint32_t total = (uint32_t)sum + word;

    total = (total & UINT32_C(0xffff)) + (total >> 16);
    return (uint16_t)total;
}

static inline uint16_t
in_pseudo(uint32_t first, uint32_t second, uint32_t third)
{
    uint64_t total = (uint64_t)first + second + third;

    total = (total & UINT64_C(0xffffffff)) + (total >> 32);
    total = (total & UINT64_C(0xffff)) + (total >> 16);
    if (total > UINT16_MAX)
        total -= UINT16_MAX;
    return (uint16_t)total;
}

int in6_cksum_pseudo(struct ip6_hdr *header, uint32_t length,
    uint8_t protocol, uint16_t checksum);

#endif
