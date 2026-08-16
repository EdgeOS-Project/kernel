/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * IPv6 pseudo-header checksum support derived from FreeBSD
 * sys/netinet6/in6_cksum.c.
 */

#include <stdint.h>

#include "compat/freebsd/netinet/in.h"
#include "compat/freebsd/netinet/ip6.h"
#include "compat/freebsd/machine/in_cksum.h"

static uint32_t
in6_checksum_add_word(uint32_t sum, uint16_t word)
{
    return sum + word;
}

static uint16_t
in6_checksum_load_word(const uint8_t *bytes)
{
    uint16_t word;

    __builtin_memcpy(&word, bytes, sizeof(word));
    return word;
}

int
in6_cksum_pseudo(struct ip6_hdr *header, uint32_t length,
    uint8_t protocol, uint16_t checksum)
{
    uint32_t sum = checksum;
    uint32_t network_length;
    const uint8_t *source;
    const uint8_t *destination;

    if (!header)
        return 0;
    network_length = __builtin_bswap32(length);
    source = header->ip6_src.s6_addr;
    destination = header->ip6_dst.s6_addr;

    sum = in6_checksum_add_word(sum,
        in6_checksum_load_word((const uint8_t *)&network_length));
    sum = in6_checksum_add_word(sum,
        in6_checksum_load_word((const uint8_t *)&network_length + 2));
    sum = in6_checksum_add_word(sum, (uint16_t)protocol << 8);

    for (unsigned int offset = 0; offset < 16; offset += 2) {
        sum = in6_checksum_add_word(sum,
            in6_checksum_load_word(source + offset));
        sum = in6_checksum_add_word(sum,
            in6_checksum_load_word(destination + offset));
    }
    sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    if (sum > UINT16_MAX)
        sum -= UINT16_MAX;
    return (int)sum;
}
