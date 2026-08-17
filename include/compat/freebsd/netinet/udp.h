/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NETINET_UDP_H_
#define _NETINET_UDP_H_

#include <stdint.h>

struct udphdr {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
};

#endif
