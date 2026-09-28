/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NET_IF_ARP_H_
#define _NET_IF_ARP_H_

#include "if_var.h"

#define ARPHRD_ETHER 1
#define ARPHRD_INFINIBAND 32

#define ARPOP_REPLY 2

struct arphdr {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
};

#endif
