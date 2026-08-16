/* SPDX-License-Identifier: BSD-3-Clause */
/* Ethernet protocol hooks shared with the EdgeOS network stack. */

#ifndef _NETINET_IF_ETHER_H_
#define _NETINET_IF_ETHER_H_

#include <net/ethernet.h>
#include <sys/socket.h>

void arp_ifinit(if_t interface, struct ifaddr *address);

#endif
