/* SPDX-License-Identifier: BSD-3-Clause */
/* Ethernet protocol hooks shared with the EdgeOS network stack. */

#ifndef _NETINET_IF_ETHER_H_
#define _NETINET_IF_ETHER_H_

#include <net/ethernet.h>
#include <sys/socket.h>

struct llentry;
struct mbuf;

int arpresolve(struct ifnet *ifp, int is_gateway, struct mbuf *mbuf,
    const struct sockaddr *destination, unsigned char *link_address,
    uint32_t *flags, struct llentry **entry);
void arp_ifinit(if_t interface, struct ifaddr *address);

#endif
