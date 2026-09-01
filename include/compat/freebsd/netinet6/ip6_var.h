/* SPDX-License-Identifier: BSD-3-Clause */
/* IPv6 driver-facing declarations are provided by the shared stack. */

#ifndef _NETINET6_IP6_VAR_H_
#define _NETINET6_IP6_VAR_H_

struct mbuf;
struct ifnet;
struct sockaddr;
struct llentry;

#define V_ip6_v6only 1

int ip6_nexthdr(const struct mbuf *, int, int, int *);
int ip6_lasthdr(const struct mbuf *, int, int, int *);
int nd6_resolve(struct ifnet *ifp, int gateway_flags, struct mbuf *mbuf,
    const struct sockaddr *destination, unsigned char *link_address,
    uint32_t *flags, struct llentry **entry);

#endif
