/* SPDX-License-Identifier: BSD-3-Clause */
/* IPv6 driver-facing declarations are provided by the shared stack. */

#ifndef _NETINET6_IP6_VAR_H_
#define _NETINET6_IP6_VAR_H_

struct mbuf;

int ip6_nexthdr(const struct mbuf *, int, int, int *);
int ip6_lasthdr(const struct mbuf *, int, int, int *);

#endif
