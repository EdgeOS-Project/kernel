/* SPDX-License-Identifier: BSD-2-Clause */
/* Single-domain allocation policy used by the EdgeOS driver bridge. */

#ifndef _SYS_DOMAINSET_H_
#define _SYS_DOMAINSET_H_

struct domainset {
    int preferred_domain;
};

typedef struct domainset_mask {
    unsigned long bits[1];
} domainset_t;

#define DOMAINSET_EMPTY(mask) ((mask)->bits[0] == 0)
#define DOMAINSET_ISSET(domain, mask) \
    ((unsigned int)(domain) < sizeof(unsigned long) * 8u && \
    (((mask)->bits[0] >> (unsigned int)(domain)) & 1ul) != 0)
#define DOMAINSET_SUBSET(left, right) \
    (((left)->bits[0] & ~(right)->bits[0]) == 0)

extern struct domainset domainset_prefer[1];
extern struct domainset domainset_round_robin[1];

#define DOMAINSET_PREF(domain) (&domainset_prefer[0])
#define DOMAINSET_RR() (&domainset_round_robin[0])

#endif
