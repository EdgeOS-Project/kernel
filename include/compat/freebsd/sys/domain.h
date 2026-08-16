/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD domain registration mapped onto the shared EdgeOS runtime. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_DOMAIN_H
#define EDGEOS_COMPAT_FREEBSD_SYS_DOMAIN_H

#include <sys/queue.h>
#include <sys/types.h>

struct ifnet;
struct mbuf;
struct protosw;
struct rib_head;
struct socket;

struct domain {
    SLIST_ENTRY(domain) dom_next;
    int dom_family;
    u_int dom_nprotosw;
    char *dom_name;
    int dom_flags;
    int (*dom_probe)(void);
    struct rib_head *(*dom_rtattach)(uint32_t);
    void (*dom_rtdetach)(struct rib_head *);
    struct protosw *dom_protosw[];
};

#define DOMF_UNLOADABLE 0x0004

extern int domain_init_status;
extern SLIST_HEAD(domainhead, domain) domains;

void domain_add(struct domain *domain);
void domain_remove(struct domain *domain);

#define DOMAIN_SET(name)                                                \
    SYSINIT(domain_add_##name, SI_SUB_PROTO_DOMAIN, SI_ORDER_FIRST,     \
        domain_add, &(name##domain));                                   \
    SYSUNINIT(domain_remove_##name, SI_SUB_PROTO_DOMAIN, SI_ORDER_FIRST,\
        domain_remove, &(name##domain))

#endif
