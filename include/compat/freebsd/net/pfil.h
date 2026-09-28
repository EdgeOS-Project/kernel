/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NET_PFIL_H_
#define _NET_PFIL_H_

#include <stdint.h>

struct ifnet;
struct mbuf;
struct inpcb;

typedef struct pfil_head *pfil_head_t;

typedef enum {
    PFIL_PASS = 0,
    PFIL_DROPPED,
    PFIL_CONSUMED,
    PFIL_REALLOCED,
} pfil_return_t;

enum pfil_types {
    PFIL_TYPE_AF = 1,
    PFIL_TYPE_ETHERNET = 2,
};

struct pfil_head_args {
    int pa_version;
    int pa_flags;
    enum pfil_types pa_type;
    const char *pa_headname;
};

struct pfil_head {
    int head_nhooksin;
    int head_nhooksout;
};

#define PFIL_VERSION 2
#define PFIL_FLAG_AF 0x0001
#define PFIL_IN 0x00010000
#define PFIL_HOOKED_IN(head) ((head) && (head)->head_nhooksin > 0)

pfil_head_t pfil_head_register(struct pfil_head_args *arguments);
void pfil_head_unregister(pfil_head_t head);
pfil_return_t pfil_mbuf_in(pfil_head_t head, struct mbuf **mbuf,
    struct ifnet *ifp, struct inpcb *pcb);
pfil_return_t pfil_mem_in(pfil_head_t head, void *data, unsigned int length,
    struct ifnet *ifp, struct mbuf **mbuf);

#endif
