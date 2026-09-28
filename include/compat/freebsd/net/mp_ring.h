/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD multi-producer ring contract used by iflib. */

#ifndef __NET_MP_RING_H
#define __NET_MP_RING_H

#ifndef _KERNEL
#error "ifmp rings are a kernel interface"
#endif

#include <sys/counter.h>
#include <sys/param.h>

struct malloc_type;
struct ifmp_ring;

typedef unsigned int (*mp_ring_drain_t)(struct ifmp_ring *,
    unsigned int, unsigned int);
typedef unsigned int (*mp_ring_can_drain_t)(struct ifmp_ring *);
typedef void (*mp_ring_serial_t)(struct ifmp_ring *);

struct ifmp_ring {
    volatile uint64_t state __aligned(CACHE_LINE_SIZE);
    int size __aligned(CACHE_LINE_SIZE);
    void *cookie;
    struct malloc_type *mt;
    mp_ring_drain_t drain;
    mp_ring_can_drain_t can_drain;
    counter_u64_t enqueues;
    counter_u64_t drops;
    counter_u64_t starts;
    counter_u64_t stalls;
    counter_u64_t restarts;
    counter_u64_t abdications;
    void *volatile items[] __aligned(CACHE_LINE_SIZE);
};

int ifmp_ring_alloc(struct ifmp_ring **ring, int size, void *cookie,
    mp_ring_drain_t drain, mp_ring_can_drain_t can_drain,
    struct malloc_type *type, int flags);
void ifmp_ring_free(struct ifmp_ring *ring);
int ifmp_ring_enqueue(struct ifmp_ring *ring, void **items, int count,
    int budget, int abdicate);
void ifmp_ring_check_drainage(struct ifmp_ring *ring, int budget);
void ifmp_ring_reset_stats(struct ifmp_ring *ring);
int ifmp_ring_is_idle(struct ifmp_ring *ring);
int ifmp_ring_is_stalled(struct ifmp_ring *ring);

#endif
