/* SPDX-License-Identifier: MPL-2.0 */
/* Lock-free FreeBSD buffer-ring contract used by shared network drivers. */

#ifndef _SYS_BUF_RING_H_
#define _SYS_BUF_RING_H_

#include <stddef.h>
#include <stdint.h>

#include "../machine/cpu.h"
#include "../edgeos/systm.h"

#ifndef ENOBUFS
#define ENOBUFS 55
#endif

struct mtx;
struct malloc_type;

#ifdef INVARIANTS
#define BSD_BUF_RING_ASSERT(expression) do { \
    if (__builtin_expect(!(expression), 0)) \
        bsd_bridge_panic_stop(); \
} while (0)
#else
#define BSD_BUF_RING_ASSERT(expression) do { (void)0; } while (0)
#endif

struct buf_ring {
    uint32_t br_prod_head;
    uint32_t br_prod_tail;
    int br_prod_size;
    int br_prod_mask;
    uint64_t br_drops;
    uint32_t br_cons_head __attribute__((aligned(64)));
    uint32_t br_cons_tail;
    int br_cons_size;
    int br_cons_mask;
    void *br_ring[] __attribute__((aligned(64)));
};

static inline int
buf_ring_enqueue(struct buf_ring *ring, void *buffer)
{
    uint32_t producer_head;
    uint32_t producer_next;
    uint32_t consumer_tail;

    bsd_critical_enter();
    do {
        producer_head = __atomic_load_n(&ring->br_prod_head,
            __ATOMIC_ACQUIRE);
        producer_next = producer_head + 1u;
        consumer_tail = __atomic_load_n(&ring->br_cons_tail,
            __ATOMIC_ACQUIRE);
        if ((int32_t)(consumer_tail + (uint32_t)ring->br_prod_size -
            producer_next) < 1) {
            if (producer_head == __atomic_load_n(&ring->br_prod_head,
                __ATOMIC_RELAXED) &&
                consumer_tail == __atomic_load_n(&ring->br_cons_tail,
                __ATOMIC_RELAXED)) {
                ring->br_drops++;
                bsd_critical_exit();
                return ENOBUFS;
            }
            continue;
        }
    } while (!__atomic_compare_exchange_n(&ring->br_prod_head,
        &producer_head, producer_next, 0, __ATOMIC_RELAXED,
        __ATOMIC_RELAXED));

    ring->br_ring[producer_head & (uint32_t)ring->br_prod_mask] = buffer;
    while (__atomic_load_n(&ring->br_prod_tail,
        __ATOMIC_RELAXED) != producer_head)
        cpu_spinwait();
    __atomic_store_n(&ring->br_prod_tail, producer_next,
        __ATOMIC_RELEASE);
    bsd_critical_exit();
    return 0;
}

static inline void *
buf_ring_dequeue_sc(struct buf_ring *ring)
{
    uint32_t consumer_head;
    uint32_t producer_tail;
    void *buffer;

    consumer_head = __atomic_load_n(&ring->br_cons_head,
        __ATOMIC_RELAXED);
    producer_tail = __atomic_load_n(&ring->br_prod_tail,
        __ATOMIC_ACQUIRE);
    if (consumer_head == producer_tail)
        return NULL;
    buffer = ring->br_ring[
        consumer_head & (uint32_t)ring->br_cons_mask];
    __atomic_store_n(&ring->br_cons_head, consumer_head + 1u,
        __ATOMIC_RELAXED);
    __atomic_store_n(&ring->br_cons_tail, consumer_head + 1u,
        __ATOMIC_RELEASE);
    return buffer;
}

static inline void *
buf_ring_peek_clear_sc(struct buf_ring *ring)
{
    uint32_t consumer_head = __atomic_load_n(&ring->br_cons_head,
        __ATOMIC_RELAXED);

    if (consumer_head == __atomic_load_n(&ring->br_prod_tail,
        __ATOMIC_ACQUIRE))
        return NULL;
    return ring->br_ring[
        consumer_head & (uint32_t)ring->br_cons_mask];
}

static inline void
buf_ring_putback_sc(struct buf_ring *ring, void *buffer)
{
    uint32_t index = __atomic_load_n(&ring->br_cons_head,
        __ATOMIC_RELAXED) &
        (uint32_t)ring->br_cons_mask;

    BSD_BUF_RING_ASSERT(index != (__atomic_load_n(&ring->br_prod_tail,
        __ATOMIC_RELAXED) &
        (uint32_t)ring->br_prod_mask));
    ring->br_ring[index] = buffer;
}

static inline void
buf_ring_advance_sc(struct buf_ring *ring)
{
    uint32_t consumer_head = __atomic_load_n(&ring->br_cons_head,
        __ATOMIC_RELAXED);

    if (consumer_head == __atomic_load_n(&ring->br_prod_tail,
        __ATOMIC_RELAXED))
        return;
    __atomic_store_n(&ring->br_cons_head, consumer_head + 1u,
        __ATOMIC_RELAXED);
    __atomic_store_n(&ring->br_cons_tail, consumer_head + 1u,
        __ATOMIC_RELEASE);
}

static inline int
buf_ring_empty(struct buf_ring *ring)
{
    return __atomic_load_n(&ring->br_cons_head, __ATOMIC_RELAXED) ==
        __atomic_load_n(&ring->br_prod_tail, __ATOMIC_ACQUIRE);
}

static inline int
buf_ring_full(struct buf_ring *ring)
{
    uint32_t producer_head = __atomic_load_n(&ring->br_prod_head,
        __ATOMIC_ACQUIRE);
    uint32_t consumer_tail = __atomic_load_n(&ring->br_cons_tail,
        __ATOMIC_ACQUIRE);

    return producer_head - consumer_tail >=
        (uint32_t)ring->br_prod_size - 1u;
}

static inline int
buf_ring_count(struct buf_ring *ring)
{
    uint32_t consumer_tail = __atomic_load_n(&ring->br_cons_tail,
        __ATOMIC_RELAXED);
    uint32_t producer_tail = __atomic_load_n(&ring->br_prod_tail,
        __ATOMIC_ACQUIRE);

    return ((uint32_t)ring->br_prod_size + producer_tail -
        consumer_tail) & (uint32_t)ring->br_prod_mask;
}

struct buf_ring *buf_ring_alloc(int count, struct malloc_type *type,
    int flags, struct mtx *lock);
void buf_ring_free(struct buf_ring *ring, struct malloc_type *type);

#undef BSD_BUF_RING_ASSERT

#endif
