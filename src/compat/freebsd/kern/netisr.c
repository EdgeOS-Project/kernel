/* SPDX-License-Identifier: MPL-2.0 */
/* Shared packet-dispatch bridge for FreeBSD network device drivers. */

#include <stddef.h>
#include <stdint.h>

typedef unsigned int u_int;
typedef uint64_t u_int64_t;
#ifdef BSD_BRIDGE_HOST_TEST
#define _KERNEL 1
#endif

#include "compat/freebsd/net/if_var.h"
#include <net/netisr.h>
#include "compat/freebsd/netinet/in.h"
#include "compat/freebsd/sys/mbuf.h"
#include "compat/freebsd/sys/smp.h"

#define BSD_NETISR_MAX_PROTOCOLS 16u
#define BSD_NETISR_QUEUE_CAPACITY 1024u
#define BSD_NETISR_DEFAULT_QUEUE_LIMIT 256u
#define BSD_NETISR_EINVAL 22
#define BSD_NETISR_ENOENT 2
#define BSD_NETISR_ENOBUFS 55

struct bsd_netisr_slot {
    const struct netisr_handler *handler;
    uint64_t queue_drops;
    unsigned int queue_limit;
    unsigned int queue_length;
};

struct bsd_netisr_work {
    struct mbuf *mbuf;
    uintptr_t source;
    unsigned int protocol;
};

static struct bsd_netisr_slot g_netisr_slots[BSD_NETISR_MAX_PROTOCOLS];
static struct bsd_netisr_work g_netisr_queue[BSD_NETISR_QUEUE_CAPACITY];
static unsigned int g_netisr_queue_head;
static unsigned int g_netisr_queue_tail;
static unsigned int g_netisr_queue_length;
static volatile uint8_t g_netisr_guard;

static void
netisr_lock(void)
{
    while (__atomic_test_and_set(&g_netisr_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
netisr_unlock(void)
{
    __atomic_clear(&g_netisr_guard, __ATOMIC_RELEASE);
}

void
netisr_register(const struct netisr_handler *handler)
{
    if (!handler || handler->nh_proto == 0 ||
        handler->nh_proto >= BSD_NETISR_MAX_PROTOCOLS)
        return;
    netisr_lock();
    g_netisr_slots[handler->nh_proto].handler = handler;
    g_netisr_slots[handler->nh_proto].queue_limit = handler->nh_qlimit ?
        handler->nh_qlimit : BSD_NETISR_DEFAULT_QUEUE_LIMIT;
    netisr_unlock();
}

void
netisr_unregister(const struct netisr_handler *handler)
{
    if (!handler || handler->nh_proto == 0 ||
        handler->nh_proto >= BSD_NETISR_MAX_PROTOCOLS)
        return;
    netisr_lock();
    if (g_netisr_slots[handler->nh_proto].handler == handler)
        g_netisr_slots[handler->nh_proto].handler = 0;
    netisr_unlock();
}

void
netisr_clearqdrops(const struct netisr_handler *handler)
{
    if (handler && handler->nh_proto < BSD_NETISR_MAX_PROTOCOLS) {
        netisr_lock();
        g_netisr_slots[handler->nh_proto].queue_drops = 0;
        netisr_unlock();
    }
}

void
netisr_getqdrops(const struct netisr_handler *handler, uint64_t *drops)
{
    if (!drops)
        return;
    if (!handler || handler->nh_proto >= BSD_NETISR_MAX_PROTOCOLS) {
        *drops = 0;
        return;
    }
    netisr_lock();
    *drops = g_netisr_slots[handler->nh_proto].queue_drops;
    netisr_unlock();
}

void
netisr_getqlimit(const struct netisr_handler *handler, unsigned int *limit)
{
    if (!limit)
        return;
    if (!handler || handler->nh_proto >= BSD_NETISR_MAX_PROTOCOLS) {
        *limit = 0;
        return;
    }
    netisr_lock();
    *limit = g_netisr_slots[handler->nh_proto].queue_limit;
    netisr_unlock();
}

int
netisr_setqlimit(const struct netisr_handler *handler, unsigned int limit)
{
    if (!handler || handler->nh_proto == 0 ||
        handler->nh_proto >= BSD_NETISR_MAX_PROTOCOLS)
        return BSD_NETISR_EINVAL;
    netisr_lock();
    g_netisr_slots[handler->nh_proto].queue_limit = limit;
    netisr_unlock();
    return 0;
}

static int
netisr_deliver(unsigned int protocol, uintptr_t source, struct mbuf *mbuf)
{
    const struct netisr_handler *handler;
    if_t interface;

    (void)source;
    if (!mbuf || protocol == 0 || protocol >= BSD_NETISR_MAX_PROTOCOLS) {
        m_freem(mbuf);
        return BSD_NETISR_EINVAL;
    }
    handler = g_netisr_slots[protocol].handler;
    if (handler && handler->nh_handler) {
        handler->nh_handler(mbuf);
        return 0;
    }
    interface = mbuf->m_pkthdr.rcvif;
    if (!interface) {
        m_freem(mbuf);
        return BSD_NETISR_ENOENT;
    }
    if (protocol == NETISR_IP) {
        if_input_raw(interface, mbuf, AF_INET);
        return 0;
    }
    if (protocol == NETISR_IPV6) {
        if_input_raw(interface, mbuf, AF_INET6);
        return 0;
    }
    if (protocol == NETISR_ETHER) {
        if_input(interface, mbuf);
        return 0;
    }
    m_freem(mbuf);
    return BSD_NETISR_ENOENT;
}

int
netisr_dispatch_src(unsigned int protocol, uintptr_t source, struct mbuf *mbuf)
{
    const struct netisr_handler *handler;

    if (!mbuf || protocol == 0 || protocol >= BSD_NETISR_MAX_PROTOCOLS) {
        m_freem(mbuf);
        return BSD_NETISR_EINVAL;
    }
    handler = g_netisr_slots[protocol].handler;
    if (handler && handler->nh_dispatch == NETISR_DISPATCH_DEFERRED)
        return netisr_queue_src(protocol, source, mbuf);
    return netisr_deliver(protocol, source, mbuf);
}

int
netisr_dispatch(unsigned int protocol, struct mbuf *mbuf)
{
    return netisr_dispatch_src(protocol, 0, mbuf);
}

int
netisr_queue_src(unsigned int protocol, uintptr_t source, struct mbuf *mbuf)
{
    struct bsd_netisr_slot *slot;
    struct bsd_netisr_work *work;

    if (!mbuf || protocol == 0 || protocol >= BSD_NETISR_MAX_PROTOCOLS) {
        m_freem(mbuf);
        return BSD_NETISR_EINVAL;
    }
    netisr_lock();
    slot = &g_netisr_slots[protocol];
    if (g_netisr_queue_length == BSD_NETISR_QUEUE_CAPACITY ||
        slot->queue_limit == 0 || slot->queue_length >= slot->queue_limit) {
        slot->queue_drops++;
        netisr_unlock();
        m_freem(mbuf);
        return BSD_NETISR_ENOBUFS;
    }
    work = &g_netisr_queue[g_netisr_queue_tail];
    work->mbuf = mbuf;
    work->source = source;
    work->protocol = protocol;
    g_netisr_queue_tail =
        (g_netisr_queue_tail + 1u) % BSD_NETISR_QUEUE_CAPACITY;
    g_netisr_queue_length++;
    slot->queue_length++;
    netisr_unlock();
    netisr_sched_poll();
    return 0;
}

int
netisr_queue(unsigned int protocol, struct mbuf *mbuf)
{
    return netisr_queue_src(protocol, 0, mbuf);
}

unsigned int
netisr_default_flow2cpu(unsigned int flow_id)
{
    unsigned int count = netisr_get_cpucount();

    return count ? flow_id % count : 0;
}

unsigned int
netisr_get_cpucount(void)
{
    return mp_ncpus > 0 ? (unsigned int)mp_ncpus : 1u;
}

unsigned int
netisr_get_cpuid(unsigned int cpu_number)
{
    return cpu_number < netisr_get_cpucount() ?
        cpu_number : NETISR_CPUID_NONE;
}

void
netisr_sched_poll(void)
{
    netisr_poll();
}

void
netisr_poll(void)
{
    for (;;) {
        struct bsd_netisr_work work;
        struct bsd_netisr_slot *slot;

        netisr_lock();
        if (g_netisr_queue_length == 0) {
            netisr_unlock();
            return;
        }
        work = g_netisr_queue[g_netisr_queue_head];
        g_netisr_queue[g_netisr_queue_head].mbuf = 0;
        g_netisr_queue_head =
            (g_netisr_queue_head + 1u) % BSD_NETISR_QUEUE_CAPACITY;
        g_netisr_queue_length--;
        slot = &g_netisr_slots[work.protocol];
        if (slot->queue_length)
            slot->queue_length--;
        netisr_unlock();
        (void)netisr_deliver(work.protocol, work.source, work.mbuf);
    }
}

void
netisr_pollmore(void)
{
    netisr_poll();
}
