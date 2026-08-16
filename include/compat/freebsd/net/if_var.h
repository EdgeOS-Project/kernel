/* SPDX-License-Identifier: BSD-3-Clause */
/* Functional FreeBSD ifnet interface used by imported network drivers. */

#ifndef _NET_IF_VAR_H_
#define _NET_IF_VAR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "if.h"
#include "../sys/callout.h"
#include "../sys/buf_ring.h"
#include "../sys/epoch.h"
#include "../sys/mbuf.h"
#include "../sys/socket.h"
#include "../sys/taskqueue.h"
#include "vnet.h"

struct route;
struct ifaddr;
struct _device;
struct bpf_if;
struct ifvlantrunk;
struct sockaddr_dl;
struct malloc_type;
struct mtx;
struct thread;
typedef struct _device *device_t;

typedef enum {
    IFCOUNTER_IPACKETS = 0,
    IFCOUNTER_IERRORS,
    IFCOUNTER_OPACKETS,
    IFCOUNTER_OERRORS,
    IFCOUNTER_COLLISIONS,
    IFCOUNTER_IBYTES,
    IFCOUNTER_OBYTES,
    IFCOUNTER_IMCASTS,
    IFCOUNTER_OMCASTS,
    IFCOUNTER_IQDROPS,
    IFCOUNTER_OQDROPS,
    IFCOUNTER_NOPROTO,
    IFCOUNTERS
} ift_counter;

typedef void (*if_start_fn_t)(if_t);
typedef int (*if_ioctl_fn_t)(if_t, unsigned long, char *);
typedef void (*if_init_fn_t)(void *);
typedef void (*if_input_fn_t)(if_t, struct mbuf *);
typedef int (*if_output_fn_t)(if_t, struct mbuf *, const struct sockaddr *,
    struct route *);
typedef void (*if_qflush_fn_t)(if_t);
typedef int (*if_transmit_fn_t)(if_t, struct mbuf *);
typedef uint64_t (*if_get_counter_t)(if_t, ift_counter);
typedef unsigned int iflladdr_cb_t(void *, struct sockaddr_dl *,
    unsigned int);

#define IF_DUNIT_NONE (-1)
#define IFNET_EVENT_UP 0
#define IFNET_EVENT_DOWN 1
#define IFNET_EVENT_UPDATE_BAUDRATE 3

struct ifnet {
    char if_name_storage[IFNAMSIZ];
    char if_driver_name[IFNAMSIZ];
    unsigned int if_dunit;
    unsigned int if_index;
    uint8_t if_type;
    uint8_t if_mac[6];
    uint16_t if_header_length;
    int if_flags;
    int if_drv_flags;
    int if_capabilities;
    int if_capenable;
    int if_hwassist;
    int if_mtu;
    int if_link_state;
    uint64_t if_baudrate;
    unsigned int if_tsomax;
    unsigned int if_tsomaxsegcount;
    unsigned int if_tsomaxsegsize;
    void *if_softc;
    device_t if_device;
    struct vnet *if_vnet;
    if_init_fn_t if_init_callback;
    if_ioctl_fn_t if_ioctl_callback;
    if_start_fn_t if_start_callback;
    if_output_fn_t if_output_callback;
    if_input_fn_t if_input;
    if_transmit_fn_t if_transmit_callback;
    if_qflush_fn_t if_qflush_callback;
    if_get_counter_t if_counter_callback;
    struct mbuf *if_send_head;
    struct mbuf *if_send_tail;
    unsigned int if_send_length;
    unsigned int if_send_limit;
    uint64_t if_counters[IFCOUNTERS];
    uint64_t if_bridge_handle;
    void *if_bridge;
    uint32_t if_inflight;
    volatile uint32_t if_refcount;
    uint32_t if_fib;
    uint32_t if_ipv4_address;
    uint32_t if_ipv4_netmask;
    uint32_t if_ipv4_gateway;
    uint8_t if_attached;
    struct bpf_if *if_bpf;
    struct ifvlantrunk *if_vlantrunk;
    struct task if_linktask;
    struct ifaddr *if_addr;
};

struct ifaddr {
    struct sockaddr *ifa_addr;
    struct sockaddr *ifa_dstaddr;
    struct sockaddr *ifa_netmask;
    if_t ifa_ifp;
    uint16_t ifa_flags;
    volatile uint32_t ifa_refcount;
};

#define if_init if_init_callback
#define if_ioctl if_ioctl_callback
#define if_start if_start_callback
#define if_output if_output_callback
#define if_transmit if_transmit_callback
#define if_qflush if_qflush_callback
#define if_get_counter if_counter_callback
#define if_hdrlen if_header_length

if_t if_alloc(unsigned char type);
void *if_gethandle(unsigned char type);
void if_free(if_t ifp);
void if_ref(if_t ifp);
void if_rele(if_t ifp);
void if_initname(if_t ifp, const char *name, int unit);
const char *if_name(if_t ifp);
int if_printf(if_t ifp, const char *format, ...);
uint64_t if_setbaudrate(if_t ifp, uint64_t baudrate);
uint64_t if_getbaudrate(const if_t ifp);
int if_getdunit(const if_t ifp);
int if_getindex(const if_t ifp);
int if_getalloctype(const if_t ifp);
const char *if_getdname(const if_t ifp);
int if_setcapabilitiesbit(if_t ifp, int set_bits, int clear_bits);
int if_setcapabilities(if_t ifp, int capabilities);
int if_getcapabilities(const if_t ifp);
int if_setcapenable(if_t ifp, int capabilities);
int if_setcapenablebit(if_t ifp, int set_bits, int clear_bits);
int if_togglecapenable(if_t ifp, int toggle_bits);
int if_getcapenable(const if_t ifp);
int if_setdrvflagbits(if_t ifp, int set_bits, int clear_bits);
int if_setdrvflags(if_t ifp, int flags);
int if_getdrvflags(const if_t ifp);
int if_sethwassistbits(if_t ifp, int set_bits, int clear_bits);
int if_sethwassist(if_t ifp, int value);
int if_gethwassist(const if_t ifp);
void if_clearhwassist(if_t ifp);
int if_togglehwassist(if_t ifp, int toggle_bits);
int if_setsoftc(if_t ifp, void *softc);
void *if_getsoftc(if_t ifp);
int if_setflags(if_t ifp, int flags);
int if_setflagbits(if_t ifp, int set_bits, int clear_bits);
int if_getflags(const if_t ifp);
void if_down(if_t ifp);
void if_up(if_t ifp);
int if_setmtu(if_t ifp, int mtu);
int if_getmtu(const if_t ifp);
int if_setsendqready(if_t ifp);
int if_setsendqlen(if_t ifp, int length);
int if_sethwtsomax(if_t ifp, unsigned int value);
int if_sethwtsomaxsegcount(if_t ifp, unsigned int value);
int if_sethwtsomaxsegsize(if_t ifp, unsigned int value);
unsigned int if_gethwtsomax(const if_t ifp);
unsigned int if_gethwtsomaxsegcount(const if_t ifp);
unsigned int if_gethwtsomaxsegsize(const if_t ifp);
int if_setifheaderlen(if_t ifp, int length);
char *if_getlladdr(const struct ifnet *ifp);
const uint8_t *if_getbroadcastaddr(const if_t ifp);
struct vnet *if_getvnet(const if_t ifp);
int if_getlinkstate(if_t ifp);
void if_init(if_t ifp, void *context);
void if_input(if_t ifp, struct mbuf *mbuf);
void if_setrcvif(struct mbuf *mbuf, if_t ifp);
int if_transmit(if_t ifp, struct mbuf *mbuf);
int if_sendq_prepend(if_t ifp, struct mbuf *mbuf);
struct mbuf *if_dequeue(if_t ifp);
int if_sendq_empty(if_t ifp);
void if_qflush(if_t ifp);
void if_link_state_change(if_t ifp, int state);
void if_inc_counter(if_t ifp, ift_counter counter, int64_t value);
uint64_t if_getcounter(if_t ifp, ift_counter counter);
uint64_t if_get_counter_default(if_t ifp, ift_counter counter);
unsigned int if_foreach_lladdr(if_t ifp, iflladdr_cb_t callback,
    void *argument);
unsigned int if_foreach_llmaddr(if_t ifp, iflladdr_cb_t callback,
    void *argument);
unsigned int if_llmaddr_count(if_t ifp);
bool if_maddr_empty(if_t ifp);
struct ifaddr *if_getifaddr(const if_t ifp);
if_t ifnet_byindex(unsigned int index);
int ifhwioctl(unsigned long command, if_t ifp, char *data,
    struct thread *thread);

struct buf_ring *buf_ring_alloc(int count, struct malloc_type *type,
    int flags, struct mtx *mutex);
void buf_ring_free(struct buf_ring *ring, struct malloc_type *type);
int drbr_enqueue(if_t ifp, struct buf_ring *ring, struct mbuf *mbuf);
struct mbuf *drbr_dequeue(if_t ifp, struct buf_ring *ring);
int drbr_needs_enqueue(if_t ifp, struct buf_ring *ring);
void drbr_putback(if_t ifp, struct buf_ring *ring, struct mbuf *mbuf);
struct mbuf *drbr_peek(if_t ifp, struct buf_ring *ring);
void drbr_flush(if_t ifp, struct buf_ring *ring);
void drbr_free(struct buf_ring *ring, struct malloc_type *type);
void drbr_advance(if_t ifp, struct buf_ring *ring);
int drbr_empty(if_t ifp, struct buf_ring *ring);
int drbr_inuse(if_t ifp, struct buf_ring *ring);

void if_setinitfn(if_t ifp, if_init_fn_t callback);
void if_setioctlfn(if_t ifp, if_ioctl_fn_t callback);
void if_setstartfn(if_t ifp, if_start_fn_t callback);
if_start_fn_t if_getstartfn(if_t ifp);
void if_settransmitfn(if_t ifp, if_transmit_fn_t callback);
void if_setinputfn(if_t ifp, if_input_fn_t callback);
if_input_fn_t if_getinputfn(if_t ifp);
void if_setoutputfn(if_t ifp, if_output_fn_t callback);
void if_setqflushfn(if_t ifp, if_qflush_fn_t callback);
void if_setgetcounterfn(if_t ifp, if_get_counter_t callback);
if_t if_alloc_dev(unsigned char type, device_t device);
void if_setdev(if_t ifp, device_t device);
int if_altq_is_enabled(if_t ifp);
void if_vlancap(if_t ifp);
int if_vlantrunkinuse(if_t ifp);
struct ifvlantrunk *if_getvlantrunk(if_t ifp);
void ifnet_global_write_lock(void);
void ifnet_global_write_unlock(void);
void if_attach(if_t ifp);
void if_detach(if_t ifp);
void if_dead(if_t ifp);
int if_getfib(if_t ifp);
void if_input_raw(if_t ifp, struct mbuf *mbuf, unsigned int family);

#define IFNET_WLOCK() ifnet_global_write_lock()
#define IFNET_WUNLOCK() ifnet_global_write_unlock()

struct ifqueue {
    struct mbuf *ifq_head;
    struct mbuf *ifq_tail;
    int ifq_len;
    int ifq_maxlen;
    volatile uint8_t ifq_guard;
};

extern int ifqmaxlen;

static inline void
ifqueue_lock(struct ifqueue *queue)
{
    while (__atomic_test_and_set(&queue->ifq_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
        __asm__ __volatile__("yield");
#endif
    }
}

static inline void
ifqueue_unlock(struct ifqueue *queue)
{
    __atomic_clear(&queue->ifq_guard, __ATOMIC_RELEASE);
}

static inline struct mbuf *
ifqueue_dequeue(struct ifqueue *queue)
{
    struct mbuf *mbuf;

    ifqueue_lock(queue);
    mbuf = queue->ifq_head;
    if (mbuf) {
        queue->ifq_head = mbuf->m_nextpkt;
        if (!queue->ifq_head)
            queue->ifq_tail = 0;
        mbuf->m_nextpkt = 0;
        --queue->ifq_len;
    }
    ifqueue_unlock(queue);
    return mbuf;
}

static inline void
ifqueue_enqueue_unlocked(struct ifqueue *queue, struct mbuf *mbuf)
{
    if (!queue || !mbuf)
        return;
    mbuf->m_nextpkt = 0;
    if (queue->ifq_tail)
        queue->ifq_tail->m_nextpkt = mbuf;
    else
        queue->ifq_head = mbuf;
    queue->ifq_tail = mbuf;
    ++queue->ifq_len;
}

static inline struct mbuf *
ifqueue_dequeue_unlocked(struct ifqueue *queue)
{
    struct mbuf *mbuf;

    if (!queue)
        return 0;
    mbuf = queue->ifq_head;
    if (mbuf) {
        queue->ifq_head = mbuf->m_nextpkt;
        if (!queue->ifq_head)
            queue->ifq_tail = 0;
        mbuf->m_nextpkt = 0;
        --queue->ifq_len;
    }
    return mbuf;
}

#define IF_LOCK(queue) ifqueue_lock((queue))
#define IF_UNLOCK(queue) ifqueue_unlock((queue))
#define IF_DEQUEUE(queue, mbuf) ((mbuf) = ifqueue_dequeue((queue)))
#define _IF_ENQUEUE(queue, mbuf) ifqueue_enqueue_unlocked((queue), (mbuf))
#define _IF_DEQUEUE(queue, mbuf) \
    ((mbuf) = ifqueue_dequeue_unlocked((queue)))

#endif
