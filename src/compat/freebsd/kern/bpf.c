/* SPDX-License-Identifier: MPL-2.0 */
/* Concurrent packet-tap delivery for imported BSD network drivers. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/net/bpf.h"
#include "compat/freebsd/net/if_var.h"
#include "compat/freebsd/sys/mbuf.h"
#include "compat/freebsd/sys/sockio.h"

#define BSD_BPF_EINVAL 22

struct bpf_listener {
    struct bpf_listener *next;
    struct bpf_if *owner;
    struct bpf_if *interface_reference;
    bsd_bpf_listener_fn callback;
    void *context;
    volatile uint32_t references;
    volatile uint8_t active;
};

struct bpf_if {
    struct bpf_listener *listeners;
    const struct bif_methods *methods;
    void *softc;
    unsigned int dlt;
    unsigned int header_length;
    volatile uint32_t references;
    volatile uint32_t deliveries;
    volatile uint32_t listener_count;
    volatile uint8_t listener_guard;
    volatile uint8_t detaching;
    volatile uint8_t cleanup_started;
    char name[IFNAMSIZ];
};

static void
bpf_interface_lock(struct bpf_if *interface)
{
    while (__atomic_test_and_set(
        &interface->listener_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
bpf_interface_unlock(struct bpf_if *interface)
{
    __atomic_clear(&interface->listener_guard, __ATOMIC_RELEASE);
}

static void
bpf_interface_retain(struct bpf_if *interface)
{
    (void)__atomic_fetch_add(
        &interface->references, 1u, __ATOMIC_ACQ_REL);
}

static void
bpf_interface_release(struct bpf_if *interface)
{
    if (__atomic_fetch_sub(
        &interface->references, 1u, __ATOMIC_ACQ_REL) == 1)
        bsd_free(interface, M_DEVBUF);
}

static void
bpf_listener_release(struct bpf_listener *listener)
{
    if (__atomic_fetch_sub(
        &listener->references, 1u, __ATOMIC_ACQ_REL) == 1)
        bsd_free(listener, M_DEVBUF);
}

static int
bpf_direction(const struct bpf_if *interface, const struct mbuf *mbuf)
{
    return mbuf && mbuf->m_pkthdr.rcvif == interface->softc ?
        BPF_D_IN : BPF_D_OUT;
}

struct bpf_if *
bpf_attach(const char *name, unsigned int dlt, unsigned int header_length,
    const struct bif_methods *methods, void *softc)
{
    struct bpf_if *interface;

    if (!name)
        return 0;
    interface = bsd_malloc(
        sizeof(*interface), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!interface)
        return 0;
    (void)bsd_strlcpy(interface->name, name, sizeof(interface->name));
    interface->dlt = dlt;
    interface->header_length = header_length;
    interface->methods = methods;
    interface->softc = softc;
    interface->references = 1;
    return interface;
}

struct bpf_listener *
bsd_bpf_listener_attach(struct bpf_if *interface,
    bsd_bpf_listener_fn callback, void *context)
{
    struct bpf_listener *listener;
    uint32_t previous;

    if (!interface || !callback)
        return 0;
    listener = bsd_malloc(
        sizeof(*listener), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!listener)
        return 0;
    bpf_interface_lock(interface);
    if (interface->detaching) {
        bpf_interface_unlock(interface);
        bsd_free(listener, M_DEVBUF);
        return 0;
    }
    bpf_interface_retain(interface);
    listener->owner = interface;
    listener->interface_reference = interface;
    listener->callback = callback;
    listener->context = context;
    listener->references = 2;
    listener->active = 1;
    listener->next = interface->listeners;
    interface->listeners = listener;
    previous = __atomic_fetch_add(
        &interface->listener_count, 1u, __ATOMIC_ACQ_REL);
    bpf_interface_unlock(interface);
    if (previous == 0 && interface->methods &&
        interface->methods->bif_attachd)
        interface->methods->bif_attachd(interface->softc);
    return listener;
}

void
bsd_bpf_listener_detach(struct bpf_listener *listener)
{
    struct bpf_if *interface;
    struct bpf_if *interface_reference;
    uint8_t expected = 1;
    uint32_t previous;
    int notify_detached = 0;

    if (!listener ||
        !__atomic_compare_exchange_n(&listener->active, &expected, 0, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    interface = listener->owner;
    interface_reference = listener->interface_reference;
    if (interface) {
        bpf_interface_lock(interface);
        if (!interface->detaching) {
            previous = __atomic_fetch_sub(
                &interface->listener_count, 1u, __ATOMIC_ACQ_REL);
            notify_detached = previous == 1;
        }
        listener->owner = 0;
        bpf_interface_unlock(interface);
    }
    if (notify_detached && interface->methods &&
        interface->methods->bif_detachd)
        interface->methods->bif_detachd(interface->softc);
    if (interface_reference)
        bpf_interface_release(interface_reference);
    listener->interface_reference = 0;
    bpf_listener_release(listener);
}

bool
bpf_peers_present(const struct bpf_if *interface)
{
    return interface &&
        __atomic_load_n(&interface->listener_count, __ATOMIC_ACQUIRE) != 0;
}

bool
bpf_peers_present_if(struct ifnet *interface)
{
    return interface && bpf_peers_present(interface->if_bpf);
}

static void
bpf_finalize_detach(struct bpf_if *interface)
{
    struct bpf_listener *listener;
    uint8_t expected = 0;

    if (!__atomic_compare_exchange_n(
        &interface->cleanup_started, &expected, 1, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    listener = interface->listeners;
    interface->listeners = 0;
    while (listener) {
        struct bpf_listener *next = listener->next;

        listener->owner = 0;
        bpf_listener_release(listener);
        listener = next;
    }
    bpf_interface_release(interface);
}

static void
bpf_delivery_release(struct bpf_if *interface)
{
    if (__atomic_fetch_sub(
        &interface->deliveries, 1u, __ATOMIC_ACQ_REL) == 1 &&
        __atomic_load_n(&interface->detaching, __ATOMIC_ACQUIRE))
        bpf_finalize_detach(interface);
}

static void
bpf_deliver(struct bpf_if *interface, const void *prefix,
    uint32_t prefix_length, struct mbuf *mbuf)
{
    struct bpf_listener *listener;
    int direction;

    if (!interface || !mbuf)
        return;
    bpf_interface_lock(interface);
    if (interface->detaching) {
        bpf_interface_unlock(interface);
        return;
    }
    (void)__atomic_fetch_add(
        &interface->deliveries, 1u, __ATOMIC_ACQ_REL);
    bpf_interface_unlock(interface);
    if (!bpf_peers_present(interface)) {
        bpf_delivery_release(interface);
        return;
    }
    direction = bpf_direction(interface, mbuf);
    if (interface->methods && interface->methods->bif_chkdir &&
        interface->methods->bif_chkdir(
            interface->softc, mbuf, direction)) {
        bpf_delivery_release(interface);
        return;
    }
    listener = __atomic_load_n(
        &interface->listeners, __ATOMIC_ACQUIRE);
    while (listener) {
        if (__atomic_load_n(&listener->active, __ATOMIC_ACQUIRE))
            listener->callback(listener->context, prefix,
                prefix_length, mbuf, direction);
        listener = listener->next;
    }
    bpf_delivery_release(interface);
}

void
bpf_mtap(struct bpf_if *interface, struct mbuf *mbuf)
{
    bpf_deliver(interface, 0, 0, mbuf);
}

void
bpf_mtap_if(struct ifnet *interface, struct mbuf *mbuf)
{
    if (interface)
        bpf_mtap(interface->if_bpf, mbuf);
}

void
bpf_mtap2(struct bpf_if *interface, void *prefix,
    unsigned int prefix_length, struct mbuf *mbuf)
{
    if (prefix_length != 0 && !prefix)
        return;
    bpf_deliver(interface, prefix, prefix_length, mbuf);
}

void
bpf_mtap2_if(struct ifnet *interface, void *prefix,
    unsigned int prefix_length, struct mbuf *mbuf)
{
    if (interface)
        bpf_mtap2(interface->if_bpf, prefix, prefix_length, mbuf);
}

void
bpf_tap(struct bpf_if *interface, const void *data, unsigned int length)
{
    struct mbuf packet = {
        .m_data = (char *)(uintptr_t)data,
        .m_len = (int32_t)length,
        .m_type = MT_DATA,
        .m_flags = M_PKTHDR,
        .m_pkthdr = {
            .rcvif = interface ? interface->softc : 0,
            .len = (int32_t)length,
        },
    };

    if (data || length == 0)
        bpf_deliver(interface, 0, 0, &packet);
}

void
bpf_detach(struct bpf_if *interface)
{
    uint32_t previous;

    if (!interface)
        return;
    bpf_interface_lock(interface);
    if (interface->detaching) {
        bpf_interface_unlock(interface);
        return;
    }
    interface->detaching = 1;
    previous = __atomic_exchange_n(
        &interface->listener_count, 0u, __ATOMIC_ACQ_REL);
    bpf_interface_unlock(interface);
    if (previous != 0 &&
        interface->methods && interface->methods->bif_detachd)
        interface->methods->bif_detachd(interface->softc);
    if (__atomic_load_n(&interface->deliveries, __ATOMIC_ACQUIRE) == 0)
        bpf_finalize_detach(interface);
}

void
bpfattach(struct ifnet *interface, unsigned int dlt,
    unsigned int header_length)
{
    if (!interface || interface->if_bpf)
        return;
    interface->if_bpf = bpf_attach(
        if_name(interface), dlt, header_length, 0, interface);
}

void
bpfdetach(struct ifnet *interface)
{
    struct bpf_if *bpf_interface;

    if (!interface)
        return;
    bpf_interface = interface->if_bpf;
    interface->if_bpf = 0;
    bpf_detach(bpf_interface);
}

uint32_t
bpf_ifnet_wrsize(void *softc)
{
    struct ifnet *interface = softc;

    if (!interface)
        return 0;
    return (uint32_t)if_getmtu(interface) +
        (uint32_t)interface->if_header_length;
}

int
bpf_ifnet_promisc(void *softc, bool enabled)
{
    struct ifnet *interface = softc;
    int previous;
    int result = 0;

    if (!interface)
        return BSD_BPF_EINVAL;
    previous = if_getflags(interface);
    if_setflagbits(interface, enabled ? IFF_PROMISC : 0,
        enabled ? 0 : IFF_PROMISC);
    if (interface->if_ioctl)
        result = interface->if_ioctl(
            interface, SIOCSIFFLAGS, 0);
    if (result)
        (void)if_setflags(interface, previous);
    return result;
}
