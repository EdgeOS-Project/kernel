/* SPDX-License-Identifier: MPL-2.0 */
/* Shared interface-cloner registry for imported BSD network stacks. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/net/if_clone.h"
#include "compat/freebsd/net/if_var.h"

#define BSD_IFC_EPERM 1
#define BSD_IFC_ENOENT 2
#define BSD_IFC_EEXIST 17
#define BSD_IFC_EINVAL 22
#define BSD_IFC_ENOSPC 28
#define BSD_IFC_EFAULT 14
#define BSD_IFC_MAX_UNIT 0x7fff

typedef struct bsd_ifc_interface {
    struct bsd_ifc_interface *next;
    struct ifnet *interface;
    int unit;
} bsd_ifc_interface_t;

struct if_clone {
    struct if_clone *next;
    char name[IFNAMSIZ];
    uint32_t flags;
    uint32_t maxunit;
    ifc_match_f *match;
    ifc_create_f *create;
    ifc_destroy_f *destroy;
    uint64_t *allocated_units;
    uint32_t unit_word_count;
    bsd_ifc_interface_t *interfaces;
    volatile uint32_t active_operations;
    volatile uint8_t detaching;
};

static struct if_clone *g_ifc_cloners;
static volatile uint8_t g_ifc_guard;

static void
ifc_lock(void)
{
    while (__atomic_test_and_set(&g_ifc_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
ifc_unlock(void)
{
    __atomic_clear(&g_ifc_guard, __ATOMIC_RELEASE);
}

static void
ifc_operation_release(struct if_clone *cloner)
{
    (void)__atomic_fetch_sub(
        &cloner->active_operations, 1u, __ATOMIC_ACQ_REL);
}

static int
ifc_default_match(struct if_clone *cloner, const char *name)
{
    size_t prefix_length;
    int unit;

    if (!cloner || !name)
        return 0;
    prefix_length = bsd_strlen(cloner->name);
    if (bsd_strncmp(name, cloner->name, prefix_length) != 0)
        return 0;
    if (name[prefix_length] &&
        (name[prefix_length] < '0' || name[prefix_length] > '9'))
        return 0;
    return ifc_name2unit(name, &unit) == 0;
}

int
ifc_name2unit(const char *name, int *unit)
{
    const char *cursor;
    int value = 0;

    if (!name || !unit)
        return BSD_IFC_EINVAL;
    cursor = name;
    while (*cursor && (*cursor < '0' || *cursor > '9'))
        ++cursor;
    if (!*cursor) {
        *unit = -1;
        return 0;
    }
    if (cursor[0] == '0' && cursor[1])
        return BSD_IFC_EINVAL;
    while (*cursor) {
        int digit;

        if (*cursor < '0' || *cursor > '9')
            return BSD_IFC_EINVAL;
        digit = *cursor++ - '0';
        if (value > (INT32_MAX - digit) / 10)
            return BSD_IFC_EINVAL;
        value = value * 10 + digit;
    }
    *unit = value;
    return 0;
}

static int
ifc_unit_is_allocated(struct if_clone *cloner, uint32_t unit)
{
    return (cloner->allocated_units[unit / 64u] &
        (UINT64_C(1) << (unit % 64u))) != 0;
}

static void
ifc_unit_set(struct if_clone *cloner, uint32_t unit, int allocated)
{
    uint64_t mask = UINT64_C(1) << (unit % 64u);

    if (allocated)
        cloner->allocated_units[unit / 64u] |= mask;
    else
        cloner->allocated_units[unit / 64u] &= ~mask;
}

int
ifc_alloc_unit(struct if_clone *cloner, int *unit)
{
    uint32_t candidate;

    if (!cloner || !unit)
        return BSD_IFC_EINVAL;
    ifc_lock();
    if (cloner->detaching) {
        ifc_unlock();
        return BSD_IFC_EPERM;
    }
    if (*unit >= 0) {
        candidate = (uint32_t)*unit;
        if (candidate > cloner->maxunit) {
            ifc_unlock();
            return BSD_IFC_ENOSPC;
        }
        if (ifc_unit_is_allocated(cloner, candidate)) {
            ifc_unlock();
            return BSD_IFC_EEXIST;
        }
    } else {
        for (candidate = 0; candidate <= cloner->maxunit; ++candidate) {
            if (!ifc_unit_is_allocated(cloner, candidate))
                break;
        }
        if (candidate > cloner->maxunit) {
            ifc_unlock();
            return BSD_IFC_ENOSPC;
        }
    }
    ifc_unit_set(cloner, candidate, 1);
    ifc_unlock();
    *unit = (int)candidate;
    return 0;
}

void
ifc_free_unit(struct if_clone *cloner, int unit)
{
    if (!cloner || unit < 0 || (uint32_t)unit > cloner->maxunit)
        return;
    ifc_lock();
    ifc_unit_set(cloner, (uint32_t)unit, 0);
    ifc_unlock();
}

struct if_clone *
ifc_attach_cloner(const char *name, struct if_clone_addreq *request)
{
    struct if_clone *cloner;
    uint32_t maxunit;
    size_t allocation_size;

    if (!name || !name[0] || bsd_strlen(name) >= IFNAMSIZ ||
        !request || !request->create_f || !request->destroy_f)
        return 0;
    maxunit = (request->flags & IFC_F_LIMITUNIT) ?
        request->maxunit : BSD_IFC_MAX_UNIT;
    if (maxunit > BSD_IFC_MAX_UNIT)
        return 0;
    allocation_size = sizeof(*cloner) +
        ((size_t)maxunit + 64u) / 64u * sizeof(uint64_t);
    cloner = bsd_malloc(allocation_size, M_DEVBUF, M_WAITOK | M_ZERO);
    if (!cloner)
        return 0;
    (void)bsd_strlcpy(cloner->name, name, sizeof(cloner->name));
    cloner->flags = request->flags & IFC_F_AUTOUNIT;
    cloner->maxunit = maxunit;
    cloner->match = request->match_f ?
        request->match_f : ifc_default_match;
    cloner->create = request->create_f;
    cloner->destroy = request->destroy_f;
    cloner->allocated_units = (uint64_t *)(cloner + 1);
    cloner->unit_word_count = (maxunit + 64u) / 64u;
    ifc_lock();
    for (struct if_clone *entry = g_ifc_cloners; entry;
        entry = entry->next) {
        if (bsd_strcmp(entry->name, name) == 0) {
            ifc_unlock();
            bsd_free(cloner, M_DEVBUF);
            return 0;
        }
    }
    cloner->next = g_ifc_cloners;
    g_ifc_cloners = cloner;
    ifc_unlock();
    return cloner;
}

void
ifc_link_ifp(struct if_clone *cloner, struct ifnet *interface)
{
    bsd_ifc_interface_t *entry;
    bsd_ifc_interface_t *current;
    int unit;

    if (!cloner || !interface ||
        ifc_name2unit(if_name(interface), &unit) != 0)
        return;
    entry = bsd_malloc(sizeof(*entry), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!entry)
        return;
    entry->interface = interface;
    entry->unit = unit;
    if_ref(interface);
    ifc_lock();
    for (current = cloner->interfaces; current; current = current->next) {
        if (current->interface == interface) {
            ifc_unlock();
            if_rele(interface);
            bsd_free(entry, M_DEVBUF);
            return;
        }
    }
    entry->next = cloner->interfaces;
    cloner->interfaces = entry;
    ifc_unlock();
}

bool
ifc_unlink_ifp(struct if_clone *cloner, struct ifnet *interface)
{
    bsd_ifc_interface_t **position;
    bsd_ifc_interface_t *entry;

    if (!cloner || !interface)
        return false;
    ifc_lock();
    position = &cloner->interfaces;
    while (*position && (*position)->interface != interface)
        position = &(*position)->next;
    entry = *position;
    if (entry)
        *position = entry->next;
    ifc_unlock();
    if (!entry)
        return false;
    ifc_free_unit(cloner, entry->unit);
    if_rele(interface);
    bsd_free(entry, M_DEVBUF);
    return true;
}

void
if_clone_addif(struct if_clone *cloner, struct ifnet *interface)
{
    ifc_link_ifp(cloner, interface);
}

int
ifc_copyin(const struct ifc_data *data, void *target, size_t length)
{
    if (!data || !target || !data->params)
        return BSD_IFC_EINVAL;
    if ((data->flags & IFC_F_SYSSPACE) == 0)
        return BSD_IFC_EFAULT;
    bsd_memcpy(target, data->params, length);
    return 0;
}

int
ifc_create_ifp(const char *requested_name, struct ifc_data *data,
    struct ifnet **interface)
{
    struct if_clone *cloner = 0;
    struct ifnet *created = 0;
    char name[IFNAMSIZ];
    int unit;
    int result;

    if (!requested_name || !data || !interface ||
        bsd_strlen(requested_name) >= sizeof(name))
        return BSD_IFC_EINVAL;
    ifc_lock();
    for (struct if_clone *entry = g_ifc_cloners; entry;
        entry = entry->next) {
        if (!entry->detaching && entry->match(entry, requested_name)) {
            cloner = entry;
            (void)__atomic_fetch_add(
                &cloner->active_operations, 1u, __ATOMIC_ACQ_REL);
            break;
        }
    }
    ifc_unlock();
    if (!cloner)
        return BSD_IFC_ENOENT;
    (void)bsd_strlcpy(name, requested_name, sizeof(name));
    result = ifc_name2unit(name, &unit);
    if (result)
        goto complete;
    if (unit < 0 && (cloner->flags & IFC_F_AUTOUNIT) == 0) {
        result = BSD_IFC_EINVAL;
        goto complete;
    }
    result = ifc_alloc_unit(cloner, &unit);
    if (result)
        goto complete;
    if (bsd_snprintf(name, sizeof(name), "%s%d",
        cloner->name, unit) >= (int)sizeof(name)) {
        ifc_free_unit(cloner, unit);
        result = BSD_IFC_EINVAL;
        goto complete;
    }
    data->unit = (uint32_t)unit;
    data->flags |= IFC_F_CREATE;
    result = cloner->create(
        cloner, name, sizeof(name), data, &created);
    if (result || !created) {
        ifc_free_unit(cloner, unit);
        if (!result)
            result = BSD_IFC_EINVAL;
        goto complete;
    }
    ifc_link_ifp(cloner, created);
    *interface = created;
    result = 0;

complete:
    ifc_operation_release(cloner);
    return result;
}

static int
ifc_destroy_interface(
    struct if_clone *cloner, struct ifnet *interface, int force)
{
    int unit;
    int error;

    if (!cloner || !interface)
        return BSD_IFC_EINVAL;
    if (ifc_name2unit(if_name(interface), &unit) != 0 ||
        !ifc_unlink_ifp(cloner, interface))
        return BSD_IFC_ENOENT;
    error = cloner->destroy(cloner, interface,
        force ? IFC_F_FORCE : 0);
    if (error) {
        ifc_lock();
        if (unit >= 0 && (uint32_t)unit <= cloner->maxunit)
            ifc_unit_set(cloner, (uint32_t)unit, 1);
        ifc_unlock();
        ifc_link_ifp(cloner, interface);
        return error;
    }
    return 0;
}

int
if_clone_destroyif(struct if_clone *cloner, struct ifnet *interface)
{
    int error;

    if (!cloner || !interface)
        return BSD_IFC_EINVAL;
    ifc_lock();
    if (cloner->detaching) {
        ifc_unlock();
        return BSD_IFC_EPERM;
    }
    (void)__atomic_fetch_add(
        &cloner->active_operations, 1u, __ATOMIC_ACQ_REL);
    ifc_unlock();
    error = ifc_destroy_interface(cloner, interface, 0);
    ifc_operation_release(cloner);
    return error;
}

void
ifc_detach_cloner(struct if_clone *cloner)
{
    struct if_clone **position;

    if (!cloner)
        return;
    ifc_lock();
    if (cloner->detaching) {
        ifc_unlock();
        return;
    }
    cloner->detaching = 1;
    ifc_unlock();
    while (__atomic_load_n(
        &cloner->active_operations, __ATOMIC_ACQUIRE) != 0)
        bsd_kthread_pump();
    while (cloner->interfaces) {
        if (ifc_destroy_interface(
            cloner, cloner->interfaces->interface, 1) != 0) {
            ifc_lock();
            cloner->detaching = 0;
            ifc_unlock();
            return;
        }
    }
    ifc_lock();
    position = &g_ifc_cloners;
    while (*position && *position != cloner)
        position = &(*position)->next;
    if (*position)
        *position = cloner->next;
    ifc_unlock();
    bsd_free(cloner, M_DEVBUF);
}
