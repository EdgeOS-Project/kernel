/* SPDX-License-Identifier: MPL-2.0 */
/* Shared functional UMA zones for imported BSD drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/vm/uma.h"

struct uma_zone {
    char name[32];
    size_t size;
    uma_ctor constructor;
    uma_dtor destructor;
    uma_init initializer;
    uma_fini finalizer;
    unsigned int alignment;
    unsigned int flags;
    uint32_t current;
    uint32_t limit;
};

static void
uma_copy_name(char destination[32], const char *source)
{
    size_t index = 0;

    if (source) {
        while (index < 31u && source[index]) {
            destination[index] = source[index];
            index++;
        }
    }
    destination[index] = 0;
}

uma_zone_t
uma_zcreate(const char *name, size_t size, uma_ctor constructor,
    uma_dtor destructor, uma_init initializer, uma_fini finalizer,
    unsigned int alignment, unsigned int flags)
{
    struct uma_zone *zone;

    if (!name || !name[0] || size == 0 ||
        (alignment != 0 && (alignment & (alignment + 1u)) != 0))
        return 0;
    zone = bsd_malloc(sizeof(*zone), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!zone)
        return 0;
    uma_copy_name(zone->name, name);
    zone->size = size;
    zone->constructor = constructor;
    zone->destructor = destructor;
    zone->initializer = initializer;
    zone->finalizer = finalizer;
    zone->alignment = alignment;
    zone->flags = flags;
    return zone;
}

void
uma_zdestroy(uma_zone_t zone)
{
    if (!zone || __atomic_load_n(&zone->current, __ATOMIC_ACQUIRE) != 0)
        return;
    bsd_free(zone, M_DEVBUF);
}

void *
uma_zalloc_arg(uma_zone_t zone, void *argument, int flags)
{
    void *item;
    uint32_t current;
    size_t alignment;

    if (!zone)
        return 0;
    current = __atomic_load_n(&zone->current, __ATOMIC_ACQUIRE);
    for (;;) {
        if (zone->limit != 0 && current >= zone->limit)
            return 0;
        if (__atomic_compare_exchange_n(&zone->current, &current,
            current + 1u, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
    alignment = (size_t)zone->alignment + 1u;
    if (alignment < sizeof(void *))
        alignment = sizeof(void *);
    item = bsd_malloc_aligned(zone->size, alignment, M_DEVBUF,
        flags | ((zone->flags & UMA_ZONE_ZINIT) ? M_ZERO : 0));
    if (!item)
        goto fail;
    if (zone->initializer &&
        zone->initializer(item, (int)zone->size, flags) != 0)
        goto fail_item;
    if (zone->constructor &&
        zone->constructor(item, (int)zone->size, argument, flags) != 0)
        goto fail_initialized;
    return item;

fail_initialized:
    if (zone->finalizer)
        zone->finalizer(item, (int)zone->size);
fail_item:
    bsd_free(item, M_DEVBUF);
fail:
    (void)__atomic_sub_fetch(&zone->current, 1u, __ATOMIC_ACQ_REL);
    return 0;
}

void
uma_zfree_arg(uma_zone_t zone, void *item, void *argument)
{
    if (!zone || !item)
        return;
    if (zone->destructor)
        zone->destructor(item, (int)zone->size, argument);
    if (zone->finalizer)
        zone->finalizer(item, (int)zone->size);
    bsd_free(item, M_DEVBUF);
    (void)__atomic_sub_fetch(&zone->current, 1u, __ATOMIC_ACQ_REL);
}

void
uma_prealloc(uma_zone_t zone, int item_count)
{
    uma_zone_reserve(zone, item_count);
}

void
uma_zone_reserve(uma_zone_t zone, int item_count)
{
    if (!zone || item_count < 0)
        return;
    zone->limit = (uint32_t)item_count;
}

int
uma_zone_get_cur(uma_zone_t zone)
{
    if (!zone)
        return 0;
    return (int)__atomic_load_n(&zone->current, __ATOMIC_ACQUIRE);
}
