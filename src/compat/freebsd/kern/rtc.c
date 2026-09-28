/* SPDX-License-Identifier: MPL-2.0 */
/* Shared realtime-clock registry for imported FreeBSD clock drivers. */

#include <sys/bus.h>
#include <sys/clock.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/systm.h>

struct bsd_rtc_entry {
    device_t device;
    long resolution_us;
    int flags;
    u_int offset_ns;
    struct bsd_rtc_entry *next;
};

static struct mtx g_bsd_rtc_lock;
static struct bsd_rtc_entry *g_bsd_rtc_entries;

MTX_SYSINIT(edgeos_rtc_registry, &g_bsd_rtc_lock, "RTC registry", MTX_DEF);

void
clock_register_flags(device_t device, long resolution_us, int flags)
{
    struct bsd_rtc_entry **cursor;
    struct bsd_rtc_entry *entry;

    if (!device || resolution_us <= 0)
        return;
    entry = malloc(sizeof(*entry), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!entry)
        return;
    entry->device = device;
    entry->resolution_us = resolution_us;
    entry->flags = flags;

    mtx_lock(&g_bsd_rtc_lock);
    cursor = &g_bsd_rtc_entries;
    while (*cursor && (*cursor)->resolution_us <= resolution_us)
        cursor = &(*cursor)->next;
    entry->next = *cursor;
    *cursor = entry;
    mtx_unlock(&g_bsd_rtc_lock);
}

void
clock_register(device_t device, long resolution_us)
{
    clock_register_flags(device, resolution_us, 0);
}

void
clock_schedule(device_t device, u_int offset_ns)
{
    struct bsd_rtc_entry *entry;

    mtx_lock(&g_bsd_rtc_lock);
    for (entry = g_bsd_rtc_entries; entry; entry = entry->next) {
        if (entry->device == device) {
            entry->offset_ns = offset_ns;
            break;
        }
    }
    mtx_unlock(&g_bsd_rtc_lock);
}

void
clock_unregister(device_t device)
{
    struct bsd_rtc_entry **cursor;
    struct bsd_rtc_entry *entry = NULL;

    mtx_lock(&g_bsd_rtc_lock);
    cursor = &g_bsd_rtc_entries;
    while (*cursor) {
        if ((*cursor)->device == device) {
            entry = *cursor;
            *cursor = entry->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    mtx_unlock(&g_bsd_rtc_lock);
    if (entry)
        free(entry, M_DEVBUF);
}

void
clock_dbgprint_ct(device_t device, int operation,
    const struct clocktime *calendar)
{
    if (!bootverbose || !device || !calendar)
        return;
    device_printf(device, "%s %04d-%02d-%02d %02d:%02d:%02d.%09ld\n",
        (operation & CLOCK_DBG_READ) ? "read" : "write",
        calendar->year, calendar->mon, calendar->day,
        calendar->hour, calendar->min, calendar->sec, calendar->nsec);
}
