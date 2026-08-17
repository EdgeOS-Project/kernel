/* SPDX-License-Identifier: MPL-2.0 */
/* Shared event registry for imported BSD drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/eventhandler.h"

struct eventhandler_entry {
    struct eventhandler_entry *next;
    struct eventhandler_list *list;
    void *function;
    void *argument;
    int priority;
    uint8_t active;
};

struct eventhandler_list {
    struct eventhandler_list *next;
    struct eventhandler_entry *entries;
    char *name;
};

struct eventhandler_snapshot {
    struct eventhandler_entry *entries;
    size_t count;
};

MALLOC_DEFINE(M_EVENTHANDLER, "eventhandler",
    "BSD bridge event handler records");

static volatile unsigned int g_eventhandler_guard;
static struct eventhandler_list *g_eventhandler_lists;

static void
eventhandler_lock(void)
{
    while (__atomic_test_and_set(&g_eventhandler_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
eventhandler_unlock(void)
{
    __atomic_clear(&g_eventhandler_guard, __ATOMIC_RELEASE);
}

static struct eventhandler_list *
eventhandler_find_unlocked(const char *name)
{
    struct eventhandler_list *list;

    for (list = g_eventhandler_lists; list; list = list->next) {
        if (bsd_strcmp(list->name, name) == 0)
            return list;
    }
    return 0;
}

struct eventhandler_list *
eventhandler_find_list(const char *name)
{
    struct eventhandler_list *list;

    if (!name)
        return 0;
    eventhandler_lock();
    list = eventhandler_find_unlocked(name);
    eventhandler_unlock();
    return list;
}

struct eventhandler_list *
eventhandler_create_list(const char *name)
{
    struct eventhandler_list *candidate;
    struct eventhandler_list *list;
    size_t length;

    if (!name || name[0] == '\0')
        return 0;
    list = eventhandler_find_list(name);
    if (list)
        return list;
    length = bsd_strlen(name) + 1;
    candidate = bsd_malloc(sizeof(*candidate) + length,
        M_EVENTHANDLER, M_WAITOK | M_ZERO);
    if (!candidate)
        return 0;
    candidate->name = (char *)(void *)(candidate + 1);
    bsd_memcpy(candidate->name, name, length);

    eventhandler_lock();
    list = eventhandler_find_unlocked(name);
    if (!list) {
        candidate->next = g_eventhandler_lists;
        g_eventhandler_lists = candidate;
        list = candidate;
        candidate = 0;
    }
    eventhandler_unlock();
    if (candidate)
        bsd_free(candidate, M_EVENTHANDLER);
    return list;
}

eventhandler_tag
eventhandler_register(struct eventhandler_list *list, const char *name,
    void *function, void *argument, int priority)
{
    struct eventhandler_entry *entry;
    struct eventhandler_entry **cursor;

    if (!function || (!list && (!name || name[0] == '\0')))
        return 0;
    if (!list)
        list = eventhandler_create_list(name);
    if (!list)
        return 0;
    entry = bsd_malloc(sizeof(*entry), M_EVENTHANDLER,
        M_WAITOK | M_ZERO);
    if (!entry)
        return 0;
    entry->list = list;
    entry->function = function;
    entry->argument = argument;
    entry->priority = priority;
    entry->active = 1;

    eventhandler_lock();
    cursor = &list->entries;
    while (*cursor && (*cursor)->priority <= priority)
        cursor = &(*cursor)->next;
    entry->next = *cursor;
    *cursor = entry;
    eventhandler_unlock();
    return entry;
}

void
eventhandler_deregister(struct eventhandler_list *list,
    eventhandler_tag tag)
{
    struct eventhandler_entry **cursor;
    struct eventhandler_entry *removed = 0;

    if (!tag)
        return;
    if (!list)
        list = tag->list;
    if (!list || list != tag->list)
        return;
    eventhandler_lock();
    for (cursor = &list->entries; *cursor; cursor = &(*cursor)->next) {
        if (*cursor == tag) {
            removed = *cursor;
            *cursor = removed->next;
            removed->active = 0;
            break;
        }
    }
    eventhandler_unlock();
    if (removed)
        bsd_free(removed, M_EVENTHANDLER);
}

void
eventhandler_deregister_nowait(struct eventhandler_list *list,
    eventhandler_tag tag)
{
    eventhandler_deregister(list, tag);
}

void
eventhandler_prune_list(struct eventhandler_list *list)
{
    (void)list;
}

size_t
bsd_eventhandler_count(const char *name)
{
    struct eventhandler_list *list;
    struct eventhandler_entry *entry;
    size_t count = 0;

    if (!name)
        return 0;
    eventhandler_lock();
    list = eventhandler_find_unlocked(name);
    for (entry = list ? list->entries : 0; entry; entry = entry->next) {
        if (entry->active)
            count++;
    }
    eventhandler_unlock();
    return count;
}

static struct eventhandler_snapshot
eventhandler_snapshot(const char *name)
{
    struct eventhandler_snapshot snapshot = {0};
    struct eventhandler_list *list;
    struct eventhandler_entry *entry;
    size_t capacity = 0;

    eventhandler_lock();
    list = eventhandler_find_unlocked(name);
    for (entry = list ? list->entries : 0; entry; entry = entry->next) {
        if (entry->active)
            capacity++;
    }
    eventhandler_unlock();
    if (capacity == 0)
        return snapshot;
    if (capacity > SIZE_MAX / sizeof(*snapshot.entries))
        bsd_bridge_panic_stop();
    snapshot.entries = bsd_malloc(capacity * sizeof(*snapshot.entries),
        M_EVENTHANDLER, M_NOWAIT);
    if (!snapshot.entries)
        bsd_bridge_panic_stop();

    eventhandler_lock();
    list = eventhandler_find_unlocked(name);
    for (entry = list ? list->entries : 0;
        entry && snapshot.count < capacity; entry = entry->next) {
        if (entry->active)
            snapshot.entries[snapshot.count++] = *entry;
    }
    eventhandler_unlock();
    return snapshot;
}

static void
eventhandler_snapshot_release(struct eventhandler_snapshot *snapshot)
{
    if (snapshot->entries)
        bsd_free(snapshot->entries, M_EVENTHANDLER);
    snapshot->entries = 0;
    snapshot->count = 0;
}

void
bsd_eventhandler_invoke_0(const char *name)
{
    struct eventhandler_snapshot snapshot = eventhandler_snapshot(name);

    for (size_t index = 0; index < snapshot.count; ++index)
        ((void (*)(void *))snapshot.entries[index].function)(
            snapshot.entries[index].argument);
    eventhandler_snapshot_release(&snapshot);
}

void
bsd_eventhandler_invoke_1(const char *name, uintptr_t argument0)
{
    struct eventhandler_snapshot snapshot = eventhandler_snapshot(name);

    for (size_t index = 0; index < snapshot.count; ++index)
        ((void (*)(void *, uintptr_t))snapshot.entries[index].function)(
            snapshot.entries[index].argument, argument0);
    eventhandler_snapshot_release(&snapshot);
}

void
bsd_eventhandler_invoke_2(const char *name, uintptr_t argument0,
    uintptr_t argument1)
{
    struct eventhandler_snapshot snapshot = eventhandler_snapshot(name);

    for (size_t index = 0; index < snapshot.count; ++index)
        ((void (*)(void *, uintptr_t, uintptr_t))
            snapshot.entries[index].function)(
            snapshot.entries[index].argument, argument0, argument1);
    eventhandler_snapshot_release(&snapshot);
}

void
bsd_eventhandler_invoke_3(const char *name, uintptr_t argument0,
    uintptr_t argument1, uintptr_t argument2)
{
    struct eventhandler_snapshot snapshot = eventhandler_snapshot(name);

    for (size_t index = 0; index < snapshot.count; ++index)
        ((void (*)(void *, uintptr_t, uintptr_t, uintptr_t))
            snapshot.entries[index].function)(
            snapshot.entries[index].argument, argument0, argument1,
            argument2);
    eventhandler_snapshot_release(&snapshot);
}
