/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux userfaultfd service.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/runtime_limits.h"
#include "kernel/userfaultfd.h"
#include "kernel/userfaultfd_runtime.h"
#include "string.h"

#define KERNEL_UFFD_PAGE_SIZE 4096u
#define KERNEL_UFFD_INDEX_NONE UINT16_MAX

typedef struct kernel_userfaultfd_context {
    uint8_t used;
    uint8_t api_ready;
    uint8_t closing;
    uint8_t padding0;
    uint16_t head;
    uint16_t tail;
    uint16_t queued_events;
    uint32_t references;
    uint32_t unresolved_faults;
    uint32_t flags;
    int32_t owner_pid;
    uint64_t address_space;
    uint64_t features;
    uint64_t readiness_sequence;
    uint64_t next_ticket;
} kernel_userfaultfd_context_t;

typedef struct kernel_userfaultfd_range {
    uint8_t used;
    uint8_t padding[3];
    int32_t context_id;
    uint64_t start;
    uint64_t end;
    uint64_t mode;
} kernel_userfaultfd_range_t;

typedef struct kernel_userfaultfd_wp_range {
    uint8_t used;
    uint8_t padding[3];
    int32_t context_id;
    uint64_t start;
    uint64_t end;
} kernel_userfaultfd_wp_range_t;

typedef struct kernel_userfaultfd_event {
    uint8_t used;
    uint8_t queued;
    uint8_t resolving;
    uint8_t padding;
    uint16_t next;
    uint16_t reserved;
    int32_t context_id;
    uint64_t page;
    uint64_t address;
    uint64_t flags;
    uint64_t ticket;
    uint32_t thread_id;
} kernel_userfaultfd_event_t;

static kernel_userfaultfd_context_t
    g_userfaultfd_contexts[EDGE_RUNTIME_MAX_USERFAULTFDS];
static kernel_userfaultfd_range_t
    g_userfaultfd_ranges[EDGE_RUNTIME_MAX_USERFAULTFD_RANGES];
static kernel_userfaultfd_wp_range_t
    g_userfaultfd_wp_ranges[EDGE_RUNTIME_MAX_USERFAULTFD_RANGES];
static kernel_userfaultfd_event_t
    g_userfaultfd_events[EDGE_RUNTIME_USERFAULTFD_EVENT_POOL];
static volatile uint32_t g_userfaultfd_lock;

static void userfaultfd_lock(void) {
    while (__sync_lock_test_and_set(&g_userfaultfd_lock, 1u)) { }
}

static void userfaultfd_unlock(void) {
    __sync_lock_release(&g_userfaultfd_lock);
}

static int userfaultfd_range_valid(const kernel_uffdio_range_t *range) {
    return range && range->length &&
           !(range->start & (KERNEL_UFFD_PAGE_SIZE - 1u)) &&
           !(range->length & (KERNEL_UFFD_PAGE_SIZE - 1u)) &&
           range->start <= UINT64_MAX - range->length;
}

static kernel_userfaultfd_context_t *userfaultfd_context_locked(
    int context_id) {
    if (context_id < 0 ||
        context_id >= EDGE_RUNTIME_MAX_USERFAULTFDS ||
        !g_userfaultfd_contexts[context_id].used ||
        g_userfaultfd_contexts[context_id].closing)
        return 0;
    return &g_userfaultfd_contexts[context_id];
}

static int userfaultfd_registered_range_covers_locked(
        int context_id, uint64_t start, uint64_t end,
        uint64_t required_mode) {
    uint64_t cursor = start;

    while (cursor < end) {
        uint64_t next = cursor;
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
            kernel_userfaultfd_range_t *range =
                &g_userfaultfd_ranges[index];
            if (!range->used || range->context_id != context_id ||
                cursor < range->start || cursor >= range->end ||
                (range->mode & required_mode) != required_mode)
                continue;
            if (range->end > next) next = range->end;
        }
        if (next == cursor) return 0;
        cursor = next < end ? next : end;
    }
    return 1;
}

static int userfaultfd_wp_page_active_locked(int context_id,
                                             uint64_t page) {
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_wp_range_t *range =
            &g_userfaultfd_wp_ranges[index];
        if (range->used && range->context_id == context_id &&
            page >= range->start && page < range->end)
            return 1;
    }
    return 0;
}

static int userfaultfd_wp_add_locked(int context_id, uint64_t start,
                                     uint64_t end) {
    kernel_userfaultfd_wp_range_t *target = 0;
    kernel_userfaultfd_wp_range_t *free_range = 0;
    uint64_t merged_start = start;
    uint64_t merged_end = end;

    for (;;) {
        int expanded = 0;
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
            kernel_userfaultfd_wp_range_t *range =
                &g_userfaultfd_wp_ranges[index];
            if (!range->used) {
                if (!free_range) free_range = range;
                continue;
            }
            if (range->context_id != context_id ||
                range->end < merged_start || range->start > merged_end)
                continue;
            if (!target) target = range;
            if (range->start < merged_start) {
                merged_start = range->start;
                expanded = 1;
            }
            if (range->end > merged_end) {
                merged_end = range->end;
                expanded = 1;
            }
        }
        if (!expanded) break;
    }
    if (!target) target = free_range;
    if (!target) return -EDGE_LINUX_ENOSPC;
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_wp_range_t *range =
            &g_userfaultfd_wp_ranges[index];
        if (range == target || !range->used ||
            range->context_id != context_id ||
            range->end < merged_start || range->start > merged_end)
            continue;
        memset(range, 0, sizeof(*range));
    }
    memset(target, 0, sizeof(*target));
    target->used = 1;
    target->context_id = context_id;
    target->start = merged_start;
    target->end = merged_end;
    return 0;
}

static int userfaultfd_wp_remove_locked(int context_id, uint64_t start,
                                        uint64_t end) {
    kernel_userfaultfd_wp_range_t *split = 0;
    kernel_userfaultfd_wp_range_t *free_range = 0;
    uint64_t split_end = 0;

    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_wp_range_t *range =
            &g_userfaultfd_wp_ranges[index];
        if (!range->used) {
            if (!free_range) free_range = range;
            continue;
        }
        if (range->context_id == context_id &&
            start > range->start && end < range->end)
            split = range;
    }
    if (split && !free_range) return -EDGE_LINUX_ENOSPC;
    if (split) split_end = split->end;
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_wp_range_t *range =
            &g_userfaultfd_wp_ranges[index];
        if (!range->used || range->context_id != context_id ||
            start >= range->end || end <= range->start)
            continue;
        if (start <= range->start && end >= range->end) {
            memset(range, 0, sizeof(*range));
        } else if (start <= range->start) {
            range->start = end;
        } else if (end >= range->end) {
            range->end = start;
        } else {
            range->end = start;
        }
    }
    if (split) {
        memset(free_range, 0, sizeof(*free_range));
        free_range->used = 1;
        free_range->context_id = context_id;
        free_range->start = end;
        free_range->end = split_end;
    }
    return 0;
}

static int userfaultfd_unregister_capacity_locked(
        int context_id, uint64_t start, uint64_t end) {
    uint16_t free_registered = 0;
    uint16_t split_registered = 0;
    uint16_t free_writeprotected = 0;
    uint16_t split_writeprotected = 0;

    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *registered =
            &g_userfaultfd_ranges[index];
        kernel_userfaultfd_wp_range_t *writeprotected =
            &g_userfaultfd_wp_ranges[index];

        if (!registered->used)
            ++free_registered;
        else if (registered->context_id == context_id &&
                 start > registered->start && end < registered->end)
            ++split_registered;
        if (!writeprotected->used)
            ++free_writeprotected;
        else if (writeprotected->context_id == context_id &&
                 start > writeprotected->start &&
                 end < writeprotected->end)
            ++split_writeprotected;
    }
    if (split_registered > free_registered ||
        split_writeprotected > free_writeprotected)
        return -EDGE_LINUX_ENOSPC;
    return 0;
}

static void userfaultfd_sequence_advance(
    kernel_userfaultfd_context_t *context) {
    ++context->readiness_sequence;
    if (!context->readiness_sequence) context->readiness_sequence = 1u;
}

static uint16_t userfaultfd_event_allocate_locked(void) {
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        if (g_userfaultfd_events[index].used) continue;
        memset(&g_userfaultfd_events[index], 0,
               sizeof(g_userfaultfd_events[index]));
        g_userfaultfd_events[index].used = 1;
        g_userfaultfd_events[index].next = KERNEL_UFFD_INDEX_NONE;
        return index;
    }
    return KERNEL_UFFD_INDEX_NONE;
}

static void userfaultfd_event_free_locked(uint16_t index) {
    if (index >= EDGE_RUNTIME_USERFAULTFD_EVENT_POOL) return;
    memset(&g_userfaultfd_events[index], 0,
           sizeof(g_userfaultfd_events[index]));
    g_userfaultfd_events[index].next = KERNEL_UFFD_INDEX_NONE;
}

static void userfaultfd_remove_queued_event_locked(
    kernel_userfaultfd_context_t *context, uint16_t target) {
    uint16_t previous = KERNEL_UFFD_INDEX_NONE;
    uint16_t current = context->head;

    while (current != KERNEL_UFFD_INDEX_NONE) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[current];
        if (current == target) {
            if (previous == KERNEL_UFFD_INDEX_NONE)
                context->head = event->next;
            else
                g_userfaultfd_events[previous].next = event->next;
            if (context->tail == current) context->tail = previous;
            event->queued = 0;
            event->next = KERNEL_UFFD_INDEX_NONE;
            if (context->queued_events) --context->queued_events;
            return;
        }
        previous = current;
        current = event->next;
    }
}

int kernel_userfaultfd_create(uint64_t address_space, int32_t owner_pid,
                              uint32_t flags) {
    uint32_t allowed = KERNEL_UFFD_CLOEXEC | KERNEL_UFFD_NONBLOCK |
                       KERNEL_UFFD_USER_MODE_ONLY;
    int result = -EDGE_LINUX_EMFILE;

    if (!address_space || owner_pid <= 0 || (flags & ~allowed))
        return -EDGE_LINUX_EINVAL;
    userfaultfd_lock();
    for (int index = 0; index < EDGE_RUNTIME_MAX_USERFAULTFDS; ++index) {
        kernel_userfaultfd_context_t *context =
            &g_userfaultfd_contexts[index];
        if (context->used) continue;
        memset(context, 0, sizeof(*context));
        context->used = 1;
        context->references = 1;
        context->flags = flags;
        context->owner_pid = owner_pid;
        context->address_space = address_space;
        context->head = KERNEL_UFFD_INDEX_NONE;
        context->tail = KERNEL_UFFD_INDEX_NONE;
        context->next_ticket = 1u;
        result = index;
        break;
    }
    userfaultfd_unlock();
    return result;
}

int kernel_userfaultfd_retain(int context_id) {
    kernel_userfaultfd_context_t *context;
    int result = -EDGE_LINUX_EBADF;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (context && context->references != UINT32_MAX) {
        ++context->references;
        result = 0;
    }
    userfaultfd_unlock();
    return result;
}

void kernel_userfaultfd_release(int context_id) {
    kernel_userfaultfd_context_t *context;
    uint64_t address_space = 0;
    int notify = 0;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context || !context->references) {
        userfaultfd_unlock();
        return;
    }
    if (--context->references) {
        userfaultfd_unlock();
        return;
    }
    context->closing = 1;
    address_space = context->address_space;
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        if (event->used && event->context_id == context_id)
            userfaultfd_event_free_locked(index);
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        if (g_userfaultfd_ranges[index].used &&
            g_userfaultfd_ranges[index].context_id == context_id)
            memset(&g_userfaultfd_ranges[index], 0,
                   sizeof(g_userfaultfd_ranges[index]));
    }
    userfaultfd_unlock();

    for (;;) {
        kernel_userfaultfd_wp_range_t restore;
        int found = 0;

        memset(&restore, 0, sizeof(restore));
        userfaultfd_lock();
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
            kernel_userfaultfd_wp_range_t *range =
                &g_userfaultfd_wp_ranges[index];
            if (!range->used || range->context_id != context_id)
                continue;
            restore = *range;
            memset(range, 0, sizeof(*range));
            found = 1;
            break;
        }
        userfaultfd_unlock();
        if (!found) break;
        (void)arch_mm_address_space_write_protect(
            address_space, restore.start,
            restore.end - restore.start, 0);
    }

    userfaultfd_lock();
    context = &g_userfaultfd_contexts[context_id];
    if (context->used && context->closing) {
        memset(context, 0, sizeof(*context));
        notify = 1;
    }
    userfaultfd_unlock();
    if (notify) kernel_userfaultfd_state_changed(context_id);
}

int kernel_userfaultfd_query(int context_id,
                             kernel_userfaultfd_state_t *state) {
    kernel_userfaultfd_context_t *context;
    if (!state) return -EDGE_LINUX_EINVAL;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    memset(state, 0, sizeof(*state));
    state->references = context->references;
    state->queued_events = context->queued_events;
    state->unresolved_faults = context->unresolved_faults;
    state->api_ready = context->api_ready;
    state->readiness_sequence = context->readiness_sequence;
    state->address_space = context->address_space;
    state->owner_pid = context->owner_pid;
    userfaultfd_unlock();
    return 0;
}

int kernel_userfaultfd_negotiate(int context_id,
                                 kernel_uffdio_api_t *api) {
    kernel_userfaultfd_context_t *context;
    uint64_t requested_features;
    int result = 0;
    if (!api) return -EDGE_LINUX_EINVAL;
    requested_features = api->features;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        result = -EDGE_LINUX_EBADF;
    } else if (context->api_ready || api->api != KERNEL_UFFD_API ||
               (requested_features & ~KERNEL_UFFD_SUPPORTED_FEATURES)) {
        memset(api, 0, sizeof(*api));
        result = -EDGE_LINUX_EINVAL;
    } else {
        if (requested_features & KERNEL_UFFD_FEATURE_WP_ASYNC)
            requested_features |= KERNEL_UFFD_FEATURE_WP_UNPOPULATED;
        context->api_ready = 1;
        context->features = requested_features;
        api->features = KERNEL_UFFD_SUPPORTED_FEATURES;
        api->ioctls = KERNEL_UFFD_API_IOCTLS;
    }
    userfaultfd_unlock();
    return result;
}

int kernel_userfaultfd_register(int context_id,
                                kernel_uffdio_register_t *registration) {
    kernel_userfaultfd_context_t *context;
    kernel_userfaultfd_range_t *free_range = 0;
    uint64_t end;
    int result = 0;

    if (!registration || !userfaultfd_range_valid(&registration->range) ||
        !registration->mode ||
        (registration->mode &
         ~(KERNEL_UFFD_REGISTER_MODE_MISSING |
           KERNEL_UFFD_REGISTER_MODE_WP |
           KERNEL_UFFD_REGISTER_MODE_MINOR)))
        return -EDGE_LINUX_EINVAL;
    end = registration->range.start + registration->range.length;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        result = -EDGE_LINUX_EBADF;
        goto out;
    }
    if (!context->api_ready) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *range = &g_userfaultfd_ranges[index];
        if (!range->used) {
            if (!free_range) free_range = range;
            continue;
        }
        if (registration->range.start < range->end && end > range->start) {
            kernel_userfaultfd_context_t *owner =
                userfaultfd_context_locked(range->context_id);
            if (owner && owner->address_space == context->address_space) {
                result = -EDGE_LINUX_EBUSY;
                goto out;
            }
        }
    }
    if (!free_range) {
        result = -EDGE_LINUX_ENOSPC;
        goto out;
    }
    memset(free_range, 0, sizeof(*free_range));
    free_range->used = 1;
    free_range->context_id = context_id;
    free_range->start = registration->range.start;
    free_range->end = end;
    free_range->mode = registration->mode;
    registration->ioctls = 0;
    if (registration->mode & (KERNEL_UFFD_REGISTER_MODE_MISSING |
                              KERNEL_UFFD_REGISTER_MODE_MINOR))
        registration->ioctls |= KERNEL_UFFD_RANGE_IOCTLS;
    if (!(registration->mode & KERNEL_UFFD_REGISTER_MODE_MINOR))
        registration->ioctls &=
            ~(1ULL << KERNEL_UFFDIO_CONTINUE_NUMBER);
    if (registration->mode & KERNEL_UFFD_REGISTER_MODE_WP)
        registration->ioctls |= KERNEL_UFFD_WP_RANGE_IOCTLS;
out:
    userfaultfd_unlock();
    return result;
}

int kernel_userfaultfd_unregister(int context_id,
                                  const kernel_uffdio_range_t *range) {
    kernel_userfaultfd_context_t *context;
    uint64_t end;

    if (!userfaultfd_range_valid(range)) return -EDGE_LINUX_EINVAL;
    end = range->start + range->length;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (userfaultfd_unregister_capacity_locked(
            context_id, range->start, end) < 0) {
        userfaultfd_unlock();
        return -EDGE_LINUX_ENOSPC;
    }
    {
        int wp_result = userfaultfd_wp_remove_locked(
            context_id, range->start, end);
        if (wp_result < 0) {
            userfaultfd_unlock();
            return wp_result;
        }
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *entry = &g_userfaultfd_ranges[index];
        uint64_t old_end;

        if (!entry->used || entry->context_id != context_id ||
            range->start >= entry->end || end <= entry->start)
            continue;
        if (range->start <= entry->start && end >= entry->end) {
            memset(entry, 0, sizeof(*entry));
            continue;
        }
        if (range->start <= entry->start) {
            entry->start = end;
            continue;
        }
        if (end >= entry->end) {
            entry->end = range->start;
            continue;
        }
        old_end = entry->end;
        entry->end = range->start;
        for (uint16_t free_index = 0;
             free_index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES;
             ++free_index) {
            kernel_userfaultfd_range_t *right =
                &g_userfaultfd_ranges[free_index];
            if (right->used) continue;
            right->used = 1;
            right->context_id = context_id;
            right->start = end;
            right->end = old_end;
            right->mode = entry->mode;
            break;
        }
    }
    userfaultfd_unlock();
    (void)kernel_userfaultfd_resolve(context_id, range);
    return 0;
}

int kernel_userfaultfd_unregister_validate(
        int context_id, const kernel_uffdio_range_t *range,
        uint64_t *address_space) {
    kernel_userfaultfd_context_t *context;
    uint64_t end;
    int result;

    if (!address_space || !userfaultfd_range_valid(range))
        return -EDGE_LINUX_EINVAL;
    end = range->start + range->length;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    result = userfaultfd_unregister_capacity_locked(
        context_id, range->start, end);
    *address_space = context->address_space;
    userfaultfd_unlock();
    return result;
}

int kernel_userfaultfd_validate_resolution(
    int context_id, const kernel_uffdio_range_t *range, uint64_t mode,
    uint64_t *address_space) {
    kernel_userfaultfd_context_t *context;
    uint64_t end;
    int covered = 0;

    if (!address_space ||
        (mode & ~(KERNEL_UFFDIO_MODE_DONTWAKE |
                  KERNEL_UFFDIO_COPY_MODE_WP)) ||
        !userfaultfd_range_valid(range))
        return -EDGE_LINUX_EINVAL;
    end = range->start + range->length;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *entry = &g_userfaultfd_ranges[index];
        if (entry->used && entry->context_id == context_id &&
            (entry->mode & KERNEL_UFFD_REGISTER_MODE_MISSING) &&
            range->start >= entry->start && end <= entry->end) {
            covered = 1;
            break;
        }
    }
    if (covered) {
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
            kernel_userfaultfd_event_t *event =
                &g_userfaultfd_events[index];
            if (event->used && event->context_id == context_id &&
                event->page >= range->start && event->page < end)
                event->resolving = 1;
        }
    }
    *address_space = context->address_space;
    userfaultfd_unlock();
    return covered ? 0 : -EDGE_LINUX_ENOENT;
}

int kernel_userfaultfd_cancel_resolution(
    int context_id, const kernel_uffdio_range_t *range) {
    uint64_t end;
    int changed = 0;

    if (!userfaultfd_range_valid(range)) return -EDGE_LINUX_EINVAL;
    end = range->start + range->length;
    userfaultfd_lock();
    if (!userfaultfd_context_locked(context_id)) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        if (event->used && event->context_id == context_id &&
            event->page >= range->start && event->page < end &&
            event->resolving) {
            event->resolving = 0;
            changed = 1;
        }
    }
    userfaultfd_unlock();
    return changed;
}

int kernel_userfaultfd_continue_validate(
    int context_id, const kernel_uffdio_range_t *range, uint64_t mode,
    uint64_t *address_space) {
    kernel_userfaultfd_context_t *context;
    uint64_t end;
    int covered;

    if (!address_space || !userfaultfd_range_valid(range) ||
        (mode & ~(KERNEL_UFFDIO_CONTINUE_MODE_DONTWAKE |
                  KERNEL_UFFDIO_CONTINUE_MODE_WP)))
        return -EDGE_LINUX_EINVAL;
    end = range->start + range->length;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    covered = userfaultfd_registered_range_covers_locked(
        context_id, range->start, end,
        KERNEL_UFFD_REGISTER_MODE_MINOR);
    if (covered) {
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
            kernel_userfaultfd_event_t *event =
                &g_userfaultfd_events[index];
            if (event->used && event->context_id == context_id &&
                event->page >= range->start && event->page < end &&
                (event->flags & KERNEL_UFFD_PAGEFAULT_FLAG_MINOR))
                event->resolving = 1;
        }
    }
    *address_space = context->address_space;
    userfaultfd_unlock();
    return covered ? 0 : -EDGE_LINUX_ENOENT;
}

static int userfaultfd_resolve_events(
    int context_id, const kernel_uffdio_range_t *range,
    uint64_t required_flags) {
    kernel_userfaultfd_context_t *context;
    uint64_t end;
    int resolved = 0;

    if (!userfaultfd_range_valid(range)) return -EDGE_LINUX_EINVAL;
    end = range->start + range->length;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        if (!event->used || event->context_id != context_id ||
            event->page < range->start || event->page >= end ||
            (event->flags & required_flags) != required_flags)
            continue;
        if (event->queued)
            userfaultfd_remove_queued_event_locked(context, index);
        userfaultfd_event_free_locked(index);
        if (context->unresolved_faults) --context->unresolved_faults;
        ++resolved;
    }
    if (resolved) userfaultfd_sequence_advance(context);
    userfaultfd_unlock();
    if (resolved) kernel_userfaultfd_state_changed(context_id);
    return resolved;
}

int kernel_userfaultfd_continue_resolve(
    int context_id, const kernel_uffdio_range_t *range) {
    return userfaultfd_resolve_events(
        context_id, range, KERNEL_UFFD_PAGEFAULT_FLAG_MINOR);
}

int kernel_userfaultfd_writeprotect_validate(
        int context_id, const kernel_uffdio_range_t *range, uint64_t mode,
        uint64_t *address_space) {
    kernel_userfaultfd_context_t *context;
    uint64_t end;
    int covered;

    if (!address_space || !userfaultfd_range_valid(range) ||
        (mode & ~(KERNEL_UFFDIO_WRITEPROTECT_MODE_WP |
                  KERNEL_UFFDIO_WRITEPROTECT_MODE_DONTWAKE)) ||
        (mode & KERNEL_UFFDIO_WRITEPROTECT_MODE_WP &&
         mode & KERNEL_UFFDIO_WRITEPROTECT_MODE_DONTWAKE))
        return -EDGE_LINUX_EINVAL;
    end = range->start + range->length;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    covered = userfaultfd_registered_range_covers_locked(
        context_id, range->start, end, KERNEL_UFFD_REGISTER_MODE_WP);
    *address_space = context->address_space;
    userfaultfd_unlock();
    return covered ? 0 : -EDGE_LINUX_ENOENT;
}

int kernel_userfaultfd_writeprotect_intersects(
        int context_id, const kernel_uffdio_range_t *range,
        uint64_t *address_space) {
    kernel_userfaultfd_context_t *context;
    uint64_t end;
    int intersects = 0;

    if (!address_space || !userfaultfd_range_valid(range))
        return -EDGE_LINUX_EINVAL;
    end = range->start + range->length;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_wp_range_t *entry =
            &g_userfaultfd_wp_ranges[index];
        if (entry->used && entry->context_id == context_id &&
            range->start < entry->end && end > entry->start) {
            intersects = 1;
            break;
        }
    }
    *address_space = context->address_space;
    userfaultfd_unlock();
    return intersects;
}

int kernel_userfaultfd_writeprotect_commit(
        int context_id, const kernel_uffdio_range_t *range, uint64_t mode) {
    kernel_userfaultfd_context_t *context;
    uint64_t end;
    int result;
    int wake;

    if (!userfaultfd_range_valid(range) ||
        (mode & ~(KERNEL_UFFDIO_WRITEPROTECT_MODE_WP |
                  KERNEL_UFFDIO_WRITEPROTECT_MODE_DONTWAKE)))
        return -EDGE_LINUX_EINVAL;
    end = range->start + range->length;
    wake = !(mode & KERNEL_UFFDIO_WRITEPROTECT_MODE_DONTWAKE);
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (!userfaultfd_registered_range_covers_locked(
            context_id, range->start, end,
            KERNEL_UFFD_REGISTER_MODE_WP)) {
        userfaultfd_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    if (mode & KERNEL_UFFDIO_WRITEPROTECT_MODE_WP)
        result = userfaultfd_wp_add_locked(
            context_id, range->start, end);
    else
        result = userfaultfd_wp_remove_locked(
            context_id, range->start, end);
    userfaultfd_unlock();
    if (result == 0 && wake &&
        !(mode & KERNEL_UFFDIO_WRITEPROTECT_MODE_WP))
        (void)kernel_userfaultfd_resolve(context_id, range);
    return result;
}

void kernel_userfaultfd_mapping_unmap(
        uint64_t address_space, const kernel_uffdio_range_t *range) {
    uint8_t affected[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t end;

    if (!address_space || !userfaultfd_range_valid(range)) return;
    end = range->start + range->length;
    memset(affected, 0, sizeof(affected));
    userfaultfd_lock();
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *entry = &g_userfaultfd_ranges[index];
        kernel_userfaultfd_context_t *context;
        uint64_t old_end;

        if (!entry->used || range->start >= entry->end ||
            end <= entry->start)
            continue;
        context = userfaultfd_context_locked(entry->context_id);
        if (!context || context->address_space != address_space)
            continue;
        affected[entry->context_id] = 1u;
        if (range->start <= entry->start && end >= entry->end) {
            memset(entry, 0, sizeof(*entry));
            continue;
        }
        if (range->start <= entry->start) {
            entry->start = end;
            continue;
        }
        if (end >= entry->end) {
            entry->end = range->start;
            continue;
        }
        old_end = entry->end;
        entry->end = range->start;
        for (uint16_t free_index = 0;
             free_index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES;
             ++free_index) {
            kernel_userfaultfd_range_t *right =
                &g_userfaultfd_ranges[free_index];
            if (right->used) continue;
            right->used = 1u;
            right->context_id = entry->context_id;
            right->start = end;
            right->end = old_end;
            right->mode = entry->mode;
            break;
        }
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_wp_range_t *entry =
            &g_userfaultfd_wp_ranges[index];
        kernel_userfaultfd_context_t *context;
        uint64_t old_end;

        if (!entry->used || range->start >= entry->end ||
            end <= entry->start)
            continue;
        context = userfaultfd_context_locked(entry->context_id);
        if (!context || context->address_space != address_space)
            continue;
        affected[entry->context_id] = 1u;
        if (range->start <= entry->start && end >= entry->end) {
            memset(entry, 0, sizeof(*entry));
            continue;
        }
        if (range->start <= entry->start) {
            entry->start = end;
            continue;
        }
        if (end >= entry->end) {
            entry->end = range->start;
            continue;
        }
        old_end = entry->end;
        entry->end = range->start;
        for (uint16_t free_index = 0;
             free_index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES;
             ++free_index) {
            kernel_userfaultfd_wp_range_t *right =
                &g_userfaultfd_wp_ranges[free_index];
            if (right->used) continue;
            right->used = 1u;
            right->context_id = entry->context_id;
            right->start = end;
            right->end = old_end;
            break;
        }
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        kernel_userfaultfd_context_t *context;

        if (!event->used || event->page < range->start ||
            event->page >= end)
            continue;
        context = userfaultfd_context_locked(event->context_id);
        if (!context || context->address_space != address_space)
            continue;
        affected[event->context_id] = 1u;
        if (event->queued)
            userfaultfd_remove_queued_event_locked(context, index);
        userfaultfd_event_free_locked(index);
        if (context->unresolved_faults) --context->unresolved_faults;
    }
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id) {
        kernel_userfaultfd_context_t *context;
        if (!affected[context_id]) continue;
        context = userfaultfd_context_locked(context_id);
        if (context) userfaultfd_sequence_advance(context);
    }
    userfaultfd_unlock();
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id)
        if (affected[context_id])
            kernel_userfaultfd_state_changed(context_id);
}

int kernel_userfaultfd_resolve(int context_id,
                               const kernel_uffdio_range_t *range) {
    return userfaultfd_resolve_events(context_id, range, 0);
}

int kernel_userfaultfd_page_fault(
    uint64_t address_space, uint64_t address, int write, int present,
    uint32_t thread_id, int *context_id, uint64_t *ticket) {
    kernel_userfaultfd_context_t *context = 0;
    uint64_t page = address & ~(uint64_t)(KERNEL_UFFD_PAGE_SIZE - 1u);
    uint16_t event_index;
    int found_context = -1;
    int writeprotect_fault = 0;
    int minor_fault = 0;
    int shmem_page_state = 0;

    if (!address_space || !context_id || !ticket)
        return -EDGE_LINUX_EINVAL;
    if (!present)
        shmem_page_state = arch_mm_address_space_shmem_page_state(
            address_space, page);
    userfaultfd_lock();
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *range = &g_userfaultfd_ranges[index];
        int missing_fault;
        int backed_minor_fault;
        int protected_write;

        if (!range->used || page < range->start || page >= range->end)
            continue;
        backed_minor_fault = !present && shmem_page_state > 0 &&
            (range->mode & KERNEL_UFFD_REGISTER_MODE_MINOR);
        missing_fault = !present && !backed_minor_fault &&
            (range->mode & KERNEL_UFFD_REGISTER_MODE_MISSING);
        protected_write = write &&
            (range->mode & KERNEL_UFFD_REGISTER_MODE_WP) &&
            userfaultfd_wp_page_active_locked(range->context_id, page);
        if (!missing_fault && !backed_minor_fault && !protected_write)
            continue;
        context = userfaultfd_context_locked(range->context_id);
        if (context && context->api_ready &&
            context->address_space == address_space) {
            found_context = range->context_id;
            writeprotect_fault = protected_write;
            minor_fault = backed_minor_fault;
            break;
        }
    }
    if (!context) {
        userfaultfd_unlock();
        return 0;
    }
    if (writeprotect_fault &&
        (context->features & KERNEL_UFFD_FEATURE_WP_ASYNC)) {
        int result = userfaultfd_wp_remove_locked(
            found_context, page, page + KERNEL_UFFD_PAGE_SIZE);
        if (result == 0) userfaultfd_sequence_advance(context);
        userfaultfd_unlock();
        if (result == 0)
            result = arch_mm_address_space_write_protect(
                address_space, page, KERNEL_UFFD_PAGE_SIZE, 0);
        if (result < 0) {
            userfaultfd_lock();
            context = userfaultfd_context_locked(found_context);
            if (context)
                (void)userfaultfd_wp_add_locked(
                    found_context, page,
                    page + KERNEL_UFFD_PAGE_SIZE);
            userfaultfd_unlock();
        } else {
            kernel_userfaultfd_state_changed(found_context);
        }
        return result;
    }
    if (context->features & KERNEL_UFFD_FEATURE_SIGBUS) {
        userfaultfd_unlock();
        return KERNEL_UFFD_FAULT_SIGBUS;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        if (!event->used || event->context_id != found_context ||
            event->page != page)
            continue;
        if (write) event->flags |= KERNEL_UFFD_PAGEFAULT_FLAG_WRITE;
        if (writeprotect_fault)
            event->flags |= KERNEL_UFFD_PAGEFAULT_FLAG_WP;
        if (minor_fault)
            event->flags |= KERNEL_UFFD_PAGEFAULT_FLAG_MINOR;
        *context_id = found_context;
        *ticket = event->ticket;
        userfaultfd_unlock();
        return 1;
    }
    event_index = userfaultfd_event_allocate_locked();
    if (event_index == KERNEL_UFFD_INDEX_NONE) {
        userfaultfd_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    g_userfaultfd_events[event_index].context_id = found_context;
    g_userfaultfd_events[event_index].page = page;
    g_userfaultfd_events[event_index].address =
        (context->features & KERNEL_UFFD_FEATURE_EXACT_ADDRESS) ?
            address : page;
    g_userfaultfd_events[event_index].flags =
        write ? KERNEL_UFFD_PAGEFAULT_FLAG_WRITE : 0u;
    if (writeprotect_fault)
        g_userfaultfd_events[event_index].flags |=
            KERNEL_UFFD_PAGEFAULT_FLAG_WP;
    if (minor_fault)
        g_userfaultfd_events[event_index].flags |=
            KERNEL_UFFD_PAGEFAULT_FLAG_MINOR;
    g_userfaultfd_events[event_index].ticket = context->next_ticket++;
    if (context->features & KERNEL_UFFD_FEATURE_THREAD_ID)
        g_userfaultfd_events[event_index].thread_id = thread_id;
    if (!context->next_ticket) context->next_ticket = 1u;
    g_userfaultfd_events[event_index].queued = 1;
    if (context->tail == KERNEL_UFFD_INDEX_NONE)
        context->head = event_index;
    else
        g_userfaultfd_events[context->tail].next = event_index;
    context->tail = event_index;
    ++context->queued_events;
    ++context->unresolved_faults;
    userfaultfd_sequence_advance(context);
    *context_id = found_context;
    *ticket = g_userfaultfd_events[event_index].ticket;
    userfaultfd_unlock();
    kernel_userfaultfd_state_changed(found_context);
    return KERNEL_UFFD_FAULT_QUEUED;
}

int kernel_userfaultfd_apply_writeprotect(
        uint64_t address_space, uint64_t address) {
    uint64_t page = address & ~(uint64_t)(KERNEL_UFFD_PAGE_SIZE - 1u);
    int active = 0;

    if (!address_space) return -EDGE_LINUX_EINVAL;
    userfaultfd_lock();
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *range = &g_userfaultfd_ranges[index];
        kernel_userfaultfd_context_t *context;

        if (!range->used || page < range->start || page >= range->end ||
            !(range->mode & KERNEL_UFFD_REGISTER_MODE_WP) ||
            !userfaultfd_wp_page_active_locked(range->context_id, page))
            continue;
        context = userfaultfd_context_locked(range->context_id);
        if (context && context->api_ready &&
            context->address_space == address_space &&
            (context->features & KERNEL_UFFD_FEATURE_WP_UNPOPULATED)) {
            active = 1;
            break;
        }
    }
    userfaultfd_unlock();
    if (!active) return 0;
    return arch_mm_address_space_write_protect(
        address_space, page, KERNEL_UFFD_PAGE_SIZE, 1);
}

int kernel_userfaultfd_missing_fault(
    uint64_t address_space, uint64_t address, int write, uint32_t thread_id,
    int *context_id, uint64_t *ticket) {
    return kernel_userfaultfd_page_fault(
        address_space, address, write, 0, thread_id,
        context_id, ticket);
}

int kernel_userfaultfd_fault_pending(int context_id, uint64_t ticket) {
    int pending = 0;
    userfaultfd_lock();
    if (!userfaultfd_context_locked(context_id)) {
        userfaultfd_unlock();
        return 0;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        if (event->used && event->context_id == context_id &&
            event->ticket == ticket) {
            pending = 1;
            break;
        }
    }
    userfaultfd_unlock();
    return pending;
}

int kernel_userfaultfd_resolution_bypasses_fault(
    uint64_t address_space, uint64_t address) {
    uint64_t page = address & ~(uint64_t)(KERNEL_UFFD_PAGE_SIZE - 1u);
    int bypass = 0;

    userfaultfd_lock();
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        kernel_userfaultfd_context_t *context;
        if (!event->used || !event->resolving || event->page != page)
            continue;
        context = userfaultfd_context_locked(event->context_id);
        if (context && context->address_space == address_space) {
            bypass = 1;
            break;
        }
    }
    userfaultfd_unlock();
    return bypass;
}

int64_t kernel_userfaultfd_read(
    int context_id, kernel_userfaultfd_copy_record_fn copy_record,
    void *copy_context, uint64_t length) {
    kernel_userfaultfd_context_t *context;
    kernel_userfaultfd_message_t message;
    uint16_t event_index;

    if (!copy_record) return -EDGE_LINUX_EFAULT;
    if (length < sizeof(message)) return -EDGE_LINUX_EINVAL;
    userfaultfd_lock();
    context = userfaultfd_context_locked(context_id);
    if (!context) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (!context->api_ready) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    event_index = context->head;
    if (event_index == KERNEL_UFFD_INDEX_NONE) {
        userfaultfd_unlock();
        return -EDGE_LINUX_EAGAIN;
    }
    memset(&message, 0, sizeof(message));
    message.event = KERNEL_UFFD_EVENT_PAGEFAULT;
    message.flags = g_userfaultfd_events[event_index].flags;
    message.address = g_userfaultfd_events[event_index].address;
    message.thread_id = g_userfaultfd_events[event_index].thread_id;
    userfaultfd_remove_queued_event_locked(context, event_index);
    userfaultfd_unlock();
    if (copy_record(copy_context, 0, &message, sizeof(message)) < 0) {
        userfaultfd_lock();
        context = userfaultfd_context_locked(context_id);
        if (context && g_userfaultfd_events[event_index].used &&
            !g_userfaultfd_events[event_index].queued) {
            g_userfaultfd_events[event_index].queued = 1;
            g_userfaultfd_events[event_index].next = context->head;
            context->head = event_index;
            if (context->tail == KERNEL_UFFD_INDEX_NONE)
                context->tail = event_index;
            ++context->queued_events;
        }
        userfaultfd_unlock();
        return -EDGE_LINUX_EFAULT;
    }
    return sizeof(message);
}
