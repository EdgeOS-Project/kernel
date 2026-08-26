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
    uint8_t page_shift;
    uint8_t padding[2];
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
    uint8_t event_type;
    uint16_t next;
    uint16_t reserved;
    int32_t context_id;
    uint64_t page;
    uint64_t address;
    uint64_t flags;
    uint64_t ticket;
    uint32_t thread_id;
    uint32_t padding;
    uint64_t notification_start;
    uint64_t notification_end;
    uint64_t notification_extra;
} kernel_userfaultfd_event_t;

typedef struct kernel_userfaultfd_remap_notifications {
    uint8_t remap[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t destination_unmap_start[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t destination_unmap_end[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t source_unmap_start[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t source_unmap_end[EDGE_RUNTIME_MAX_USERFAULTFDS];
} kernel_userfaultfd_remap_notifications_t;

static kernel_userfaultfd_context_t
    g_userfaultfd_contexts[EDGE_RUNTIME_MAX_USERFAULTFDS];
static kernel_userfaultfd_range_t
    g_userfaultfd_ranges[EDGE_RUNTIME_MAX_USERFAULTFD_RANGES];
static kernel_userfaultfd_wp_range_t
    g_userfaultfd_wp_ranges[EDGE_RUNTIME_MAX_USERFAULTFD_RANGES];
static kernel_userfaultfd_range_t
    g_userfaultfd_remap_ranges[EDGE_RUNTIME_MAX_USERFAULTFD_RANGES * 3u];
static kernel_userfaultfd_wp_range_t
    g_userfaultfd_remap_wp_ranges[
        EDGE_RUNTIME_MAX_USERFAULTFD_RANGES * 3u];
static kernel_userfaultfd_remap_notifications_t
    g_userfaultfd_remap_notifications;
static kernel_userfaultfd_event_t
    g_userfaultfd_events[EDGE_RUNTIME_USERFAULTFD_EVENT_POOL];
static volatile uint32_t g_userfaultfd_lock;
static uint64_t g_userfaultfd_next_transaction = 1u;

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

static void userfaultfd_complete_fork_transaction_locked(
        uint16_t event_index,
        uint8_t affected[EDGE_RUNTIME_MAX_USERFAULTFDS]) {
    kernel_userfaultfd_event_t *event;
    uint64_t transaction_id;

    if (event_index >= EDGE_RUNTIME_USERFAULTFD_EVENT_POOL || !affected)
        return;
    event = &g_userfaultfd_events[event_index];
    if (!event->used || event->event_type != KERNEL_UFFD_EVENT_FORK)
        return;
    transaction_id = event->notification_start;
    event->resolving = 1u;
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *candidate =
            &g_userfaultfd_events[index];
        if (candidate->used &&
            candidate->event_type == KERNEL_UFFD_EVENT_FORK &&
            candidate->notification_start == transaction_id &&
            !candidate->resolving)
            return;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *candidate =
            &g_userfaultfd_events[index];
        if (!candidate->used ||
            candidate->event_type != KERNEL_UFFD_EVENT_FORK ||
            candidate->notification_start != transaction_id)
            continue;
        if (candidate->context_id >= 0 &&
            candidate->context_id < EDGE_RUNTIME_MAX_USERFAULTFDS)
            affected[candidate->context_id] = 1u;
        userfaultfd_event_free_locked(index);
    }
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

static void userfaultfd_cancel_fork_transaction_locked(
        uint64_t transaction_id,
        uint8_t notify_contexts[EDGE_RUNTIME_MAX_USERFAULTFDS],
        uint8_t release_children[EDGE_RUNTIME_MAX_USERFAULTFDS]) {
    if (!transaction_id || !notify_contexts || !release_children)
        return;
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        kernel_userfaultfd_context_t *context;

        if (!event->used ||
            event->event_type != KERNEL_UFFD_EVENT_FORK ||
            event->notification_start != transaction_id)
            continue;
        context = userfaultfd_context_locked(event->context_id);
        if (event->queued && context)
            userfaultfd_remove_queued_event_locked(context, index);
        if (event->context_id >= 0 &&
            event->context_id < EDGE_RUNTIME_MAX_USERFAULTFDS)
            notify_contexts[event->context_id] = 1u;
        if (!event->resolving &&
            event->notification_extra < EDGE_RUNTIME_MAX_USERFAULTFDS)
            release_children[event->notification_extra] = 1u;
        userfaultfd_event_free_locked(index);
    }
}

static int userfaultfd_queue_notification_locked(
        kernel_userfaultfd_context_t *context, int context_id,
        uint8_t event_type, uint64_t start, uint64_t end, uint64_t extra,
        uint64_t *ticket) {
    uint16_t event_index;
    kernel_userfaultfd_event_t *event;

    event_index = userfaultfd_event_allocate_locked();
    if (event_index == KERNEL_UFFD_INDEX_NONE)
        return -EDGE_LINUX_ENOMEM;
    event = &g_userfaultfd_events[event_index];
    event->context_id = context_id;
    event->event_type = event_type;
    event->notification_start = start;
    event->notification_end = end;
    event->notification_extra = extra;
    event->ticket = context->next_ticket++;
    if (!context->next_ticket) context->next_ticket = 1u;
    event->queued = 1u;
    if (context->tail == KERNEL_UFFD_INDEX_NONE)
        context->head = event_index;
    else
        g_userfaultfd_events[context->tail].next = event_index;
    context->tail = event_index;
    ++context->queued_events;
    userfaultfd_sequence_advance(context);
    if (ticket) *ticket = event->ticket;
    return 0;
}

static void userfaultfd_queue_mapping_notifications_locked(
        uint64_t address_space, const kernel_uffdio_range_t *range,
        uint64_t feature, uint8_t event_type,
        uint64_t extra,
        uint8_t affected[EDGE_RUNTIME_MAX_USERFAULTFDS],
        uint64_t tickets[EDGE_RUNTIME_MAX_USERFAULTFDS]) {
    uint64_t end = range->start + range->length;

    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id) {
        kernel_userfaultfd_context_t *context =
            userfaultfd_context_locked(context_id);
        uint64_t overlap_start = UINT64_MAX;
        uint64_t overlap_end = 0;

        if (!context || !context->api_ready ||
            context->address_space != address_space ||
            !(context->features & feature))
            continue;
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
            kernel_userfaultfd_range_t *registered =
                &g_userfaultfd_ranges[index];
            uint64_t start;
            uint64_t stop;

            if (!registered->used ||
                registered->context_id != context_id ||
                range->start >= registered->end ||
                end <= registered->start)
                continue;
            start = range->start > registered->start ?
                    range->start : registered->start;
            stop = end < registered->end ? end : registered->end;
            if (start < overlap_start) overlap_start = start;
            if (stop > overlap_end) overlap_end = stop;
        }
        if (overlap_end <= overlap_start) continue;
        if (userfaultfd_queue_notification_locked(
                context, context_id, event_type,
                overlap_start, overlap_end, extra,
                &tickets[context_id]) == 0)
            affected[context_id] = 1u;
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
    uint8_t release_child_contexts[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint8_t notify_contexts[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t address_space = 0;
    int notify = 0;

    memset(release_child_contexts, 0,
           sizeof(release_child_contexts));
    memset(notify_contexts, 0, sizeof(notify_contexts));
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
        if (event->used && event->context_id == context_id) {
            if (event->event_type == KERNEL_UFFD_EVENT_FORK) {
                uint64_t transaction_id = event->notification_start;
                userfaultfd_cancel_fork_transaction_locked(
                    transaction_id, notify_contexts,
                    release_child_contexts);
                continue;
            }
            userfaultfd_event_free_locked(index);
        }
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
    if (notify) notify_contexts[context_id] = 1u;
    for (int notify_id = 0;
         notify_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++notify_id)
        if (notify_contexts[notify_id])
            kernel_userfaultfd_state_changed(notify_id);
    for (int child_id = 0;
         child_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++child_id)
        if (release_child_contexts[child_id])
            kernel_userfaultfd_release(child_id);
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
    state->features = context->features;
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

int kernel_userfaultfd_register_backing(
        int context_id, kernel_uffdio_register_t *registration,
        uint8_t page_shift) {
    kernel_userfaultfd_context_t *context;
    kernel_userfaultfd_range_t *free_range = 0;
    uint64_t end;
    int result = 0;

    if (!registration || page_shift < 12u || page_shift > 30u ||
        !userfaultfd_range_valid(&registration->range) ||
        ((registration->range.start | registration->range.length) &
         ((UINT64_C(1) << page_shift) - 1u)) ||
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
    free_range->page_shift = page_shift;
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

int kernel_userfaultfd_register(int context_id,
                                kernel_uffdio_register_t *registration) {
    return kernel_userfaultfd_register_backing(
        context_id, registration, 12u);
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
            if (event->used &&
                event->event_type == KERNEL_UFFD_EVENT_PAGEFAULT &&
                event->context_id == context_id &&
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
        if (event->used &&
            event->event_type == KERNEL_UFFD_EVENT_PAGEFAULT &&
            event->context_id == context_id &&
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
            if (event->used &&
                event->event_type == KERNEL_UFFD_EVENT_PAGEFAULT &&
                event->context_id == context_id &&
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
        if (!event->used ||
            event->event_type != KERNEL_UFFD_EVENT_PAGEFAULT ||
            event->context_id != context_id ||
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

static void userfaultfd_mapping_forget_common(
        uint64_t address_space, const kernel_uffdio_range_t *range,
        int notify_unmap, int64_t completion_result) {
    uint8_t affected[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t tickets[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t end;

    if (!address_space || !userfaultfd_range_valid(range)) return;
    end = range->start + range->length;
    memset(affected, 0, sizeof(affected));
    memset(tickets, 0, sizeof(tickets));
    userfaultfd_lock();
    if (notify_unmap)
        userfaultfd_queue_mapping_notifications_locked(
            address_space, range, KERNEL_UFFD_FEATURE_EVENT_UNMAP,
            KERNEL_UFFD_EVENT_UNMAP, 0, affected, tickets);
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

        if (!event->used ||
            event->event_type != KERNEL_UFFD_EVENT_PAGEFAULT ||
            event->page < range->start ||
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
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id)
        if (tickets[context_id])
            arch_userfaultfd_wait_event(
                context_id, tickets[context_id], completion_result);
}

void kernel_userfaultfd_mapping_unmap(
        uint64_t address_space, const kernel_uffdio_range_t *range,
        int64_t completion_result) {
    userfaultfd_mapping_forget_common(
        address_space, range, 1, completion_result);
}

void kernel_userfaultfd_mapping_forget(
        uint64_t address_space, const kernel_uffdio_range_t *range) {
    userfaultfd_mapping_forget_common(address_space, range, 0, 0);
}

void kernel_userfaultfd_mapping_remove(
        uint64_t address_space, const kernel_uffdio_range_t *range) {
    uint8_t affected[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t tickets[EDGE_RUNTIME_MAX_USERFAULTFDS];

    if (!address_space || !userfaultfd_range_valid(range)) return;
    memset(affected, 0, sizeof(affected));
    memset(tickets, 0, sizeof(tickets));
    userfaultfd_lock();
    userfaultfd_queue_mapping_notifications_locked(
        address_space, range, KERNEL_UFFD_FEATURE_EVENT_REMOVE,
        KERNEL_UFFD_EVENT_REMOVE, 0, affected, tickets);
    userfaultfd_unlock();
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id)
        if (affected[context_id])
            kernel_userfaultfd_state_changed(context_id);
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id)
        if (tickets[context_id])
            arch_userfaultfd_wait_event(
                context_id, tickets[context_id], 0);
}

static int userfaultfd_remap_range_append(
        uint32_t *count, const kernel_userfaultfd_range_t *source,
        uint64_t start, uint64_t end) {
    kernel_userfaultfd_range_t *target;

    if (end <= start) return 0;
    if (!count || !source ||
        *count >= EDGE_RUNTIME_MAX_USERFAULTFD_RANGES * 3u)
        return -EDGE_LINUX_ENOSPC;
    target = &g_userfaultfd_remap_ranges[(*count)++];
    *target = *source;
    target->start = start;
    target->end = end;
    return 0;
}

static int userfaultfd_remap_wp_range_append(
        uint32_t *count, const kernel_userfaultfd_wp_range_t *source,
        uint64_t start, uint64_t end) {
    kernel_userfaultfd_wp_range_t *target;

    if (end <= start) return 0;
    if (!count || !source ||
        *count >= EDGE_RUNTIME_MAX_USERFAULTFD_RANGES * 3u)
        return -EDGE_LINUX_ENOSPC;
    target = &g_userfaultfd_remap_wp_ranges[(*count)++];
    *target = *source;
    target->start = start;
    target->end = end;
    return 0;
}

void kernel_userfaultfd_mapping_remap(
        uint64_t address_space, uint64_t from, uint64_t old_length,
        uint64_t to, uint64_t new_length, int64_t completion_result) {
    uint8_t affected[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t tickets[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t from_end;
    uint64_t to_end;
    uint32_t range_count = 0;
    uint32_t wp_count = 0;
    int capacity_error = 0;

    if (!address_space || !old_length || !new_length ||
        (from & (KERNEL_UFFD_PAGE_SIZE - 1u)) ||
        (to & (KERNEL_UFFD_PAGE_SIZE - 1u)) ||
        (old_length & (KERNEL_UFFD_PAGE_SIZE - 1u)) ||
        (new_length & (KERNEL_UFFD_PAGE_SIZE - 1u)) ||
        from > UINT64_MAX - old_length ||
        to > UINT64_MAX - new_length)
        return;
    from_end = from + old_length;
    to_end = to + new_length;
    memset(affected, 0, sizeof(affected));
    memset(tickets, 0, sizeof(tickets));

    userfaultfd_lock();
    memset(&g_userfaultfd_remap_notifications, 0,
           sizeof(g_userfaultfd_remap_notifications));
    memset(g_userfaultfd_remap_ranges, 0,
           sizeof(g_userfaultfd_remap_ranges));
    memset(g_userfaultfd_remap_wp_ranges, 0,
           sizeof(g_userfaultfd_remap_wp_ranges));
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        const kernel_userfaultfd_range_t *entry =
            &g_userfaultfd_ranges[index];
        kernel_userfaultfd_context_t *context;
        uint64_t overlap_start;
        uint64_t overlap_end;

        if (!entry->used) continue;
        context = userfaultfd_context_locked(entry->context_id);
        if (!context || context->address_space != address_space) {
            if (userfaultfd_remap_range_append(
                    &range_count, entry, entry->start, entry->end) < 0)
                capacity_error = 1;
            continue;
        }
        if ((context->features & KERNEL_UFFD_FEATURE_EVENT_UNMAP) &&
            entry->start < to_end && entry->end > to) {
            uint64_t start = entry->start > to ? entry->start : to;
            uint64_t end = entry->end < to_end ? entry->end : to_end;
            if (!g_userfaultfd_remap_notifications
                     .destination_unmap_end[entry->context_id] ||
                start < g_userfaultfd_remap_notifications
                            .destination_unmap_start[entry->context_id])
                g_userfaultfd_remap_notifications
                    .destination_unmap_start[entry->context_id] = start;
            if (end > g_userfaultfd_remap_notifications
                          .destination_unmap_end[entry->context_id])
                g_userfaultfd_remap_notifications
                    .destination_unmap_end[entry->context_id] = end;
        }
        if ((context->features & KERNEL_UFFD_FEATURE_EVENT_UNMAP) &&
            entry->start < from_end && entry->end > from) {
            uint64_t start = entry->start > from ? entry->start : from;
            uint64_t end = entry->end < from_end ? entry->end : from_end;
            if (!g_userfaultfd_remap_notifications
                     .source_unmap_end[entry->context_id] ||
                start < g_userfaultfd_remap_notifications
                            .source_unmap_start[entry->context_id])
                g_userfaultfd_remap_notifications
                    .source_unmap_start[entry->context_id] = start;
            if (end > g_userfaultfd_remap_notifications
                          .source_unmap_end[entry->context_id])
                g_userfaultfd_remap_notifications
                    .source_unmap_end[entry->context_id] = end;
        }
        overlap_start = entry->start > from ? entry->start : from;
        overlap_end = entry->end < from_end ? entry->end : from_end;
        if (overlap_end > overlap_start) {
            uint64_t moved_start =
                to + (overlap_start - from);
            uint64_t moved_end = to + (overlap_end - from);
            affected[entry->context_id] = 1u;
            if (userfaultfd_remap_range_append(
                    &range_count, entry, entry->start, overlap_start) < 0)
                capacity_error = 1;
            if (userfaultfd_remap_range_append(
                    &range_count, entry, overlap_end, entry->end) < 0)
                capacity_error = 1;
            if (context->features & KERNEL_UFFD_FEATURE_EVENT_REMAP) {
                if (moved_end > to_end) moved_end = to_end;
                if (userfaultfd_remap_range_append(
                        &range_count, entry, moved_start, moved_end) < 0)
                    capacity_error = 1;
                g_userfaultfd_remap_notifications
                    .remap[entry->context_id] = 1u;
            }
            continue;
        }
        if (entry->start < to_end && entry->end > to) {
            affected[entry->context_id] = 1u;
            if (userfaultfd_remap_range_append(
                    &range_count, entry, entry->start,
                    entry->end < to ? entry->end : to) < 0)
                capacity_error = 1;
            if (userfaultfd_remap_range_append(
                    &range_count, entry,
                    entry->start > to_end ? entry->start : to_end,
                    entry->end) < 0)
                capacity_error = 1;
            continue;
        }
        if (userfaultfd_remap_range_append(
                &range_count, entry, entry->start, entry->end) < 0)
            capacity_error = 1;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        const kernel_userfaultfd_wp_range_t *entry =
            &g_userfaultfd_wp_ranges[index];
        kernel_userfaultfd_context_t *context;
        uint64_t overlap_start;
        uint64_t overlap_end;

        if (!entry->used) continue;
        context = userfaultfd_context_locked(entry->context_id);
        if (!context || context->address_space != address_space) {
            if (userfaultfd_remap_wp_range_append(
                    &wp_count, entry, entry->start, entry->end) < 0)
                capacity_error = 1;
            continue;
        }
        overlap_start = entry->start > from ? entry->start : from;
        overlap_end = entry->end < from_end ? entry->end : from_end;
        if (overlap_end > overlap_start) {
            uint64_t moved_start =
                to + (overlap_start - from);
            uint64_t moved_end = to + (overlap_end - from);
            if (userfaultfd_remap_wp_range_append(
                    &wp_count, entry, entry->start, overlap_start) < 0)
                capacity_error = 1;
            if (userfaultfd_remap_wp_range_append(
                    &wp_count, entry, overlap_end, entry->end) < 0)
                capacity_error = 1;
            if (context->features & KERNEL_UFFD_FEATURE_EVENT_REMAP) {
                if (moved_end > to_end) moved_end = to_end;
                if (userfaultfd_remap_wp_range_append(
                        &wp_count, entry, moved_start, moved_end) < 0)
                    capacity_error = 1;
            }
            continue;
        }
        if (entry->start < to_end && entry->end > to) {
            if (userfaultfd_remap_wp_range_append(
                    &wp_count, entry, entry->start,
                    entry->end < to ? entry->end : to) < 0)
                capacity_error = 1;
            if (userfaultfd_remap_wp_range_append(
                    &wp_count, entry,
                    entry->start > to_end ? entry->start : to_end,
                    entry->end) < 0)
                capacity_error = 1;
            continue;
        }
        if (userfaultfd_remap_wp_range_append(
                &wp_count, entry, entry->start, entry->end) < 0)
            capacity_error = 1;
    }
    if (!capacity_error &&
        range_count <= EDGE_RUNTIME_MAX_USERFAULTFD_RANGES &&
        wp_count <= EDGE_RUNTIME_MAX_USERFAULTFD_RANGES) {
        memset(g_userfaultfd_ranges, 0, sizeof(g_userfaultfd_ranges));
        memset(g_userfaultfd_wp_ranges, 0,
               sizeof(g_userfaultfd_wp_ranges));
        memcpy(g_userfaultfd_ranges, g_userfaultfd_remap_ranges,
               range_count * sizeof(g_userfaultfd_ranges[0]));
        memcpy(g_userfaultfd_wp_ranges, g_userfaultfd_remap_wp_ranges,
               wp_count * sizeof(g_userfaultfd_wp_ranges[0]));
        for (int context_id = 0;
             context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id) {
            kernel_userfaultfd_context_t *context;
            if (!g_userfaultfd_remap_notifications
                     .destination_unmap_end[context_id])
                continue;
            context = userfaultfd_context_locked(context_id);
            if (context && userfaultfd_queue_notification_locked(
                    context, context_id, KERNEL_UFFD_EVENT_UNMAP,
                    g_userfaultfd_remap_notifications
                        .destination_unmap_start[context_id],
                    g_userfaultfd_remap_notifications
                        .destination_unmap_end[context_id],
                    0,
                    &tickets[context_id]) == 0)
                affected[context_id] = 1u;
        }
        for (int context_id = 0;
             context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id) {
            kernel_userfaultfd_context_t *context;
            if (!g_userfaultfd_remap_notifications.remap[context_id])
                continue;
            context = userfaultfd_context_locked(context_id);
            if (context && userfaultfd_queue_notification_locked(
                    context, context_id, KERNEL_UFFD_EVENT_REMAP,
                    from, to, old_length, &tickets[context_id]) == 0)
                affected[context_id] = 1u;
        }
        for (int context_id = 0;
             context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id) {
            kernel_userfaultfd_context_t *context;
            if (!g_userfaultfd_remap_notifications
                     .source_unmap_end[context_id])
                continue;
            context = userfaultfd_context_locked(context_id);
            if (context && userfaultfd_queue_notification_locked(
                    context, context_id, KERNEL_UFFD_EVENT_UNMAP,
                    g_userfaultfd_remap_notifications
                        .source_unmap_start[context_id],
                    g_userfaultfd_remap_notifications
                        .source_unmap_end[context_id],
                    0,
                    &tickets[context_id]) == 0)
                affected[context_id] = 1u;
        }
    }
    userfaultfd_unlock();
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id)
        if (affected[context_id])
            kernel_userfaultfd_state_changed(context_id);
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id)
        if (tickets[context_id])
            arch_userfaultfd_wait_event(
                context_id, tickets[context_id], completion_result);
}

void kernel_userfaultfd_mapping_expand(
        uint64_t address_space, uint64_t address,
        uint64_t old_length, uint64_t new_length) {
    uint8_t affected[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t old_end;
    uint64_t new_end;

    if (!address_space || !old_length || new_length <= old_length ||
        (address & (KERNEL_UFFD_PAGE_SIZE - 1u)) ||
        (old_length & (KERNEL_UFFD_PAGE_SIZE - 1u)) ||
        (new_length & (KERNEL_UFFD_PAGE_SIZE - 1u)) ||
        address > UINT64_MAX - old_length ||
        address > UINT64_MAX - new_length)
        return;
    old_end = address + old_length;
    new_end = address + new_length;
    memset(affected, 0, sizeof(affected));
    userfaultfd_lock();
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *entry = &g_userfaultfd_ranges[index];
        kernel_userfaultfd_context_t *context;

        if (!entry->used || entry->end != old_end ||
            entry->start >= old_end)
            continue;
        context = userfaultfd_context_locked(entry->context_id);
        if (!context || context->address_space != address_space)
            continue;
        entry->end = new_end;
        affected[entry->context_id] = 1u;
    }
    userfaultfd_unlock();
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id)
        if (affected[context_id])
            kernel_userfaultfd_state_changed(context_id);
}

static int userfaultfd_context_allocate_locked(
        uint64_t address_space, int32_t owner_pid,
        const kernel_userfaultfd_context_t *source) {
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id) {
        kernel_userfaultfd_context_t *context =
            &g_userfaultfd_contexts[context_id];

        if (context->used) continue;
        memset(context, 0, sizeof(*context));
        context->used = 1u;
        context->api_ready = source->api_ready;
        context->references = 1u;
        context->flags = source->flags;
        context->owner_pid = owner_pid;
        context->address_space = address_space;
        context->features = source->features;
        context->head = KERNEL_UFFD_INDEX_NONE;
        context->tail = KERNEL_UFFD_INDEX_NONE;
        context->next_ticket = 1u;
        return context_id;
    }
    return -EDGE_LINUX_ENOMEM;
}

static kernel_userfaultfd_range_t *
userfaultfd_free_range_locked(void) {
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index)
        if (!g_userfaultfd_ranges[index].used)
            return &g_userfaultfd_ranges[index];
    return 0;
}

static kernel_userfaultfd_wp_range_t *
userfaultfd_free_wp_range_locked(void) {
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index)
        if (!g_userfaultfd_wp_ranges[index].used)
            return &g_userfaultfd_wp_ranges[index];
    return 0;
}

int kernel_userfaultfd_address_space_fork(
        uint64_t parent_address_space, uint64_t child_address_space,
        int32_t child_owner_pid, int *wait_context,
        uint64_t *wait_ticket) {
    uint8_t clone_parent[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint8_t affected[EDGE_RUNTIME_MAX_USERFAULTFDS];
    int16_t child_contexts[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint64_t tickets[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint16_t contexts_required = 0;
    uint16_t ranges_required = 0;
    uint16_t wp_ranges_required = 0;
    uint16_t free_contexts = 0;
    uint16_t free_ranges = 0;
    uint16_t free_wp_ranges = 0;
    uint16_t free_events = 0;
    uint64_t transaction_id;
    int status = 0;

    if (wait_context) *wait_context = -1;
    if (wait_ticket) *wait_ticket = 0;
    if (!parent_address_space || !child_address_space ||
        parent_address_space == child_address_space ||
        child_owner_pid <= 0 || !wait_context || !wait_ticket)
        return -EDGE_LINUX_EINVAL;
    memset(clone_parent, 0, sizeof(clone_parent));
    memset(affected, 0, sizeof(affected));
    memset(child_contexts, 0xff, sizeof(child_contexts));
    memset(tickets, 0, sizeof(tickets));

    userfaultfd_lock();
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *range = &g_userfaultfd_ranges[index];
        kernel_userfaultfd_context_t *context;

        if (!range->used) {
            ++free_ranges;
            continue;
        }
        context = userfaultfd_context_locked(range->context_id);
        if (!context || context->address_space != parent_address_space ||
            !(context->features & KERNEL_UFFD_FEATURE_EVENT_FORK))
            continue;
        clone_parent[range->context_id] = 1u;
        ++ranges_required;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_wp_range_t *range =
            &g_userfaultfd_wp_ranges[index];
        kernel_userfaultfd_context_t *context;

        if (!range->used) {
            ++free_wp_ranges;
            continue;
        }
        context = userfaultfd_context_locked(range->context_id);
        if (!context || context->address_space != parent_address_space ||
            !clone_parent[range->context_id])
            continue;
        ++wp_ranges_required;
    }
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id) {
        if (!g_userfaultfd_contexts[context_id].used)
            ++free_contexts;
        if (clone_parent[context_id]) ++contexts_required;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index)
        if (!g_userfaultfd_events[index].used) ++free_events;
    if (!contexts_required) {
        userfaultfd_unlock();
        return 0;
    }
    if (contexts_required > free_contexts ||
        contexts_required > free_events ||
        ranges_required > free_ranges ||
        wp_ranges_required > free_wp_ranges) {
        userfaultfd_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    transaction_id = g_userfaultfd_next_transaction++;
    if (!g_userfaultfd_next_transaction)
        g_userfaultfd_next_transaction = 1u;

    for (int parent_id = 0;
         parent_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++parent_id) {
        int child_id;

        if (!clone_parent[parent_id]) continue;
        child_id = userfaultfd_context_allocate_locked(
            child_address_space, child_owner_pid,
            &g_userfaultfd_contexts[parent_id]);
        if (child_id < 0) {
            status = child_id;
            break;
        }
        child_contexts[parent_id] = (int16_t)child_id;
    }
    if (!status) {
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
            kernel_userfaultfd_range_t *source =
                &g_userfaultfd_ranges[index];
            kernel_userfaultfd_range_t *destination;
            int child_id;

            if (!source->used || source->context_id < 0 ||
                source->context_id >= EDGE_RUNTIME_MAX_USERFAULTFDS)
                continue;
            child_id = child_contexts[source->context_id];
            if (child_id < 0) continue;
            destination = userfaultfd_free_range_locked();
            if (!destination) {
                status = -EDGE_LINUX_ENOMEM;
                break;
            }
            *destination = *source;
            destination->context_id = child_id;
        }
    }
    if (!status) {
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
            kernel_userfaultfd_wp_range_t *source =
                &g_userfaultfd_wp_ranges[index];
            kernel_userfaultfd_wp_range_t *destination;
            int child_id;

            if (!source->used || source->context_id < 0 ||
                source->context_id >= EDGE_RUNTIME_MAX_USERFAULTFDS)
                continue;
            child_id = child_contexts[source->context_id];
            if (child_id < 0) continue;
            destination = userfaultfd_free_wp_range_locked();
            if (!destination) {
                status = -EDGE_LINUX_ENOMEM;
                break;
            }
            *destination = *source;
            destination->context_id = child_id;
        }
    }
    if (!status) {
        for (int parent_id = 0;
             parent_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++parent_id) {
            kernel_userfaultfd_context_t *context;

            if (child_contexts[parent_id] < 0) continue;
            context = userfaultfd_context_locked(parent_id);
            if (!context || userfaultfd_queue_notification_locked(
                    context, parent_id, KERNEL_UFFD_EVENT_FORK,
                    transaction_id, 0,
                    (uint64_t)child_contexts[parent_id],
                    &tickets[parent_id]) < 0) {
                status = -EDGE_LINUX_ENOMEM;
                break;
            }
            affected[parent_id] = 1u;
            if (!*wait_ticket) {
                *wait_context = parent_id;
                *wait_ticket = tickets[parent_id];
            }
        }
    }
    if (status < 0) {
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
            kernel_userfaultfd_event_t *event =
                &g_userfaultfd_events[index];
            if (!event->used ||
                event->event_type != KERNEL_UFFD_EVENT_FORK ||
                event->notification_extra >=
                    EDGE_RUNTIME_MAX_USERFAULTFDS)
                continue;
            if (child_contexts[event->context_id] !=
                (int16_t)event->notification_extra)
                continue;
            userfaultfd_remove_queued_event_locked(
                &g_userfaultfd_contexts[event->context_id], index);
            userfaultfd_event_free_locked(index);
        }
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
            int context_id = g_userfaultfd_ranges[index].context_id;
            int wp_context_id = g_userfaultfd_wp_ranges[index].context_id;
            for (int parent_id = 0;
                 parent_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++parent_id) {
                if (child_contexts[parent_id] == context_id)
                    memset(&g_userfaultfd_ranges[index], 0,
                           sizeof(g_userfaultfd_ranges[index]));
                if (child_contexts[parent_id] == wp_context_id)
                    memset(&g_userfaultfd_wp_ranges[index], 0,
                           sizeof(g_userfaultfd_wp_ranges[index]));
            }
        }
        for (int parent_id = 0;
             parent_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++parent_id)
            if (child_contexts[parent_id] >= 0)
                memset(&g_userfaultfd_contexts[
                           child_contexts[parent_id]],
                       0, sizeof(g_userfaultfd_contexts[0]));
    }
    userfaultfd_unlock();
    if (status < 0) {
        *wait_context = -1;
        *wait_ticket = 0;
        return status;
    }
    for (int parent_id = 0;
         parent_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++parent_id)
        if (affected[parent_id])
            kernel_userfaultfd_state_changed(parent_id);
    return 0;
}

void kernel_userfaultfd_wait_fork(int context_id, uint64_t ticket,
                                  int64_t completion_result) {
    if (context_id < 0 ||
        context_id >= EDGE_RUNTIME_MAX_USERFAULTFDS || !ticket)
        return;
    arch_userfaultfd_wait_event(
        context_id, ticket, completion_result);
}

int kernel_userfaultfd_consume_completed_fork(
        int64_t *completion_result) {
    return arch_userfaultfd_consume_completed_event(completion_result);
}

void kernel_userfaultfd_address_space_release(uint64_t address_space) {
    uint8_t affected[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint8_t notify_contexts[EDGE_RUNTIME_MAX_USERFAULTFDS];
    uint8_t release_children[EDGE_RUNTIME_MAX_USERFAULTFDS];

    if (!address_space) return;
    memset(affected, 0, sizeof(affected));
    memset(notify_contexts, 0, sizeof(notify_contexts));
    memset(release_children, 0, sizeof(release_children));
    userfaultfd_lock();
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id) {
        kernel_userfaultfd_context_t *context =
            userfaultfd_context_locked(context_id);

        if (!context || context->address_space != address_space)
            continue;
        for (uint16_t index = 0;
             index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
            kernel_userfaultfd_event_t *event =
                &g_userfaultfd_events[index];
            if (!event->used || event->context_id != context_id)
                continue;
            if (event->event_type == KERNEL_UFFD_EVENT_FORK) {
                uint64_t transaction_id = event->notification_start;
                userfaultfd_cancel_fork_transaction_locked(
                    transaction_id, notify_contexts,
                    release_children);
                continue;
            }
            userfaultfd_event_free_locked(index);
        }
        context->head = KERNEL_UFFD_INDEX_NONE;
        context->tail = KERNEL_UFFD_INDEX_NONE;
        context->queued_events = 0;
        context->unresolved_faults = 0;
        context->address_space = 0;
        userfaultfd_sequence_advance(context);
        affected[context_id] = 1u;
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        if (!event->used ||
            event->event_type != KERNEL_UFFD_EVENT_FORK ||
            event->notification_extra >= EDGE_RUNTIME_MAX_USERFAULTFDS ||
            !affected[event->notification_extra])
            continue;
        userfaultfd_cancel_fork_transaction_locked(
            event->notification_start, notify_contexts,
            release_children);
    }
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES; ++index) {
        kernel_userfaultfd_range_t *range = &g_userfaultfd_ranges[index];
        kernel_userfaultfd_wp_range_t *wp_range =
            &g_userfaultfd_wp_ranges[index];
        if (range->used && range->context_id >= 0 &&
            range->context_id < EDGE_RUNTIME_MAX_USERFAULTFDS &&
            affected[range->context_id])
            memset(range, 0, sizeof(*range));
        if (wp_range->used && wp_range->context_id >= 0 &&
            wp_range->context_id < EDGE_RUNTIME_MAX_USERFAULTFDS &&
            affected[wp_range->context_id])
            memset(wp_range, 0, sizeof(*wp_range));
    }
    userfaultfd_unlock();
    for (int context_id = 0;
         context_id < EDGE_RUNTIME_MAX_USERFAULTFDS; ++context_id) {
        if (affected[context_id])
            kernel_userfaultfd_state_changed(context_id);
        if (notify_contexts[context_id] && !affected[context_id])
            kernel_userfaultfd_state_changed(context_id);
        if (release_children[context_id])
            kernel_userfaultfd_release(context_id);
    }
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
    uint64_t resolution_size = KERNEL_UFFD_PAGE_SIZE;
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
            resolution_size = UINT64_C(1) << range->page_shift;
            page = address & ~(resolution_size - 1u);
            writeprotect_fault = protected_write;
            minor_fault = backed_minor_fault;
            break;
        }
    }
    if (found_context < 0) {
        userfaultfd_unlock();
        return 0;
    }
    if (writeprotect_fault &&
        (context->features & KERNEL_UFFD_FEATURE_WP_ASYNC)) {
        int result = userfaultfd_wp_remove_locked(
            found_context, page, page + resolution_size);
        if (result == 0) userfaultfd_sequence_advance(context);
        userfaultfd_unlock();
        if (result == 0)
            result = arch_mm_address_space_write_protect(
                address_space, page, resolution_size, 0);
        if (result < 0) {
            userfaultfd_lock();
            context = userfaultfd_context_locked(found_context);
            if (context)
                (void)userfaultfd_wp_add_locked(
                    found_context, page,
                    page + resolution_size);
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
        if (!event->used ||
            event->event_type != KERNEL_UFFD_EVENT_PAGEFAULT ||
            event->context_id != found_context ||
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
    g_userfaultfd_events[event_index].event_type =
        KERNEL_UFFD_EVENT_PAGEFAULT;
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
    int bypass = 0;

    userfaultfd_lock();
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_USERFAULTFD_EVENT_POOL; ++index) {
        kernel_userfaultfd_event_t *event = &g_userfaultfd_events[index];
        kernel_userfaultfd_context_t *context;
        uint64_t page = address &
            ~(uint64_t)(KERNEL_UFFD_PAGE_SIZE - 1u);
        if (!event->used ||
            event->event_type != KERNEL_UFFD_EVENT_PAGEFAULT ||
            !event->resolving)
            continue;
        context = userfaultfd_context_locked(event->context_id);
        if (!context || context->address_space != address_space)
            continue;
        for (uint16_t range_index = 0;
             range_index < EDGE_RUNTIME_MAX_USERFAULTFD_RANGES;
             ++range_index) {
            kernel_userfaultfd_range_t *range =
                &g_userfaultfd_ranges[range_index];
            if (!range->used ||
                range->context_id != event->context_id ||
                address < range->start || address >= range->end)
                continue;
            page = address &
                ~((UINT64_C(1) << range->page_shift) - 1u);
            break;
        }
        if (event->page == page) {
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
    kernel_userfaultfd_context_t *fork_context;
    kernel_userfaultfd_message_t message;
    uint16_t event_index;
    int fork_context_id = -1;
    int fork_descriptor = -1;
    uint32_t fork_flags = 0;
    uint8_t fork_affected[EDGE_RUNTIME_MAX_USERFAULTFDS];

    if (!copy_record) return -EDGE_LINUX_EFAULT;
    if (length < sizeof(message)) return -EDGE_LINUX_EINVAL;
    memset(fork_affected, 0, sizeof(fork_affected));
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
    message.event = g_userfaultfd_events[event_index].event_type;
    if (message.event == KERNEL_UFFD_EVENT_PAGEFAULT) {
        message.flags = g_userfaultfd_events[event_index].flags;
        message.address = g_userfaultfd_events[event_index].address;
        message.thread_id =
            g_userfaultfd_events[event_index].thread_id;
    } else if (message.event == KERNEL_UFFD_EVENT_FORK) {
        if (g_userfaultfd_events[event_index].notification_extra >=
            EDGE_RUNTIME_MAX_USERFAULTFDS) {
            userfaultfd_unlock();
            return -EDGE_LINUX_EIO;
        }
        fork_context_id = (int)
            g_userfaultfd_events[event_index].notification_extra;
        fork_context = userfaultfd_context_locked(fork_context_id);
        if (!fork_context) {
            userfaultfd_unlock();
            return -EDGE_LINUX_EIO;
        }
        fork_flags = fork_context->flags;
    } else {
        message.flags =
            g_userfaultfd_events[event_index].notification_start;
        message.address =
            g_userfaultfd_events[event_index].notification_end;
        message.length =
            g_userfaultfd_events[event_index].notification_extra;
    }
    userfaultfd_remove_queued_event_locked(context, event_index);
    userfaultfd_unlock();
    if (message.event == KERNEL_UFFD_EVENT_FORK) {
        fork_descriptor = kernel_userfaultfd_install_existing_descriptor(
            fork_context_id, fork_flags);
        if (fork_descriptor < 0) {
            userfaultfd_lock();
            context = userfaultfd_context_locked(context_id);
            if (context && g_userfaultfd_events[event_index].used &&
                !g_userfaultfd_events[event_index].queued) {
                g_userfaultfd_events[event_index].queued = 1u;
                g_userfaultfd_events[event_index].next = context->head;
                context->head = event_index;
                if (context->tail == KERNEL_UFFD_INDEX_NONE)
                    context->tail = event_index;
                ++context->queued_events;
            }
            userfaultfd_unlock();
            return fork_descriptor;
        }
        message.fork_ufd = (uint32_t)fork_descriptor;
    }
    if (copy_record(copy_context, 0, &message, sizeof(message)) < 0) {
        userfaultfd_lock();
        context = userfaultfd_context_locked(context_id);
        if (message.event != KERNEL_UFFD_EVENT_FORK && context &&
            g_userfaultfd_events[event_index].used &&
            !g_userfaultfd_events[event_index].queued) {
            g_userfaultfd_events[event_index].queued = 1;
            g_userfaultfd_events[event_index].next = context->head;
            context->head = event_index;
            if (context->tail == KERNEL_UFFD_INDEX_NONE)
                context->tail = event_index;
            ++context->queued_events;
        }
        if (message.event == KERNEL_UFFD_EVENT_FORK &&
            g_userfaultfd_events[event_index].used &&
            !g_userfaultfd_events[event_index].queued)
            userfaultfd_complete_fork_transaction_locked(
                event_index, fork_affected);
        userfaultfd_unlock();
        if (message.event == KERNEL_UFFD_EVENT_FORK) {
            for (int affected_context = 0;
                 affected_context < EDGE_RUNTIME_MAX_USERFAULTFDS;
                 ++affected_context)
                if (fork_affected[affected_context])
                    kernel_userfaultfd_state_changed(affected_context);
        }
        return -EDGE_LINUX_EFAULT;
    }
    if (message.event == KERNEL_UFFD_EVENT_FORK) {
        userfaultfd_lock();
        if (g_userfaultfd_events[event_index].used &&
            !g_userfaultfd_events[event_index].queued)
            userfaultfd_complete_fork_transaction_locked(
                event_index, fork_affected);
        userfaultfd_unlock();
        for (int affected_context = 0;
             affected_context < EDGE_RUNTIME_MAX_USERFAULTFDS;
             ++affected_context)
            if (fork_affected[affected_context])
                kernel_userfaultfd_state_changed(affected_context);
    } else if (message.event != KERNEL_UFFD_EVENT_PAGEFAULT) {
        userfaultfd_lock();
        if (g_userfaultfd_events[event_index].used &&
            !g_userfaultfd_events[event_index].queued)
            userfaultfd_event_free_locked(event_index);
        userfaultfd_unlock();
        kernel_userfaultfd_state_changed(context_id);
    }
    return sizeof(message);
}
