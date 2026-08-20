/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent legacy Linux AIO runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/aio_runtime.h"
#include "kernel/eventfd.h"
#include "kernel/linux_errno.h"
#include "string.h"
#include "sys/spinlock.h"

#define KERNEL_AIO_HANDLE_TAG 0xa10c000000000000ull
#define KERNEL_AIO_HANDLE_TAG_MASK 0xffff000000000000ull

typedef struct kernel_aio_pending_slot {
    uint8_t used;
    uint8_t reserved[7];
    kernel_aio_pending_request_t request;
} kernel_aio_pending_slot_t;

typedef struct kernel_aio_context {
    uint8_t used;
    uint8_t reserved[3];
    int32_t owner_tgid;
    uint32_t generation;
    uint32_t maximum_events;
    uint32_t completion_head;
    uint32_t completion_count;
    uint32_t pending_count;
    uint64_t next_token;
    struct edge_linux_io_event
        completions[KERNEL_AIO_MAX_EVENTS_PER_CONTEXT];
    kernel_aio_pending_slot_t
        pending[KERNEL_AIO_MAX_PENDING_PER_CONTEXT];
} kernel_aio_context_t;

static kernel_aio_context_t g_aio_contexts[KERNEL_AIO_MAX_CONTEXTS];
static spinlock_t g_aio_lock;
static uint32_t g_aio_generation = 1u;

static uint64_t aio_handle(uint32_t slot, uint32_t generation) {
    return KERNEL_AIO_HANDLE_TAG | ((uint64_t)generation << 8) |
           (uint64_t)(slot + 1u);
}

static int aio_context_locked(int32_t owner_tgid, uint64_t handle) {
    uint32_t slot;
    uint32_t generation;

    if ((handle & KERNEL_AIO_HANDLE_TAG_MASK) != KERNEL_AIO_HANDLE_TAG)
        return -1;
    slot = (uint32_t)(handle & 0xffu);
    if (!slot || slot > KERNEL_AIO_MAX_CONTEXTS) return -1;
    --slot;
    generation = (uint32_t)((handle >> 8) & 0xffffffffu);
    if (!g_aio_contexts[slot].used ||
        g_aio_contexts[slot].owner_tgid != owner_tgid ||
        g_aio_contexts[slot].generation != generation)
        return -1;
    return (int)slot;
}

static int aio_completion_enqueue_locked(
        kernel_aio_context_t *context,
        const struct edge_linux_io_event *event) {
    uint32_t slot;

    if (context->completion_count >= context->maximum_events)
        return -EDGE_LINUX_EAGAIN;
    slot = (context->completion_head + context->completion_count) %
           KERNEL_AIO_MAX_EVENTS_PER_CONTEXT;
    context->completions[slot] = *event;
    ++context->completion_count;
    return 0;
}

static void aio_context_release_pending_locked(
        kernel_aio_context_t *context) {
    for (uint32_t slot = 0;
         slot < KERNEL_AIO_MAX_PENDING_PER_CONTEXT; ++slot) {
        kernel_aio_pending_slot_t *pending = &context->pending[slot];
        if (!pending->used) continue;
        if (pending->request.result_event_id >= 0)
            kernel_eventfd_release(pending->request.result_event_id);
    }
}

int kernel_aio_context_create(int32_t owner_tgid, uint32_t maximum_events,
                              uint64_t *handle) {
    uint64_t lock_flags;
    uint32_t slot;

    if (owner_tgid <= 0 || !handle) return -EDGE_LINUX_EINVAL;
    if (!maximum_events ||
        maximum_events > KERNEL_AIO_MAX_EVENTS_PER_CONTEXT)
        return -EDGE_LINUX_EAGAIN;
    lock_flags = spin_lock_irqsave(&g_aio_lock);
    for (slot = 0; slot < KERNEL_AIO_MAX_CONTEXTS; ++slot)
        if (!g_aio_contexts[slot].used) break;
    if (slot == KERNEL_AIO_MAX_CONTEXTS) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    memset(&g_aio_contexts[slot], 0, sizeof(g_aio_contexts[slot]));
    if (++g_aio_generation == 0u) ++g_aio_generation;
    g_aio_contexts[slot].used = 1u;
    g_aio_contexts[slot].owner_tgid = owner_tgid;
    g_aio_contexts[slot].generation = g_aio_generation;
    g_aio_contexts[slot].maximum_events = maximum_events;
    g_aio_contexts[slot].next_token = 1u;
    *handle = aio_handle(slot, g_aio_generation);
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
    return 0;
}

int kernel_aio_context_destroy(int32_t owner_tgid, uint64_t handle) {
    uint64_t lock_flags = spin_lock_irqsave(&g_aio_lock);
    int slot = aio_context_locked(owner_tgid, handle);

    if (slot < 0) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    aio_context_release_pending_locked(&g_aio_contexts[slot]);
    memset(&g_aio_contexts[slot], 0, sizeof(g_aio_contexts[slot]));
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
    return 0;
}

void kernel_aio_release_owner(int32_t owner_tgid) {
    uint64_t lock_flags;

    if (owner_tgid <= 0) return;
    lock_flags = spin_lock_irqsave(&g_aio_lock);
    for (uint32_t slot = 0; slot < KERNEL_AIO_MAX_CONTEXTS; ++slot)
        if (g_aio_contexts[slot].used &&
            g_aio_contexts[slot].owner_tgid == owner_tgid) {
            aio_context_release_pending_locked(&g_aio_contexts[slot]);
            memset(&g_aio_contexts[slot], 0,
                   sizeof(g_aio_contexts[slot]));
        }
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
}

int kernel_aio_context_query(int32_t owner_tgid, uint64_t handle,
                             uint32_t *completion_count,
                             uint32_t *pending_count) {
    uint64_t lock_flags = spin_lock_irqsave(&g_aio_lock);
    int slot = aio_context_locked(owner_tgid, handle);

    if (slot < 0) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    if (completion_count)
        *completion_count = g_aio_contexts[slot].completion_count;
    if (pending_count)
        *pending_count = g_aio_contexts[slot].pending_count;
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
    return 0;
}

int kernel_aio_completion_enqueue(
        int32_t owner_tgid, uint64_t handle,
        const struct edge_linux_io_event *event) {
    uint64_t lock_flags;
    int slot;
    int result;

    if (!event) return -EDGE_LINUX_EINVAL;
    lock_flags = spin_lock_irqsave(&g_aio_lock);
    slot = aio_context_locked(owner_tgid, handle);
    if (slot < 0) {
        result = -EDGE_LINUX_EINVAL;
    } else if (g_aio_contexts[slot].completion_count +
               g_aio_contexts[slot].pending_count >=
               g_aio_contexts[slot].maximum_events) {
        result = -EDGE_LINUX_EAGAIN;
    } else {
        result = aio_completion_enqueue_locked(
            &g_aio_contexts[slot], event);
    }
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
    return result;
}

int kernel_aio_completion_dequeue(
        int32_t owner_tgid, uint64_t handle,
        struct edge_linux_io_event *event) {
    kernel_aio_context_t *context;
    uint64_t lock_flags;
    int slot;

    if (!event) return -EDGE_LINUX_EINVAL;
    lock_flags = spin_lock_irqsave(&g_aio_lock);
    slot = aio_context_locked(owner_tgid, handle);
    if (slot < 0) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    context = &g_aio_contexts[slot];
    if (!context->completion_count) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    *event = context->completions[context->completion_head];
    context->completion_head = (context->completion_head + 1u) %
                               KERNEL_AIO_MAX_EVENTS_PER_CONTEXT;
    --context->completion_count;
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
    return 0;
}

int kernel_aio_pending_add(int32_t owner_tgid, uint64_t handle,
                           const kernel_aio_pending_request_t *request) {
    kernel_aio_context_t *context;
    uint64_t lock_flags;
    int slot;

    if (!request || !request->object)
        return -EDGE_LINUX_EINVAL;
    lock_flags = spin_lock_irqsave(&g_aio_lock);
    slot = aio_context_locked(owner_tgid, handle);
    if (slot < 0) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    context = &g_aio_contexts[slot];
    if (context->pending_count >= KERNEL_AIO_MAX_PENDING_PER_CONTEXT ||
        context->completion_count + context->pending_count >=
            context->maximum_events) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    for (uint32_t index = 0;
         index < KERNEL_AIO_MAX_PENDING_PER_CONTEXT; ++index) {
        if (context->pending[index].used &&
            context->pending[index].request.object == request->object) {
            spin_unlock_irqrestore(&g_aio_lock, lock_flags);
            return -EDGE_LINUX_EINVAL;
        }
    }
    for (uint32_t index = 0;
         index < KERNEL_AIO_MAX_PENDING_PER_CONTEXT; ++index) {
        if (context->pending[index].used) continue;
        context->pending[index].used = 1u;
        context->pending[index].request = *request;
        context->pending[index].request.token = context->next_token++;
        if (!context->next_token) context->next_token = 1u;
        ++context->pending_count;
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return 0;
    }
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
    return -EDGE_LINUX_EAGAIN;
}

int kernel_aio_pending_snapshot(int32_t owner_tgid, uint64_t handle,
                                uint32_t slot,
                                kernel_aio_pending_request_t *request) {
    uint64_t lock_flags;
    int context_slot;

    if (!request || slot >= KERNEL_AIO_MAX_PENDING_PER_CONTEXT)
        return -EDGE_LINUX_EINVAL;
    lock_flags = spin_lock_irqsave(&g_aio_lock);
    context_slot = aio_context_locked(owner_tgid, handle);
    if (context_slot < 0) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    if (!g_aio_contexts[context_slot].pending[slot].used) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return 0;
    }
    *request = g_aio_contexts[context_slot].pending[slot].request;
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
    return 1;
}

int kernel_aio_pending_complete(int32_t owner_tgid, uint64_t handle,
                                uint64_t token, int64_t result,
                                int32_t *result_event_id) {
    struct edge_linux_io_event event;
    kernel_aio_context_t *context;
    uint64_t lock_flags;
    int context_slot;

    lock_flags = spin_lock_irqsave(&g_aio_lock);
    context_slot = aio_context_locked(owner_tgid, handle);
    if (context_slot < 0) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    context = &g_aio_contexts[context_slot];
    for (uint32_t slot = 0;
         slot < KERNEL_AIO_MAX_PENDING_PER_CONTEXT; ++slot) {
        kernel_aio_pending_slot_t *pending = &context->pending[slot];
        if (!pending->used || pending->request.token != token) continue;
        event.data = pending->request.data;
        event.object = pending->request.object;
        event.result = result;
        event.result2 = 0;
        if (aio_completion_enqueue_locked(context, &event) < 0) {
            spin_unlock_irqrestore(&g_aio_lock, lock_flags);
            return -EDGE_LINUX_EAGAIN;
        }
        if (result_event_id)
            *result_event_id = pending->request.result_event_id;
        memset(pending, 0, sizeof(*pending));
        --context->pending_count;
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return 0;
    }
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
    return -EDGE_LINUX_EAGAIN;
}

int kernel_aio_pending_cancel(int32_t owner_tgid, uint64_t handle,
                              uint64_t object,
                              struct edge_linux_io_event *event,
                              int32_t *result_event_id) {
    kernel_aio_context_t *context;
    uint64_t lock_flags;
    int context_slot;

    if (!event) return -EDGE_LINUX_EINVAL;
    lock_flags = spin_lock_irqsave(&g_aio_lock);
    context_slot = aio_context_locked(owner_tgid, handle);
    if (context_slot < 0) {
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    context = &g_aio_contexts[context_slot];
    for (uint32_t slot = 0;
         slot < KERNEL_AIO_MAX_PENDING_PER_CONTEXT; ++slot) {
        kernel_aio_pending_slot_t *pending = &context->pending[slot];
        if (!pending->used || pending->request.object != object) continue;
        (void)event;
        (void)result_event_id;
        spin_unlock_irqrestore(&g_aio_lock, lock_flags);
        /* Linux cannot synchronously cancel a queued IOCB_CMD_POLL. */
        return -EDGE_LINUX_EINPROGRESS;
    }
    spin_unlock_irqrestore(&g_aio_lock, lock_flags);
    return -EDGE_LINUX_EINVAL;
}
