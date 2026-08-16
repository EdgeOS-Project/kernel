/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Architecture-independent Linux eventfd counter and lifetime semantics.
 * Descriptor tables and scheduler wait queues remain runtime mechanisms; all
 * state transitions that userspace can observe are serialized here.
 */

#include <stdint.h>

#include "kernel/eventfd.h"
#include "kernel/linux_errno.h"
#include "kernel/runtime_limits.h"
#include "string.h"

typedef struct kernel_eventfd_object {
    uint8_t used;
    uint8_t semaphore;
    uint16_t padding;
    uint32_t references;
    uint64_t counter;
    uint64_t write_sequence;
} kernel_eventfd_object_t;

static kernel_eventfd_object_t
    g_eventfds[EDGE_RUNTIME_MAX_EVENTFDS];
static volatile uint32_t g_eventfd_lock;

static void kernel_eventfd_lock(void) {
    while (__sync_lock_test_and_set(&g_eventfd_lock, 1u)) { }
}

static void kernel_eventfd_unlock(void) {
    __sync_lock_release(&g_eventfd_lock);
}

static kernel_eventfd_object_t *kernel_eventfd_lookup_locked(int event_id) {
    if (event_id < 0 || event_id >= EDGE_RUNTIME_MAX_EVENTFDS ||
        !g_eventfds[event_id].used)
        return 0;
    return &g_eventfds[event_id];
}

int kernel_eventfd_create(uint32_t initial_value, int semaphore) {
    int result = -EDGE_LINUX_ENFILE;
    kernel_eventfd_lock();
    for (int event_id = 0; event_id < EDGE_RUNTIME_MAX_EVENTFDS;
         ++event_id) {
        kernel_eventfd_object_t *event = &g_eventfds[event_id];
        if (event->used) continue;
        memset(event, 0, sizeof(*event));
        event->used = 1;
        event->semaphore = semaphore ? 1u : 0u;
        event->references = 1u;
        event->counter = initial_value;
        event->write_sequence = initial_value ? 1u : 0u;
        result = event_id;
        break;
    }
    kernel_eventfd_unlock();
    return result;
}

int kernel_eventfd_retain(int event_id) {
    kernel_eventfd_object_t *event;
    int result = 0;
    kernel_eventfd_lock();
    event = kernel_eventfd_lookup_locked(event_id);
    if (!event) result = -EDGE_LINUX_EBADF;
    else if (event->references == UINT32_MAX)
        result = -EDGE_LINUX_EOVERFLOW;
    else ++event->references;
    kernel_eventfd_unlock();
    return result;
}

void kernel_eventfd_release(int event_id) {
    kernel_eventfd_object_t *event;
    kernel_eventfd_lock();
    event = kernel_eventfd_lookup_locked(event_id);
    if (event && event->references && --event->references == 0u)
        memset(event, 0, sizeof(*event));
    kernel_eventfd_unlock();
}

int kernel_eventfd_query(int event_id, kernel_eventfd_state_t *state) {
    kernel_eventfd_object_t *event;
    int result = 0;
    if (!state) return -EDGE_LINUX_EINVAL;
    kernel_eventfd_lock();
    event = kernel_eventfd_lookup_locked(event_id);
    if (!event) {
        result = -EDGE_LINUX_EBADF;
    } else {
        state->counter = event->counter;
        state->write_sequence = event->write_sequence;
        state->references = event->references;
        state->semaphore = event->semaphore;
    }
    kernel_eventfd_unlock();
    return result;
}

static int kernel_eventfd_consume(int event_id, uint64_t *value) {
    kernel_eventfd_object_t *event;
    uint64_t consumed = 0;
    int result = 0;

    kernel_eventfd_lock();
    event = kernel_eventfd_lookup_locked(event_id);
    if (!event) {
        result = -EDGE_LINUX_EBADF;
    } else if (!event->counter) {
        result = -EDGE_LINUX_EAGAIN;
    } else {
        consumed = event->semaphore ? 1u : event->counter;
        event->counter -= consumed;
        if (value) *value = consumed;
    }
    kernel_eventfd_unlock();
    return result;
}

static int kernel_eventfd_add(int event_id, uint64_t value) {
    kernel_eventfd_object_t *event;
    int result = 0;
    if (value == UINT64_MAX) return -EDGE_LINUX_EINVAL;
    kernel_eventfd_lock();
    event = kernel_eventfd_lookup_locked(event_id);
    if (!event) {
        result = -EDGE_LINUX_EBADF;
    } else if (value > UINT64_MAX - 1u - event->counter) {
        result = -EDGE_LINUX_EAGAIN;
    } else {
        event->counter += value;
        if (++event->write_sequence == 0u) event->write_sequence = 1u;
    }
    kernel_eventfd_unlock();
    return result;
}

static int64_t kernel_eventfd_wait_result(int status, int nonblocking) {
    if (status != -EDGE_LINUX_EAGAIN) return status;
    return nonblocking ? -EDGE_LINUX_EAGAIN : KERNEL_EVENTFD_IO_WAIT;
}

int64_t kernel_eventfd_read_io(int event_id, uint64_t buffer_length,
                               int nonblocking,
                               kernel_eventfd_copy_value_fn copy_value,
                               void *copy_context, uint64_t *value) {
    uint64_t consumed = 0;
    int status;

    /*
     * Linux permits a larger read buffer but always transfers exactly one
     * 64-bit counter value. Short reads fail before inspecting readiness.
     */
    if (buffer_length < sizeof(uint64_t)) return -EDGE_LINUX_EINVAL;
    status = kernel_eventfd_consume(event_id, &consumed);
    if (status == -EDGE_LINUX_EAGAIN)
        return kernel_eventfd_wait_result(status, nonblocking);
    if (status < 0) return status;
    if (value) *value = consumed;
    /*
     * Linux commits the counter consumption before copy_to_user can report
     * EFAULT. Keeping this ordering here makes both runtimes identical.
     */
    if (!copy_value || copy_value(copy_context, consumed) < 0)
        return -EDGE_LINUX_EFAULT;
    return KERNEL_EVENTFD_IO_BYTES;
}

int64_t kernel_eventfd_write_value(int event_id, int nonblocking,
                                   uint64_t value) {
    int status = kernel_eventfd_add(event_id, value);
    if (status == -EDGE_LINUX_EAGAIN)
        return kernel_eventfd_wait_result(status, nonblocking);
    return status < 0 ? status : KERNEL_EVENTFD_IO_BYTES;
}

int64_t kernel_eventfd_write_io(int event_id, uint64_t buffer_length,
                                int nonblocking,
                                kernel_eventfd_load_value_fn load_value,
                                void *copy_context, uint64_t *value) {
    uint64_t supplied = 0;

    /*
     * Eventfd writes are one exact 64-bit value. Validate the count before
     * touching userspace so EINVAL has the same precedence on every target.
     */
    if (buffer_length != sizeof(uint64_t)) return -EDGE_LINUX_EINVAL;
    if (!load_value || load_value(copy_context, &supplied) < 0)
        return -EDGE_LINUX_EFAULT;
    if (value) *value = supplied;
    return kernel_eventfd_write_value(event_id, nonblocking, supplied);
}
