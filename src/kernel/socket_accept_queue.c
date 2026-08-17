/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral socket accept queue.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/linux_errno.h"
#include "kernel/socket_accept_queue.h"

void kernel_socket_accept_queue_initialize(
        kernel_socket_accept_queue_t *queue) {
    if (!queue) return;
    spinlock_init(&queue->lock);
    queue->head = 0;
    queue->tail = 0;
    __atomic_store_n(&queue->count, 0u, __ATOMIC_RELAXED);
    queue->backlog = 1;
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_SOCKET_BACKLOG; ++index)
        queue->entries[index] = -1;
}

uint32_t kernel_socket_accept_queue_normalize_backlog(
        int32_t backlog) {
    uint32_t normalized;

    if (backlog < 0)
        return EDGE_RUNTIME_SOCKET_BACKLOG;
    normalized = (uint32_t)backlog;
    /*
     * Linux permits one pending connection beyond the listen backlog. A zero
     * backlog therefore still admits one connection. Apply EdgeOS's fixed
     * internal cap after adding that Linux-visible slot.
     */
    return normalized < EDGE_RUNTIME_SOCKET_BACKLOG - 1u ?
        normalized + 1u : EDGE_RUNTIME_SOCKET_BACKLOG;
}

void kernel_socket_accept_queue_configure(
        kernel_socket_accept_queue_t *queue, int32_t backlog) {
    uint64_t irq_flags;

    if (!queue) return;
    irq_flags = spin_lock_irqsave(&queue->lock);
    queue->backlog =
        kernel_socket_accept_queue_normalize_backlog(backlog);
    spin_unlock_irqrestore(&queue->lock, irq_flags);
}

uint32_t kernel_socket_accept_queue_count(
        const kernel_socket_accept_queue_t *queue) {
    if (!queue) return 0;
    /*
     * Queue mutations serialize under lock and publish count last. Readiness
     * checks only need a current empty/nonempty snapshot; avoiding an
     * IRQ-disabling lock here keeps poll/epoll hot paths inexpensive.
     */
    return __atomic_load_n(&queue->count, __ATOMIC_ACQUIRE);
}

uint32_t kernel_socket_accept_queue_backlog(
        kernel_socket_accept_queue_t *queue) {
    uint64_t irq_flags;
    uint32_t backlog;

    if (!queue) return 0;
    irq_flags = spin_lock_irqsave(&queue->lock);
    backlog = queue->backlog;
    spin_unlock_irqrestore(&queue->lock, irq_flags);
    return backlog;
}

int kernel_socket_accept_queue_enqueue(
        kernel_socket_accept_queue_t *queue, int32_t object) {
    uint64_t irq_flags;
    uint32_t count;

    if (!queue || object < 0)
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&queue->lock);
    count = __atomic_load_n(&queue->count, __ATOMIC_RELAXED);
    if (count >= queue->backlog ||
        count >= EDGE_RUNTIME_SOCKET_BACKLOG) {
        spin_unlock_irqrestore(&queue->lock, irq_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    queue->entries[queue->tail] = object;
    queue->tail =
        (queue->tail + 1u) % EDGE_RUNTIME_SOCKET_BACKLOG;
    __atomic_store_n(
        &queue->count, count + 1u, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&queue->lock, irq_flags);
    return 0;
}

int kernel_socket_accept_queue_dequeue(
        kernel_socket_accept_queue_t *queue, int32_t *object) {
    uint64_t irq_flags;
    int32_t dequeued;
    uint32_t count;

    if (!queue || !object)
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&queue->lock);
    count = __atomic_load_n(&queue->count, __ATOMIC_RELAXED);
    if (!count) {
        spin_unlock_irqrestore(&queue->lock, irq_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    dequeued = queue->entries[queue->head];
    queue->entries[queue->head] = -1;
    queue->head =
        (queue->head + 1u) % EDGE_RUNTIME_SOCKET_BACKLOG;
    --count;
    __atomic_store_n(
        &queue->count, count, __ATOMIC_RELEASE);
    if (!count)
        queue->head = queue->tail = 0;
    spin_unlock_irqrestore(&queue->lock, irq_flags);
    *object = dequeued;
    return 0;
}

uint32_t kernel_socket_accept_queue_remove(
        kernel_socket_accept_queue_t *queue, int32_t object) {
    int32_t retained[EDGE_RUNTIME_SOCKET_BACKLOG];
    uint64_t irq_flags;
    uint32_t retained_count = 0;
    uint32_t removed = 0;

    if (!queue || object < 0) return 0;
    irq_flags = spin_lock_irqsave(&queue->lock);
    for (uint32_t index = 0;
         index < __atomic_load_n(
             &queue->count, __ATOMIC_RELAXED); ++index) {
        int32_t candidate = queue->entries[
            (queue->head + index) % EDGE_RUNTIME_SOCKET_BACKLOG];
        if (candidate == object) {
            ++removed;
            continue;
        }
        retained[retained_count++] = candidate;
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_SOCKET_BACKLOG; ++index)
        queue->entries[index] =
            index < retained_count ? retained[index] : -1;
    queue->head = 0;
    queue->tail =
        retained_count % EDGE_RUNTIME_SOCKET_BACKLOG;
    __atomic_store_n(
        &queue->count, retained_count, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&queue->lock, irq_flags);
    return removed;
}

int kernel_socket_accept_queue_contains(
        kernel_socket_accept_queue_t *queue, int32_t object) {
    uint64_t irq_flags;
    int found = 0;

    if (!queue || object < 0) return 0;
    irq_flags = spin_lock_irqsave(&queue->lock);
    for (uint32_t index = 0;
         index < __atomic_load_n(
             &queue->count, __ATOMIC_RELAXED); ++index) {
        if (queue->entries[
                (queue->head + index) %
                    EDGE_RUNTIME_SOCKET_BACKLOG] == object) {
            found = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&queue->lock, irq_flags);
    return found;
}
