/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#define SYS_SPINLOCK_H
typedef struct {
    atomic_flag value;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock) {
    atomic_flag_clear_explicit(&lock->value, memory_order_relaxed);
}

static inline uint64_t spin_lock_irqsave(spinlock_t *lock) {
    while (atomic_flag_test_and_set_explicit(
               &lock->value, memory_order_acquire))
        sched_yield();
    return 0;
}

static inline void spin_unlock_irqrestore(spinlock_t *lock,
                                          uint64_t flags) {
    (void)flags;
    atomic_flag_clear_explicit(&lock->value, memory_order_release);
}

#include "kernel/linux_errno.h"
#include "kernel/socket_accept_queue.h"
#include "../../src/kernel/socket_accept_queue.c"

typedef struct queue_thread_context {
    kernel_socket_accept_queue_t *queue;
    int32_t base;
    uint32_t count;
} queue_thread_context_t;

static void *enqueue_range(void *opaque) {
    queue_thread_context_t *context =
        (queue_thread_context_t *)opaque;

    for (uint32_t index = 0; index < context->count; ++index)
        while (kernel_socket_accept_queue_enqueue(
                   context->queue,
                   context->base + (int32_t)index) ==
               -EDGE_LINUX_EAGAIN) {
        }
    return 0;
}

static void *dequeue_range(void *opaque) {
    queue_thread_context_t *context =
        (queue_thread_context_t *)opaque;
    uint32_t count = 0;

    while (count < context->count) {
        int32_t object = -1;
        if (kernel_socket_accept_queue_dequeue(
                context->queue, &object) == 0) {
            assert(object >= context->base);
            ++count;
        }
    }
    return 0;
}

static void test_backlog_and_fifo(void) {
    kernel_socket_accept_queue_t queue;
    int32_t object = -1;

    kernel_socket_accept_queue_initialize(&queue);
    assert(kernel_socket_accept_queue_count(&queue) == 0);
    assert(kernel_socket_accept_queue_backlog(&queue) == 1);
    assert(kernel_socket_accept_queue_normalize_backlog(-1) ==
           EDGE_RUNTIME_SOCKET_BACKLOG);
    assert(kernel_socket_accept_queue_normalize_backlog(0) == 1);
    assert(kernel_socket_accept_queue_normalize_backlog(1) == 2);
    assert(kernel_socket_accept_queue_normalize_backlog(9) == 10);
    assert(kernel_socket_accept_queue_normalize_backlog(
               INT32_MAX) == EDGE_RUNTIME_SOCKET_BACKLOG);

    assert(kernel_socket_accept_queue_enqueue(&queue, 10) == 0);
    assert(kernel_socket_accept_queue_enqueue(&queue, 11) ==
           -EDGE_LINUX_EAGAIN);
    kernel_socket_accept_queue_configure(&queue, 3);
    assert(kernel_socket_accept_queue_backlog(&queue) == 4);
    assert(kernel_socket_accept_queue_enqueue(&queue, 11) == 0);
    assert(kernel_socket_accept_queue_enqueue(&queue, 12) == 0);
    assert(kernel_socket_accept_queue_enqueue(&queue, 13) == 0);
    assert(kernel_socket_accept_queue_enqueue(&queue, 14) ==
           -EDGE_LINUX_EAGAIN);
    assert(kernel_socket_accept_queue_count(&queue) == 4);
    assert(kernel_socket_accept_queue_dequeue(&queue, &object) == 0);
    assert(object == 10);
    assert(kernel_socket_accept_queue_dequeue(&queue, &object) == 0);
    assert(object == 11);
    assert(kernel_socket_accept_queue_dequeue(&queue, &object) == 0);
    assert(object == 12);
    assert(kernel_socket_accept_queue_dequeue(&queue, &object) == 0);
    assert(object == 13);
    assert(kernel_socket_accept_queue_dequeue(&queue, &object) ==
           -EDGE_LINUX_EAGAIN);
}

static void test_remove_wraparound(void) {
    kernel_socket_accept_queue_t queue;
    int32_t object = -1;

    kernel_socket_accept_queue_initialize(&queue);
    kernel_socket_accept_queue_configure(
        &queue, EDGE_RUNTIME_SOCKET_BACKLOG);
    for (int32_t value = 0; value < 90; ++value)
        assert(kernel_socket_accept_queue_enqueue(
                   &queue, value % 7) == 0);
    for (uint32_t index = 0; index < 50; ++index)
        assert(kernel_socket_accept_queue_dequeue(
                   &queue, &object) == 0);
    for (int32_t value = 90; value < 140; ++value)
        assert(kernel_socket_accept_queue_enqueue(
                   &queue, value % 7) == 0);
    assert(kernel_socket_accept_queue_contains(&queue, 3));
    assert(kernel_socket_accept_queue_remove(&queue, 3) > 0);
    assert(!kernel_socket_accept_queue_contains(&queue, 3));
    while (kernel_socket_accept_queue_dequeue(
               &queue, &object) == 0)
        assert(object != 3);
    assert(kernel_socket_accept_queue_count(&queue) == 0);
}

static void test_concurrent_enqueue_dequeue(void) {
    kernel_socket_accept_queue_t queue;
    queue_thread_context_t context;
    pthread_t producer;
    pthread_t consumer;

    kernel_socket_accept_queue_initialize(&queue);
    kernel_socket_accept_queue_configure(
        &queue, EDGE_RUNTIME_SOCKET_BACKLOG);
    context.queue = &queue;
    context.base = 1000;
    context.count = 200000;
    assert(pthread_create(&producer, 0, enqueue_range, &context) == 0);
    assert(pthread_create(&consumer, 0, dequeue_range, &context) == 0);
    assert(pthread_join(producer, 0) == 0);
    assert(pthread_join(consumer, 0) == 0);
    assert(kernel_socket_accept_queue_count(&queue) == 0);
}

int main(void) {
    test_backlog_and_fifo();
    test_remove_wraparound();
    test_concurrent_enqueue_dequeue();
    puts("socket accept queue unit tests passed");
    return 0;
}
