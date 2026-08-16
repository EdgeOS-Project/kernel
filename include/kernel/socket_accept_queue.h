/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral socket accept queue.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SOCKET_ACCEPT_QUEUE_H
#define EDGEOS_KERNEL_SOCKET_ACCEPT_QUEUE_H

#include <stdint.h>

#include "kernel/runtime_limits.h"
#include "sys/spinlock.h"

typedef struct kernel_socket_accept_queue {
    spinlock_t lock;
    int32_t entries[EDGE_RUNTIME_SOCKET_BACKLOG];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    uint32_t backlog;
} kernel_socket_accept_queue_t;

void kernel_socket_accept_queue_initialize(
    kernel_socket_accept_queue_t *queue);
uint32_t kernel_socket_accept_queue_normalize_backlog(
    int32_t backlog);
void kernel_socket_accept_queue_configure(
    kernel_socket_accept_queue_t *queue, int32_t backlog);
uint32_t kernel_socket_accept_queue_count(
    const kernel_socket_accept_queue_t *queue);
uint32_t kernel_socket_accept_queue_backlog(
    kernel_socket_accept_queue_t *queue);
int kernel_socket_accept_queue_enqueue(
    kernel_socket_accept_queue_t *queue, int32_t object);
int kernel_socket_accept_queue_dequeue(
    kernel_socket_accept_queue_t *queue, int32_t *object);
uint32_t kernel_socket_accept_queue_remove(
    kernel_socket_accept_queue_t *queue, int32_t object);
int kernel_socket_accept_queue_contains(
    kernel_socket_accept_queue_t *queue, int32_t object);

#endif
