/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent legacy Linux AIO runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_AIO_RUNTIME_H
#define EDGEOS_KERNEL_AIO_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#define KERNEL_AIO_MAX_CONTEXTS 64u
#define KERNEL_AIO_MAX_EVENTS_PER_CONTEXT 128u
#define KERNEL_AIO_MAX_PENDING_PER_CONTEXT 128u

typedef struct kernel_aio_pending_request {
    uint64_t token;
    uint64_t data;
    uint64_t object;
    uint32_t descriptor;
    uint32_t events;
    int32_t result_event_id;
} kernel_aio_pending_request_t;

int kernel_aio_context_create(int32_t owner_tgid, uint32_t maximum_events,
                              uint64_t *handle);
int kernel_aio_context_destroy(int32_t owner_tgid, uint64_t handle);
void kernel_aio_release_owner(int32_t owner_tgid);
int kernel_aio_context_query(int32_t owner_tgid, uint64_t handle,
                             uint32_t *completion_count,
                             uint32_t *pending_count);
int kernel_aio_completion_enqueue(
    int32_t owner_tgid, uint64_t handle,
    const struct edge_linux_io_event *event);
int kernel_aio_completion_dequeue(
    int32_t owner_tgid, uint64_t handle,
    struct edge_linux_io_event *event);
int kernel_aio_pending_add(int32_t owner_tgid, uint64_t handle,
                           const kernel_aio_pending_request_t *request);
int kernel_aio_pending_snapshot(int32_t owner_tgid, uint64_t handle,
                                uint32_t slot,
                                kernel_aio_pending_request_t *request);
int kernel_aio_pending_complete(int32_t owner_tgid, uint64_t handle,
                                uint64_t token, int64_t result,
                                int32_t *result_event_id);
int kernel_aio_pending_cancel(int32_t owner_tgid, uint64_t handle,
                              uint64_t object,
                              struct edge_linux_io_event *event,
                              int32_t *result_event_id);

#endif
