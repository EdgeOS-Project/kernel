/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_FD_TABLE_RUNTIME_H
#define EDGEOS_KERNEL_FD_TABLE_RUNTIME_H

#include <stdint.h>

#include "sys/spinlock.h"

typedef enum kernel_fd_slot_state {
    KERNEL_FD_SLOT_FREE = 0,
    KERNEL_FD_SLOT_RESERVED,
    KERNEL_FD_SLOT_OPEN,
    KERNEL_FD_SLOT_CLOSING,
} kernel_fd_slot_state_t;

typedef struct kernel_fd_table_runtime {
    spinlock_t lock;
    uint8_t *states;
    uint32_t limit;
    uint32_t allocated_limit;
} kernel_fd_table_runtime_t;

/*
 * The caller owns the state array. Initialization preserves its contents so a
 * copied files table can initialize a fresh lock around copied slot states.
 */
int kernel_fd_table_runtime_initialize(
    kernel_fd_table_runtime_t *runtime,
    uint8_t *states,
    uint32_t limit);

/*
 * Linux select() ignores descriptor bits beyond the currently allocated
 * fdtable, rather than the process hard limit. The allocated boundary grows
 * when a high descriptor number is reserved and does not shrink on close.
 * Callers must hold the table lock while reading or inheriting this state.
 */
uint32_t kernel_fd_table_allocated_limit_locked(
    const kernel_fd_table_runtime_t *runtime);
int kernel_fd_table_inherit_allocated_limit_locked(
    kernel_fd_table_runtime_t *destination,
    const kernel_fd_table_runtime_t *source);

uint64_t kernel_fd_table_lock(kernel_fd_table_runtime_t *runtime);
void kernel_fd_table_unlock(kernel_fd_table_runtime_t *runtime,
                            uint64_t irq_flags);

kernel_fd_slot_state_t kernel_fd_table_state_locked(
    const kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor);
int kernel_fd_table_is_open_locked(
    const kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor);

int kernel_fd_table_reserve_next_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t minimum,
    uint32_t *descriptor);
int kernel_fd_table_reserve_next_below_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t minimum,
    uint32_t exclusive_limit,
    uint32_t *descriptor);
/*
 * These batch operations require the caller to hold runtime->lock.
 *
 * reserve_batch requires a valid runtime and a non-NULL reserved pointer.  It
 * scans [minimum, runtime->limit) once and reserves at most requested FREE slots
 * in ascending descriptor order.  descriptors must have room for requested
 * entries when requested is nonzero.  reserved receives the number of entries
 * written.  requested == 0 succeeds, writes zero to reserved, ignores minimum,
 * and permits descriptors to be NULL.  Partial availability succeeds with a
 * short count.  No availability, including minimum >= runtime->limit, returns
 * -EMFILE with a zero count.  Other invalid output arguments return -EINVAL
 * without changing slot state.
 *
 * publish_batch and cancel_batch first validate the entire input, then perform
 * one all-or-nothing state transition.  A valid runtime is always required.
 * count == 0 succeeds and permits descriptors to be NULL.  An out-of-range
 * descriptor returns -EBADF.  A NULL nonempty array, a duplicate descriptor,
 * or any slot not in RESERVED state returns -EINVAL.  Every error leaves every
 * slot unchanged.
 */
int kernel_fd_table_reserve_batch_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t minimum,
    uint32_t *descriptors,
    uint32_t requested,
    uint32_t *reserved);
int kernel_fd_table_reserve_batch_below_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t minimum,
    uint32_t exclusive_limit,
    uint32_t *descriptors,
    uint32_t requested,
    uint32_t *reserved);
int kernel_fd_table_publish_batch_locked(
    kernel_fd_table_runtime_t *runtime,
    const uint32_t *descriptors,
    uint32_t count);
int kernel_fd_table_cancel_batch_locked(
    kernel_fd_table_runtime_t *runtime,
    const uint32_t *descriptors,
    uint32_t count);
/*
 * Validates a complete RESERVED batch and moves it to CLOSING atomically.
 * Backends use this when hidden constructed entries own resources that must be
 * dropped without holding the table lock. Each CLOSING slot must subsequently
 * be completed with kernel_fd_table_complete_close_locked().
 */
int kernel_fd_table_begin_cancel_batch_locked(
    kernel_fd_table_runtime_t *runtime,
    const uint32_t *descriptors,
    uint32_t count);
int kernel_fd_table_reserve_exact_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor);
int kernel_fd_table_publish_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor);
int kernel_fd_table_publish_pair_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t first,
    uint32_t second);
int kernel_fd_table_cancel_reservation_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor);
int kernel_fd_table_begin_close_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor);
/*
 * Detach an OPEN descriptor number for close while the caller still holds the
 * table lock. The number becomes FREE before any potentially slow final
 * open-file-description release, matching Linux close/fput ordering.
 */
int kernel_fd_table_detach_open_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor);
int kernel_fd_table_complete_close_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor);
int kernel_fd_table_restore_open_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor);

#endif
