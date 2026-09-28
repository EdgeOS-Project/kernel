/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_SIGNALFD_H
#define EDGEOS_KERNEL_SIGNALFD_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#define KERNEL_SIGNALFD_SIGKILL 9u
#define KERNEL_SIGNALFD_SIGSTOP 19u

typedef struct kernel_signalfd_state {
    uint64_t mask;
    uint32_t references;
} kernel_signalfd_state_t;

typedef int (*kernel_signalfd_dequeue_fn)(
    void *context, uint64_t mask,
    struct edge_linux_signalfd_siginfo *information);
typedef int (*kernel_signalfd_copy_record_fn)(
    void *context, uint64_t offset,
    const struct edge_linux_signalfd_siginfo *information);

int kernel_signalfd_create(uint64_t mask);
int kernel_signalfd_retain(int signalfd_id);
void kernel_signalfd_release(int signalfd_id);
int kernel_signalfd_update(int signalfd_id, uint64_t mask);
int kernel_signalfd_query(int signalfd_id, kernel_signalfd_state_t *state);
int64_t kernel_signalfd_read(int signalfd_id, uint64_t length,
                             kernel_signalfd_dequeue_fn dequeue_signal,
                             void *dequeue_context,
                             kernel_signalfd_copy_record_fn copy_record,
                             void *copy_context);
void kernel_signalfd_siginfo_from_linux_siginfo(
    const void *linux_siginfo,
    struct edge_linux_signalfd_siginfo *information);

#endif
