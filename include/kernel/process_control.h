/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent process-control runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_PROCESS_CONTROL_H
#define EDGEOS_KERNEL_PROCESS_CONTROL_H

#include <stdint.h>

#include "kernel/scheduler_policy.h"

typedef struct kernel_process_control {
    int32_t tid;
    int32_t tgid;
    int32_t pgid;
    uint32_t uid;
    uint32_t euid;
    uint32_t suid;
    uint64_t effective_capabilities;
    int8_t nice_value;
    uint16_t io_priority;
    edge_linux_scheduler_state_t scheduler;
} kernel_process_control_t;

typedef struct kernel_process_io_priority_commit {
    int32_t tid;
    int32_t expected_tgid;
    uint32_t expected_uid;
    uint32_t expected_euid;
    uint16_t io_priority;
} kernel_process_io_priority_commit_t;

int kernel_arch_process_io_priority_commit(
    const kernel_process_io_priority_commit_t *commit);
int kernel_process_control_next(uint32_t *cursor,
                                kernel_process_control_t *control);
int kernel_process_io_priority_set(const kernel_process_control_t *target,
                                   uint16_t io_priority);

#endif
