/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent process-control runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/process_control.h"
#include "kernel/process_runtime.h"

static void process_control_clear(kernel_process_control_t *control) {
    uint8_t *bytes = (uint8_t *)control;
    uint32_t index;
    for (index = 0; index < sizeof(*control); ++index) bytes[index] = 0;
}

int kernel_process_control_next(uint32_t *cursor,
                                kernel_process_control_t *control) {
    kernel_proc_task_view_t view;
    if (!cursor || !control) return -1;
    process_control_clear(control);
    for (uint32_t slot = *cursor;; ++slot) {
        int status = kernel_arch_proc_task_sample(slot, &view);
        if (status < 0) break;
        *cursor = slot + 1u;
        if (status > 0 || view.state == KERNEL_PROC_TASK_ZOMBIE)
            continue;
        control->tid = view.tid;
        control->tgid = view.tgid > 0 ? view.tgid : view.tid;
        control->pgid = view.pgid;
        control->uid = view.uid;
        control->euid = view.euid;
        control->suid = view.suid;
        control->effective_capabilities = view.effective_capabilities;
        control->nice_value = view.nice_value;
        control->io_priority = view.io_priority;
        control->scheduler = view.scheduler;
        return 0;
    }
    process_control_clear(control);
    return -1;
}

int kernel_process_io_priority_set(const kernel_process_control_t *target,
                                   uint16_t io_priority) {
    kernel_process_io_priority_commit_t commit;
    if (!target || target->tid <= 0 || target->tgid <= 0) return -1;
    commit.tid = target->tid;
    commit.expected_tgid = target->tgid;
    commit.expected_uid = target->uid;
    commit.expected_euid = target->euid;
    commit.io_priority = io_priority;
    return kernel_arch_process_io_priority_commit(&commit);
}
