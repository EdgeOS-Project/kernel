/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux resource-limit policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "fs/proc_sysctl.h"
#include "kernel/linux_abi.h"
#include "kernel/process_runtime.h"

static int resource_limit_task_find(int32_t tid,
                                    kernel_proc_task_view_t *task) {
    if (!task || tid <= 0) return -1;
    if (kernel_proc_task_view_get(tid, task) < 0 ||
        task->state == KERNEL_PROC_TASK_ZOMBIE)
        return -1;
    return 0;
}

int kernel_process_resource_limit_get(int32_t pid, uint32_t resource,
                                      kernel_resource_limit_t *limit) {
    kernel_proc_task_view_t target;

    if (!limit || resource >= EDGE_LINUX_RLIMIT_COUNT) return -1;
    if (resource_limit_task_find(pid, &target) < 0) return -1;

    if (target.tgid > 0 && target.tgid != target.tid) {
        kernel_proc_task_view_t leader;
        if (resource_limit_task_find(target.tgid, &leader) == 0)
            target = leader;
    }
    *limit = target.resource_limits[resource];
    return 0;
}

int kernel_process_resource_limit_set(int32_t pid, uint32_t resource,
                                      const kernel_resource_limit_t *limit) {
    kernel_proc_task_view_t target;
    int32_t tgid;
    if (!limit || resource >= EDGE_LINUX_RLIMIT_COUNT) return -1;
    if (resource_limit_task_find(pid, &target) < 0) return -1;
    tgid = target.tgid > 0 ? target.tgid : target.tid;
    return kernel_arch_process_resource_limit_commit(
        target.tid, tgid, resource, limit);
}

uint64_t kernel_resource_limit_ceiling(uint32_t resource) {
    switch (resource) {
    case EDGE_LINUX_RLIMIT_NOFILE:
        return proc_sysctl_nr_open_limit();
    case EDGE_LINUX_RLIMIT_NICE:
        return 40u;
    case EDGE_LINUX_RLIMIT_RTPRIO:
        return 99u;
    default:
        return EDGE_LINUX_RLIM_INFINITY;
    }
}
