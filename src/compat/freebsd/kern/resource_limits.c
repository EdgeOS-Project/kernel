/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS process resource-limit adapter for imported FreeBSD drivers. */

#include <stdint.h>

#include "compat/freebsd/sys/proc.h"
#include "compat/freebsd/sys/resourcevar.h"
#include "compat/freebsd/sys/rtprio.h"
#include "compat/freebsd/sys/sched.h"
#include "kernel/linux_abi.h"
#include "kernel/process_runtime.h"

static int
bsd_resource_to_linux(int which, uint32_t *linux_resource)
{
    if (!linux_resource)
        return -1;

    switch (which) {
    case RLIMIT_STACK:
        *linux_resource = EDGE_LINUX_RLIMIT_STACK;
        return 0;
    case RLIMIT_MEMLOCK:
        *linux_resource = EDGE_LINUX_RLIMIT_MEMLOCK;
        return 0;
    case RLIMIT_NOFILE:
        *linux_resource = EDGE_LINUX_RLIMIT_NOFILE;
        return 0;
    case RLIMIT_VMEM:
        *linux_resource = EDGE_LINUX_RLIMIT_AS;
        return 0;
    default:
        return -1;
    }
}

rlim_t
lim_cur_proc(struct proc *process, int which)
{
    kernel_resource_limit_t limit;
    uint32_t linux_resource;
    int32_t pid;

    if (!process || process != bsd_curproc() ||
        bsd_resource_to_linux(which, &linux_resource) < 0 ||
        kernel_current_identity(&pid, 0, 0) < 0 ||
        kernel_process_resource_limit_get(pid, linux_resource, &limit) < 0)
        return RLIM_INFINITY;

    if (limit.current == EDGE_LINUX_RLIM_INFINITY ||
        limit.current > (uint64_t)RLIM_INFINITY)
        return RLIM_INFINITY;
    return (rlim_t)limit.current;
}

int
rtp_to_pri(struct rtprio *priority, struct thread *thread)
{
    int native_priority;

    if (!priority || !thread)
        return 22;
    switch (RTP_PRIO_BASE(priority->type)) {
    case RTP_PRIO_REALTIME:
        if (priority->prio > RTP_PRIO_MAX)
            return 22;
        native_priority = 8 + priority->prio;
        break;
    case RTP_PRIO_NORMAL:
        if (priority->prio > 167)
            return 22;
        native_priority = 56 + priority->prio;
        break;
    case RTP_PRIO_IDLE:
        if (priority->prio > RTP_PRIO_MAX)
            return 22;
        native_priority = 224 + priority->prio;
        break;
    default:
        return 22;
    }
    thread_lock(thread);
    sched_prio(thread, native_priority);
    thread_unlock(thread);
    return 0;
}
