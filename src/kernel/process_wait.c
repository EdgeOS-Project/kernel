/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux process-wait ABI policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/process_session.h"

static void process_wait_clear(void *pointer, uint64_t size) {
    uint8_t *bytes = (uint8_t *)pointer;
    while (size--) *bytes++ = 0;
}

int kernel_process_wait_query_build(
    const kernel_process_wait_request_t *request, int32_t caller_pgid,
    kernel_process_wait_query_t *query) {
    const uint32_t allowed_flags =
        KERNEL_PROCESS_WAIT_NOHANG | KERNEL_PROCESS_WAIT_NOREAP |
        KERNEL_PROCESS_WAIT_NOTHREAD | KERNEL_PROCESS_WAIT_WALL |
        KERNEL_PROCESS_WAIT_WCLONE | KERNEL_PROCESS_WAIT_STOPPED |
        KERNEL_PROCESS_WAIT_CONTINUED | KERNEL_PROCESS_WAIT_EXITED;
    int64_t group;

    if (!request || !query) return -EDGE_LINUX_EINVAL;
    if (request->flags & ~allowed_flags) return -EDGE_LINUX_EINVAL;
    process_wait_clear(query, sizeof(*query));
    query->flags = request->flags;
    query->pid_namespace_id = request->pid_namespace_id;
    if (request->selector > 0) {
        query->id_type = KERNEL_PROCESS_WAIT_ID_PID;
        query->id = request->selector;
        return 0;
    }
    if (request->selector == 0) {
        if (caller_pgid < 0) return -EDGE_LINUX_ECHILD;
        query->id_type = KERNEL_PROCESS_WAIT_ID_PGID;
        query->id = caller_pgid;
        return 0;
    }
    if (request->selector == -1) {
        query->id_type = KERNEL_PROCESS_WAIT_ID_ALL;
        return 0;
    }
    group = -(int64_t)request->selector;
    if (group <= 0 || group > INT32_MAX) return -EDGE_LINUX_ESRCH;
    query->id_type = KERNEL_PROCESS_WAIT_ID_PGID;
    query->id = (int32_t)group;
    return 0;
}

int kernel_process_wait_query_matches(
    const kernel_process_wait_query_t *query, int32_t candidate_pid,
    int32_t candidate_pgid) {
    if (!query) return 0;
    if (query->id_type == KERNEL_PROCESS_WAIT_ID_ALL) return 1;
    if (query->id_type == KERNEL_PROCESS_WAIT_ID_PID)
        return candidate_pid == query->id;
    if (query->id_type == KERNEL_PROCESS_WAIT_ID_PGID)
        return candidate_pgid == query->id;
    return 0;
}

uint32_t kernel_process_wait_exit_status(int32_t exit_code,
                                         uint32_t termination_signal) {
    if (termination_signal) return termination_signal & 0x7fu;
    return ((uint32_t)exit_code & 0xffu) << 8;
}

uint32_t kernel_process_wait_stop_status(uint32_t stop_signal,
                                         uint32_t ptrace_event) {
    return ((stop_signal & 0xffu) << 8) | 0x7fu |
           ((ptrace_event & 0xffffu) << 16);
}

uint32_t kernel_process_wait_continue_status(void) {
    return 0xffffu;
}

int64_t kernel_process_wait(const kernel_process_wait_request_t *request,
                            kernel_process_wait_result_t *result,
                            void *user_registers) {
    kernel_process_wait_query_t query;
    int32_t caller_pgid = 0;
    int error;

    if (!request || !result) return -EDGE_LINUX_EINVAL;
    process_wait_clear(result, sizeof(*result));
    if (request->selector == 0 &&
        kernel_process_group_id(0, &caller_pgid) < 0)
        return -EDGE_LINUX_ECHILD;
    error = kernel_process_wait_query_build(request, caller_pgid, &query);
    if (error < 0) return error;
    return arch_process_wait(&query, result, user_registers);
}

int64_t kernel_process_wait_for_tid(
        const kernel_process_wait_request_t *request,
        kernel_process_wait_result_t *result, int32_t waiter_tid) {
    kernel_process_wait_query_t query;
    int32_t caller_pgid = 0;
    int error;

    if (!request || !result || waiter_tid <= 0)
        return -EDGE_LINUX_EINVAL;
    process_wait_clear(result, sizeof(*result));
    if (!(request->flags & KERNEL_PROCESS_WAIT_NOHANG))
        return -EDGE_LINUX_EINVAL;
    if (request->selector == 0 &&
        kernel_process_group_id(waiter_tid, &caller_pgid) < 0)
        return -EDGE_LINUX_ECHILD;
    error = kernel_process_wait_query_build(request, caller_pgid, &query);
    if (error < 0) return error;
    return arch_process_wait_for_tid(&query, result, waiter_tid);
}
