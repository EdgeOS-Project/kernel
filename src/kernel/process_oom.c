/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux OOM adjustment policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/credentials.h"
#include "kernel/process_runtime.h"

int kernel_oom_score_adj_transition(
    const kernel_oom_score_adj_access_t *access,
    int32_t value, int32_t *new_minimum) {
    int privileged;

    if (!access || !new_minimum ||
        value < EDGE_LINUX_OOM_SCORE_ADJ_MIN ||
        value > EDGE_LINUX_OOM_SCORE_ADJ_MAX)
        return -1;

    privileged = ((access->caller_effective_capabilities >>
                   EDGE_LINUX_CAP_SYS_RESOURCE) & 1u) != 0;
    if (!privileged && access->caller_euid != access->target_uid &&
        access->caller_euid != access->target_suid)
        return -1;
    if (!privileged && value < access->target_minimum)
        return -1;

    *new_minimum = access->target_minimum;
    if (privileged && value < *new_minimum)
        *new_minimum = value;
    return 0;
}

int kernel_process_oom_score_adj_get(int32_t tid, int32_t *value) {
    kernel_proc_task_view_t view;
    if (!value || tid <= 0) return -1;
    if (kernel_proc_task_view_get(tid, &view) < 0 ||
        view.state == KERNEL_PROC_TASK_ZOMBIE)
        return -1;
    *value = view.oom_score_adj;
    return 0;
}

int kernel_process_oom_score_adj_set(int32_t tid, int32_t value) {
    kernel_linux_identity_t caller;
    kernel_proc_task_view_t target;
    kernel_oom_score_adj_access_t access;
    kernel_oom_score_adj_commit_t commit;

    if (tid <= 0 || value < EDGE_LINUX_OOM_SCORE_ADJ_MIN ||
        value > EDGE_LINUX_OOM_SCORE_ADJ_MAX)
        return -1;
    if (kernel_current_linux_identity(&caller) < 0) return -1;
    if (kernel_proc_task_view_get(tid, &target) < 0 ||
        target.state == KERNEL_PROC_TASK_ZOMBIE)
        return -1;

    access.caller_euid = caller.euid;
    access.caller_effective_capabilities = caller.effective_capabilities;
    access.target_uid = target.uid;
    access.target_suid = target.suid;
    access.target_minimum = target.oom_score_adj_min;
    if (kernel_oom_score_adj_transition(
            &access, value, &commit.new_minimum) < 0)
        return -1;

    commit.caller_tid = caller.global_tid;
    commit.caller_euid = caller.euid;
    commit.caller_effective_capabilities = caller.effective_capabilities;
    commit.target_tid = target.tid;
    commit.target_tgid = target.tgid > 0 ? target.tgid : target.tid;
    commit.target_uid = target.uid;
    commit.target_suid = target.suid;
    commit.target_minimum = target.oom_score_adj_min;
    commit.value = value;
    return kernel_arch_process_oom_score_adj_commit(&commit);
}
