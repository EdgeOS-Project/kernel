/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux process-group and session policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/process_session.h"
#include "kernel/process_runtime.h"
#include "kernel/perf_event.h"
#include "kernel/linux_errno.h"
#include "kernel/namespaces.h"
#include "string.h"

static int32_t process_session_view_tgid(
    const kernel_proc_task_view_t *view) {
    return view->tgid > 0 ? view->tgid : view->tid;
}

static void process_session_member_from_view(
    const kernel_proc_task_view_t *view,
    edge_linux_process_session_member_t *member) {
    member->pid = process_session_view_tgid(view);
    member->ppid = view->ppid;
    member->pgid = view->pgid;
    member->sid = view->sid;
    member->execed_since_fork = view->execed_since_fork;
}

static int process_session_member_get(
    int32_t pid, int require_live,
    edge_linux_process_session_member_t *member) {
    kernel_proc_task_view_t view;

    if (pid <= 0 || !member ||
        kernel_proc_task_view_get(pid, &view) < 0 ||
        view.tid != process_session_view_tgid(&view) ||
        (require_live && view.state == KERNEL_PROC_TASK_ZOMBIE))
        return -1;
    process_session_member_from_view(&view, member);
    return 0;
}

static int process_session_group_exists(int32_t pgid, int32_t sid) {
    kernel_proc_task_view_t view;

    for (uint32_t slot = 0;; ++slot) {
        int status = kernel_arch_proc_task_sample(slot, &view);
        if (status < 0) break;
        if (status > 0 || view.tid != process_session_view_tgid(&view))
            continue;
        if (view.pgid == pgid && (sid < 0 || view.sid == sid)) return 1;
    }
    return 0;
}

static int process_session_pid_to_global(
    const kernel_linux_identity_t *identity, int32_t visible_pid,
    int32_t *global_pid) {
    if (!identity || !global_pid || visible_pid < 0) return -1;
    if (!visible_pid) {
        *global_pid = identity->global_tgid;
        return *global_pid > 0 ? 0 : -1;
    }
    return edge_pid_namespace_visible_to_global(
        identity->pid_namespace_id, visible_pid, global_pid);
}

static int process_session_pid_to_visible(
    const kernel_linux_identity_t *identity, int32_t global_pid,
    int32_t *visible_pid) {
    if (!identity || !visible_pid || global_pid <= 0) return -1;
    return edge_pid_namespace_global_to_visible(
        identity->pid_namespace_id, global_pid, visible_pid);
}

static int64_t process_session_setpgid(
    const edge_linux_process_session_request_t *request,
    const kernel_linux_identity_t *identity,
    const edge_linux_process_session_member_t *current) {
    edge_linux_process_session_member_t target;
    edge_linux_process_session_commit_t commit;
    int32_t pid;
    int32_t pgid;

    if (request->pid < 0 || request->pgid < 0)
        return -EDGE_LINUX_EINVAL;
    if (process_session_pid_to_global(identity, request->pid, &pid) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!request->pgid) {
        pgid = pid;
    } else if (process_session_pid_to_global(
                   identity, request->pgid, &pgid) < 0) {
        return -EDGE_LINUX_EPERM;
    }
    if (process_session_member_get(pid, 0, &target) < 0)
        return -EDGE_LINUX_ESRCH;
    if (target.pid != current->pid) {
        if (target.ppid != current->pid) return -EDGE_LINUX_ESRCH;
        if (target.execed_since_fork) return -EDGE_LINUX_EACCES;
    }
    if (target.sid != current->sid || target.pid == target.sid)
        return -EDGE_LINUX_EPERM;
    if (pgid != target.pid &&
        !process_session_group_exists(pgid, current->sid))
        return -EDGE_LINUX_EPERM;
    memset(&commit, 0, sizeof(commit));
    commit.caller_tid = identity->global_tid;
    commit.current = *current;
    commit.target = target;
    commit.new_pgid = pgid;
    commit.new_sid = target.sid;
    commit.required_existing_pgid = pgid != target.pid ? pgid : 0;
    if (kernel_arch_process_session_commit(&commit) < 0)
        return -EDGE_LINUX_ESRCH;
    return 0;
}

static int64_t process_session_setsid(
    const kernel_linux_identity_t *identity,
    const edge_linux_process_session_member_t *current) {
    edge_linux_process_session_commit_t commit;

    if (process_session_group_exists(current->pid, -1))
        return -EDGE_LINUX_EPERM;
    memset(&commit, 0, sizeof(commit));
    commit.caller_tid = identity->global_tid;
    commit.current = *current;
    commit.target = *current;
    commit.new_pgid = current->pid;
    commit.new_sid = current->pid;
    commit.require_absent_process_group = 1u;
    commit.detach_controlling_terminal = 1u;
    if (kernel_arch_process_session_commit(&commit) < 0)
        return -EDGE_LINUX_ESRCH;
    return identity->pid;
}

int kernel_process_group_id(int32_t pid, int32_t *pgid_out) {
    kernel_linux_identity_t identity;
    kernel_proc_task_snapshot_t task;
    int32_t global_pid;

    if (pid < 0 || !pgid_out ||
        kernel_current_linux_identity(&identity) < 0 ||
        process_session_pid_to_global(&identity, pid, &global_pid) < 0 ||
        kernel_proc_task_snapshot(global_pid, &task) < 0)
        return -1;
    return process_session_pid_to_visible(&identity, task.pgid, pgid_out);
}

int kernel_process_session_id(int32_t pid, int32_t *sid_out) {
    kernel_linux_identity_t identity;
    kernel_proc_task_snapshot_t task;
    int32_t global_pid;

    if (pid < 0 || !sid_out ||
        kernel_current_linux_identity(&identity) < 0 ||
        process_session_pid_to_global(&identity, pid, &global_pid) < 0 ||
        kernel_proc_task_snapshot(global_pid, &task) < 0)
        return -1;
    return process_session_pid_to_visible(&identity, task.sid, sid_out);
}

int64_t kernel_process_session_change(
    const edge_linux_process_session_request_t *request) {
    kernel_linux_identity_t identity;
    edge_linux_process_session_member_t current;

    if (!request) return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) < 0 ||
        process_session_member_get(identity.global_tgid, 1, &current) < 0)
        return -EDGE_LINUX_ESRCH;
    if (request->operation == EDGE_LINUX_PROCESS_SET_PGID)
        return process_session_setpgid(request, &identity, &current);
    if (request->operation == EDGE_LINUX_PROCESS_CREATE_SESSION)
        return process_session_setsid(&identity, &current);
    return -EDGE_LINUX_EINVAL;
}

void kernel_current_exec_committed(void) {
    kernel_linux_identity_t identity;
    if (kernel_current_linux_identity(&identity) < 0) return;
#ifdef CONFIG_PERF_EVENTS
    kernel_perf_event_task_exec(identity.global_tid);
#endif
    (void)kernel_arch_process_exec_committed(identity.global_tgid);
}
