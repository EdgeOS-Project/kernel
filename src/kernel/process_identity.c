/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux process identity runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/process_runtime.h"
#include "kernel/namespaces.h"

static int kernel_pid_visible(uint32_t namespace_id, int32_t global_id,
                              int32_t *visible_id) {
    if (!visible_id) return -1;
    if (global_id <= 0) {
        *visible_id = 0;
        return 0;
    }
    return edge_pid_namespace_global_to_visible(
        namespace_id, global_id, visible_id);
}

static int kernel_linux_identity_from_view(
    const kernel_task_identity_view_t *view,
    uint32_t viewer_pid_namespace_id,
    kernel_linux_identity_t *identity) {
    if (!view || !identity || view->state == KERNEL_PROC_TASK_ZOMBIE)
        return -1;
    identity->global_tid = view->tid;
    identity->global_tgid = view->tgid > 0 ? view->tgid : view->tid;
    identity->global_ppid = view->ppid;
    identity->global_pgid = view->pgid;
    identity->global_sid = view->sid;
    identity->pid_namespace_id = viewer_pid_namespace_id;
    identity->user_namespace_id = view->user_namespace_id;
    if (kernel_pid_visible(viewer_pid_namespace_id, view->tid,
                           &identity->tid) < 0 ||
        kernel_pid_visible(viewer_pid_namespace_id,
                           view->tgid > 0 ? view->tgid : view->tid,
                           &identity->tgid) < 0)
        return -1;
    identity->pid = identity->tgid;
    if (kernel_pid_visible(viewer_pid_namespace_id, view->ppid,
                           &identity->ppid) < 0)
        identity->ppid = 0;
    if (kernel_pid_visible(viewer_pid_namespace_id, view->pgid,
                           &identity->pgid) < 0)
        identity->pgid = 0;
    if (kernel_pid_visible(viewer_pid_namespace_id, view->sid,
                           &identity->sid) < 0)
        identity->sid = 0;
    identity->uid = view->uid;
    identity->euid = view->euid;
    identity->suid = view->suid;
    identity->fsuid = view->fsuid;
    identity->gid = view->gid;
    identity->egid = view->egid;
    identity->sgid = view->sgid;
    identity->fsgid = view->fsgid;
    identity->dumpable = view->dumpable;
    identity->permitted_capabilities = view->permitted_capabilities;
    identity->effective_capabilities = view->effective_capabilities;
    return 0;
}

static void kernel_identity_view_from_proc(
    const kernel_proc_task_view_t *task,
    kernel_task_identity_view_t *identity) {
    identity->tid = task->tid;
    identity->tgid = task->tgid;
    identity->ppid = task->ppid;
    identity->pgid = task->pgid;
    identity->sid = task->sid;
    identity->pid_namespace_id = task->pid_namespace_id;
    identity->user_namespace_id = task->user_namespace_id;
    identity->uid = task->uid;
    identity->euid = task->euid;
    identity->suid = task->suid;
    identity->fsuid = task->fsuid;
    identity->gid = task->gid;
    identity->egid = task->egid;
    identity->sgid = task->sgid;
    identity->fsgid = task->fsgid;
    identity->state = task->state;
    identity->dumpable = task->dumpable;
    identity->permitted_capabilities = task->permitted_capabilities;
    identity->effective_capabilities = task->effective_capabilities;
}

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    kernel_task_identity_view_t view;
    if (!identity) return -1;
    if (kernel_arch_current_identity_sample(&view) < 0) return -1;
    return kernel_linux_identity_from_view(
        &view, view.pid_namespace_id, identity);
}

int kernel_current_cgroup_id(uint32_t *cgroup_id) {
    kernel_task_identity_view_t identity;
    kernel_proc_task_view_t task;

    if (!cgroup_id ||
        kernel_arch_current_identity_sample(&identity) < 0 ||
        kernel_arch_proc_task_lookup(identity.tid, &task) < 0)
        return -1;
    *cgroup_id = task.cgroup_id;
    return 0;
}

int kernel_process_linux_identity(int32_t pid,
                                  kernel_linux_identity_t *identity) {
    kernel_task_identity_view_t caller_view;
    kernel_task_identity_view_t identity_view;
    kernel_proc_task_view_t view;
    if (!identity || kernel_arch_current_identity_sample(&caller_view) < 0)
        return -1;
    if (kernel_proc_task_view_get(pid, &view) < 0) return -1;
    kernel_identity_view_from_proc(&view, &identity_view);
    return kernel_linux_identity_from_view(
        &identity_view, caller_view.pid_namespace_id, identity);
}

int kernel_process_resource_id(int32_t pid, uint32_t resource_type,
                               uint64_t *resource_id) {
    kernel_proc_task_view_t view;

    if (!resource_id || kernel_proc_task_view_get(pid, &view) < 0)
        return -1;
    switch (resource_type) {
        case 1u:
            *resource_id = view.memory_context_id;
            return 0;
        case 2u:
            *resource_id = view.files_context_id;
            return 0;
        case 3u:
            *resource_id = view.fs_context_id;
            return 0;
        case 4u:
            *resource_id = view.sighand_context_id;
            return 0;
        case 5u:
            *resource_id = view.io_context_id;
            return 0;
        case 6u:
            *resource_id = view.sysvsem_context_id;
            return 0;
        default:
            return -1;
    }
}

int kernel_current_pid(void) {
    kernel_task_identity_view_t view;
    return kernel_arch_current_identity_sample(&view) < 0 ? -1 : view.tid;
}

int kernel_current_identity(int32_t *pid, uint32_t *euid, uint32_t *egid) {
    kernel_task_identity_view_t view;

    if (kernel_arch_current_identity_sample(&view) < 0) return -1;
    if (pid) *pid = view.tid;
    if (euid) *euid = view.fsuid;
    if (egid) *egid = view.fsgid;
    return 0;
}

int kernel_current_no_new_privileges(void) {
    kernel_linux_prctl_state_t state;
    return kernel_current_prctl_state_get(&state) == 0 &&
           state.no_new_privileges != 0;
}
