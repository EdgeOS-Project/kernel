/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent native task view policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include <string.h>

static int current_view(kernel_process_native_view_t *view) {
    if (!view) return -1;
    memset(view, 0, sizeof(*view));
    return edge_process_runtime_current_view(view);
}

static int task_view(int32_t pid, kernel_process_native_view_t *view) {
    if (!view) return -1;
    memset(view, 0, sizeof(*view));
    return edge_process_runtime_view(pid, view);
}

int kernel_arch_current_linux_thread_state(
    kernel_linux_thread_state_t **state) {
    kernel_process_native_view_t view;

    if (!state || current_view(&view) < 0 || !view.linux_thread)
        return -1;
    *state = view.linux_thread;
    return 0;
}

int kernel_arch_process_linux_thread_state(
    int32_t pid, kernel_linux_thread_state_t **state) {
    kernel_process_native_view_t view;

    if (!state || task_view(pid, &view) < 0 || view.zombie ||
        !view.linux_thread)
        return -1;
    *state = view.linux_thread;
    return 0;
}

const char *kernel_current_comm(void) {
    kernel_process_native_view_t view;

    return current_view(&view) == 0 && view.comm ? view.comm : "unknown";
}

uintptr_t kernel_current_context_token(void) {
    kernel_process_native_view_t view;

    return current_view(&view) == 0 ? view.context_token : 0;
}

edge_namespace_set_t *kernel_arch_current_namespace_set(void) {
    kernel_process_native_view_t view;

    return current_view(&view) == 0 ? view.namespaces : 0;
}

void kernel_arch_current_namespace_committed(
    const edge_namespace_set_t *namespaces) {
    if (namespaces)
        edge_process_runtime_namespace_committed(namespaces);
}

int kernel_arch_current_fs_snapshot(char *cwd, uint32_t cwd_capacity,
                                    char *root, uint32_t root_capacity) {
    kernel_process_native_view_t view;

    if (!cwd || !root) return -EDGE_LINUX_EIO;
    if (!cwd_capacity || !root_capacity) return -EDGE_LINUX_EINVAL;
    if (current_view(&view) < 0 || view.pid <= 0)
        return -EDGE_LINUX_EIO;
    return edge_process_runtime_fs_snapshot(
        view.pid, cwd, cwd_capacity, root, root_capacity);
}

int kernel_arch_current_fs_set_location(const char *path, int set_root) {
    kernel_process_native_view_t view;

    if (!path || current_view(&view) < 0 || view.pid <= 0)
        return -EDGE_LINUX_EIO;
    return edge_process_runtime_fs_set_location(
        view.pid, path, set_root != 0);
}

int kernel_arch_current_fs_unshare(void) {
    kernel_process_native_view_t view;

    if (current_view(&view) < 0 || view.pid <= 0)
        return -EDGE_LINUX_EIO;
    return edge_process_runtime_fs_unshare(view.pid);
}

int kernel_arch_proc_task_fs_snapshot(int32_t pid, char *cwd,
                                      uint32_t cwd_capacity, char *root,
                                      uint32_t root_capacity) {
    if (pid <= 0 ||
        ((!cwd || !cwd_capacity) && (!root || !root_capacity)))
        return -EDGE_LINUX_EINVAL;
    return edge_process_runtime_fs_snapshot(
        pid, cwd, cwd_capacity, root, root_capacity);
}

int kernel_arch_ptrace_task_runtime(
    int32_t pid, edge_linux_ptrace_task_runtime_t *runtime) {
    kernel_process_native_view_t view;

    if (!runtime || task_view(pid, &view) < 0 || !view.ptrace ||
        !view.signal_mask)
        return -EDGE_LINUX_ESRCH;
    memset(runtime, 0, sizeof(*runtime));
    runtime->pid = view.pid;
    runtime->tgid = view.tgid;
    runtime->ppid = view.ppid;
    runtime->uid = view.uid;
    runtime->euid = view.euid;
    runtime->suid = view.suid;
    runtime->gid = view.gid;
    runtime->egid = view.egid;
    runtime->sgid = view.sgid;
    runtime->dumpable = view.dumpable;
    runtime->stopped = view.stopped;
    runtime->zombie = view.zombie;
    runtime->stop_reported = view.stop_reported;
    runtime->stop_signal = view.stop_signal;
    runtime->ptrace = view.ptrace;
    runtime->signal_mask = view.signal_mask;
    runtime->rseq_address = view.linux_thread ?
        view.linux_thread->rseq.address : 0;
    runtime->rseq_size = view.linux_thread ?
        view.linux_thread->rseq.length : 0;
    runtime->rseq_signature = view.linux_thread ?
        view.linux_thread->rseq.signature : 0;
    return 0;
}
