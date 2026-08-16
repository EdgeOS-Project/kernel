/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux procfs task runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/exec_runtime.h"
#include "kernel/mm_runtime.h"
#include "kernel/proc_maps.h"
#include "kernel/process_runtime.h"
#include "mm/arch_vm.h"
#include "string.h"

#define KERNEL_PROC_PAGE_SIZE 4096u
#define KERNEL_PROC_CLOCK_TICK_US 10000u

static int32_t kernel_proc_view_tgid(const kernel_proc_task_view_t *view) {
    return view->tgid > 0 ? view->tgid : view->tid;
}

static int kernel_proc_view_is_visible(
    const kernel_proc_task_view_t *view) {
    return view && view->tid > 0 && kernel_proc_view_tgid(view) > 0;
}

static char kernel_proc_view_state(const kernel_proc_task_view_t *view) {
    switch ((kernel_proc_task_state_t)view->state) {
        case KERNEL_PROC_TASK_RUNNING:
            return 'R';
        case KERNEL_PROC_TASK_STOPPED:
            return 'T';
        case KERNEL_PROC_TASK_ZOMBIE:
            return 'Z';
        case KERNEL_PROC_TASK_SLEEPING:
        default:
            return 'S';
    }
}

static __attribute__((noinline)) void kernel_proc_task_memory_snapshot(
    int32_t pid, uint64_t address_space,
    kernel_proc_task_snapshot_t *snapshot) {
    kernel_proc_vma_accounting_t accounting;
    uint64_t resident_pages;

    if (!snapshot) return;
    if (kernel_proc_vma_account(pid, &accounting) == 0) {
        snapshot->virtual_size_bytes = accounting.virtual_size_bytes;
        snapshot->text_size_bytes = accounting.text_size_bytes;
        snapshot->data_size_bytes = accounting.data_size_bytes;
        snapshot->stack_size_bytes = accounting.stack_size_bytes;
    }
    resident_pages = arch_vm_address_space_resident_pages(address_space);
    snapshot->resident_size_bytes =
        resident_pages > UINT64_MAX / KERNEL_PROC_PAGE_SIZE ? UINT64_MAX :
        resident_pages * KERNEL_PROC_PAGE_SIZE;
    snapshot->peak_resident_size_bytes = kernel_mm_resident_peak_observe(
        address_space, snapshot->resident_size_bytes);
    snapshot->locked_size_bytes =
        kernel_mm_lock_space_bytes(address_space);
}

void kernel_proc_task_view_set_identity(
    kernel_proc_task_view_t *view,
    const kernel_task_identity_view_t *identity) {
    if (!view || !identity) return;
    view->tid = identity->tid;
    view->tgid = identity->tgid;
    view->ppid = identity->ppid;
    view->pgid = identity->pgid;
    view->sid = identity->sid;
    view->pid_namespace_id = identity->pid_namespace_id;
    view->uid = identity->uid;
    view->euid = identity->euid;
    view->suid = identity->suid;
    view->fsuid = identity->fsuid;
    view->gid = identity->gid;
    view->egid = identity->egid;
    view->sgid = identity->sgid;
    view->fsgid = identity->fsgid;
    view->state = identity->state;
    view->dumpable = identity->dumpable;
    view->permitted_capabilities = identity->permitted_capabilities;
    view->effective_capabilities = identity->effective_capabilities;
}

void kernel_proc_task_view_set_names(kernel_proc_task_view_t *view,
                                     const char *comm,
                                     const char *exec_path) {
    if (!view) return;
    if (comm) {
        strncpy(view->comm, comm, sizeof(view->comm) - 1u);
        view->comm[sizeof(view->comm) - 1u] = 0;
    }
    if (exec_path) {
        strncpy(view->exec_path, exec_path,
                sizeof(view->exec_path) - 1u);
        view->exec_path[sizeof(view->exec_path) - 1u] = 0;
    }
}

int kernel_proc_task_view_get(int32_t tid, kernel_proc_task_view_t *view) {
    if (tid <= 0 || !view) return -1;
    return kernel_arch_proc_task_lookup(tid, view);
}

int kernel_proc_task_at(uint32_t ordinal, int32_t *pid_out) {
    return kernel_arch_proc_task_at_ordinal(ordinal, pid_out);
}

int kernel_proc_thread_at(int32_t tgid, uint32_t ordinal,
                          int32_t *tid_out) {
    return kernel_arch_proc_thread_at_ordinal(tgid, ordinal, tid_out);
}

int kernel_proc_task_load_snapshot(uint32_t *running_out,
                                   uint32_t *total_out) {
    kernel_proc_task_view_t view;
    uint32_t running = 0;
    uint32_t total = 0;

    if (!running_out || !total_out) return -1;
    for (uint32_t index = 0;; ++index) {
        int status = kernel_arch_proc_task_sample(index, &view);
        if (status < 0) break;
        if (status > 0) continue;
        if (!kernel_proc_view_is_visible(&view)) continue;
        ++total;
        if (view.state == KERNEL_PROC_TASK_RUNNING) ++running;
    }
    *running_out = running;
    *total_out = total;
    return 0;
}

int kernel_proc_task_snapshot(int32_t pid,
                              kernel_proc_task_snapshot_t *out) {
    kernel_proc_task_view_t target;
    uint32_t threads;

    if (pid <= 0 || !out) return -1;
    if (kernel_proc_task_view_get(pid, &target) < 0) return -1;
    threads = kernel_arch_proc_thread_group_count(
        kernel_proc_view_tgid(&target));

    memset(out, 0, sizeof(*out));
    out->pid = target.tid;
    out->tgid = kernel_proc_view_tgid(&target);
    out->ppid = target.ppid;
    out->pgid = target.pgid;
    out->sid = target.sid;
    out->tty_pgrp = target.tty_pgrp;
    out->nice_value = target.nice_value;
    out->threads = threads > UINT8_MAX ? UINT8_MAX : (uint8_t)threads;
    out->cgroup_id = target.cgroup_id;
    out->uid = target.uid;
    out->euid = target.euid;
    out->suid = target.suid;
    out->fsuid = target.fsuid;
    out->gid = target.gid;
    out->egid = target.egid;
    out->sgid = target.sgid;
    out->fsgid = target.fsgid;
    out->syscall_nr = target.syscall_nr;
    memcpy(out->syscall_args, target.syscall_args,
           sizeof(out->syscall_args));
    out->start_time_ticks = target.start_time_ticks;
    out->user_time_ticks =
        target.usage.user_time_us / KERNEL_PROC_CLOCK_TICK_US;
    out->system_time_ticks =
        target.usage.sys_time_us / KERNEL_PROC_CLOCK_TICK_US;
    out->children_user_time_ticks =
        target.children_usage.user_time_us / KERNEL_PROC_CLOCK_TICK_US;
    out->children_system_time_ticks =
        target.children_usage.sys_time_us / KERNEL_PROC_CLOCK_TICK_US;
    out->minor_faults = target.usage.minor_faults;
    out->major_faults = target.usage.major_faults;
    out->children_minor_faults = target.children_usage.minor_faults;
    out->children_major_faults = target.children_usage.major_faults;
    kernel_proc_task_memory_snapshot(
        pid, target.memory_context_id, out);
    out->processor = target.processor;
    out->scheduler_priority = target.scheduler.priority;
    out->scheduler_policy = target.scheduler.policy;
    out->state = kernel_proc_view_state(&target);
    memcpy(out->comm, target.comm, sizeof(out->comm));
    memcpy(out->exec_path, target.exec_path, sizeof(out->exec_path));
    return 0;
}

int kernel_proc_task_fs_snapshot(int32_t pid, char *cwd,
                                 uint32_t cwd_capacity, char *root,
                                 uint32_t root_capacity) {
    if (pid <= 0 || ((!cwd || !cwd_capacity) &&
                     (!root || !root_capacity)))
        return -1;
    return kernel_arch_proc_task_fs_snapshot(
        pid, cwd, cwd_capacity, root, root_capacity);
}

int kernel_proc_task_exec_file(int32_t pid, vfs_inode_t *inode,
                               vfs_superblock_t **superblock) {
    kernel_proc_task_view_t view;

    if (pid <= 0 || !inode || !superblock ||
        kernel_proc_task_view_get(pid, &view) < 0 ||
        !view.exec_file_handle)
        return -1;
    return kernel_exec_file_snapshot(
        view.exec_file_handle, superblock, inode);
}

int kernel_process_mount_namespace_id(int32_t pid, uint32_t *id_out) {
    kernel_proc_task_view_t view;

    if (pid <= 0 || !id_out) return -1;
    if (kernel_proc_task_view_get(pid, &view) < 0 ||
        view.mount_namespace_id == UINT32_MAX)
        return -1;
    *id_out = view.mount_namespace_id;
    return 0;
}

int kernel_proc_cgroup_attach(int32_t pid, uint32_t cgroup_id,
                              int entire_thread_group) {
    kernel_proc_task_view_t view;

    if (pid <= 0) return -1;
    if (kernel_proc_task_view_get(pid, &view) < 0 ||
        view.state == KERNEL_PROC_TASK_ZOMBIE)
        return -1;
    return kernel_arch_proc_cgroup_attach(
        view.tid, kernel_proc_view_tgid(&view), cgroup_id,
        entire_thread_group != 0);
}
