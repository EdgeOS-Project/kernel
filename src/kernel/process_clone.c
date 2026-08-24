/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux clone transaction.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/clone_runtime.h"
#include "fs/cgroupfs.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_ptrace.h"
#include "kernel/landlock_runtime.h"
#include "kernel/namespace_runtime.h"
#include "kernel/perf_event.h"
#include "kernel/process_runtime.h"
#include "kernel/scheduler_policy.h"
#include "kernel/userfaultfd.h"

static int64_t clone_fail(kernel_clone_state_t *state, int status) {
    if (state && state->userfaultfd_cloned) {
        kernel_userfaultfd_address_space_release(
            state->child_address_space);
        state->userfaultfd_cloned = 0;
    }
    if (state && state->prepared)
        process_clone_arch_abort(state);
    return status < 0 ? status : -EDGE_LINUX_EIO;
}

int64_t kernel_process_clone(const kernel_clone_request_t *request) {
    kernel_clone_prepare_t prepare;
    kernel_clone_configuration_t configuration;
    kernel_clone_state_t state;
    uint64_t flags;
    int status;
    int ptrace_event;
    kernel_linux_identity_t parent_identity;
    edge_linux_scheduler_state_t parent_scheduler;
    int64_t replay_result;

    if (!request || !request->user_registers)
        return -EDGE_LINUX_EINVAL;
    if (kernel_userfaultfd_consume_completed_fork(&replay_result))
        return replay_result;
    if (kernel_current_linux_identity(&parent_identity) < 0 ||
        kernel_scheduler_state_get(parent_identity.global_tid,
                                   &parent_scheduler) < 0)
        return -EDGE_LINUX_ESRCH;
    if (parent_scheduler.policy == EDGE_LINUX_SCHED_DEADLINE &&
        !(parent_scheduler.flags &
          EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK))
        return -EDGE_LINUX_EAGAIN;
    flags = request->flags;

    state.child_global_pid = 0;
    state.parent_visible_pid = 0;
    state.child_visible_pid = 0;
    state.pidfd = -1;
    state.architecture_token = 0;
    state.parent_address_space = 0;
    state.child_address_space = 0;
    state.userfaultfd_wait_ticket = 0;
    state.userfaultfd_wait_context = -1;
    state.architecture_state[0] = 0;
    state.architecture_state[1] = 0;
    state.prepared = 0;
    state.vfork_prepared = 0;
    state.published = 0;
    state.cgroup_accounted = 0;
    state.userfaultfd_cloned = 0;

    if (flags & EDGE_LINUX_CLONE_INTO_CGROUP) {
        status = process_clone_arch_validate_cgroup(
            request->cgroup_descriptor);
        if (status < 0) return status;
    }

    prepare.namespace_flags =
        flags & EDGE_LINUX_CLONE_NAMESPACE_FLAGS;
    prepare.user_registers = request->user_registers;
    prepare.share_vm = (flags & EDGE_LINUX_CLONE_VM) != 0;
    prepare.share_files = (flags & EDGE_LINUX_CLONE_FILES) != 0;
    prepare.vfork = (flags & EDGE_LINUX_CLONE_VFORK) != 0;
    prepare.is_thread = (flags & EDGE_LINUX_CLONE_THREAD) != 0;
    status = process_clone_arch_prepare(&prepare, &state);
    if (status < 0) return clone_fail(&state, status);
    if (!state.prepared || state.child_global_pid <= 0 ||
        state.parent_visible_pid <= 0 || state.child_visible_pid <= 0)
        return clone_fail(&state, -EDGE_LINUX_EIO);
    if ((flags & EDGE_LINUX_CLONE_NEWUSER) &&
        kernel_user_namespace_capabilities_grant(
            state.child_global_pid) < 0)
        return clone_fail(&state, -EDGE_LINUX_EIO);

    configuration.child_stack = request->child_stack;
    configuration.tls = request->tls;
    configuration.clear_child_tid =
        (flags & EDGE_LINUX_CLONE_CHILD_CLEARTID) ?
            request->child_tid_user : 0;
    configuration.exit_signal =
        prepare.is_thread ? 0u : request->exit_signal;
    configuration.signal_handlers =
        (flags & EDGE_LINUX_CLONE_SIGHAND) ?
            KERNEL_CLONE_SIGNAL_HANDLERS_SHARE :
        (flags & EDGE_LINUX_CLONE_CLEAR_SIGHAND) ?
            KERNEL_CLONE_SIGNAL_HANDLERS_CLEAR :
            KERNEL_CLONE_SIGNAL_HANDLERS_COPY;
    configuration.parent =
        prepare.is_thread ? KERNEL_CLONE_PARENT_THREAD_GROUP :
        (flags & EDGE_LINUX_CLONE_PARENT) ?
            KERNEL_CLONE_PARENT_INHERIT :
            KERNEL_CLONE_PARENT_CURRENT;
    configuration.share_fs =
        (flags & EDGE_LINUX_CLONE_FS) != 0;
    configuration.share_files = prepare.share_files;
    configuration.disable_altstack =
        prepare.share_vm && !prepare.vfork;
    configuration.set_tls =
        (flags & EDGE_LINUX_CLONE_SETTLS) != 0;
    status = process_clone_arch_configure(&configuration, &state);
    if (status < 0) return clone_fail(&state, status);

    if (!prepare.share_vm) {
        status = kernel_userfaultfd_address_space_fork(
            state.parent_address_space, state.child_address_space,
            state.child_global_pid,
            &state.userfaultfd_wait_context,
            &state.userfaultfd_wait_ticket);
        if (status < 0) return clone_fail(&state, status);
        state.userfaultfd_cloned = 1u;
    }

    if (flags & EDGE_LINUX_CLONE_INTO_CGROUP) {
        status = process_clone_arch_attach_cgroup(
            request->cgroup_descriptor, &state);
        if (status < 0)
            return clone_fail(&state, -EDGE_LINUX_EACCES);
    }

    status = cgroupfs_pids_validate_task(
        state.child_global_pid, state.cgroup_accounted);
    if (status < 0)
        return clone_fail(&state, -EDGE_LINUX_EAGAIN);

    /*
     * The child descriptor table must be complete before the parent receives
     * a pidfd. Otherwise a private-table child can accidentally inherit the
     * pidfd that refers to itself.
     */
    if (flags & EDGE_LINUX_CLONE_PIDFD) {
        status = process_clone_arch_install_pidfd(
            request->pidfd_user, &state);
        if (status < 0) return clone_fail(&state, status);
    }
    if (flags & EDGE_LINUX_CLONE_PARENT_SETTID) {
        status = process_clone_arch_write_parent_tid(
            request->parent_tid_user, &state);
        if (status < 0)
            return clone_fail(&state, -EDGE_LINUX_EFAULT);
    }
    if (flags & EDGE_LINUX_CLONE_CHILD_SETTID) {
        status = process_clone_arch_write_child_tid(
            request->child_tid_user, &state);
        if (status < 0)
            return clone_fail(&state, -EDGE_LINUX_EFAULT);
    }

    if (prepare.vfork) {
        status = process_clone_arch_prepare_vfork(&state);
        if (status < 0) return clone_fail(&state, status);
        state.vfork_prepared = 1;
    }

    ptrace_event = edge_linux_ptrace_clone_stop(
        request->user_registers, flags | request->exit_signal,
        state.child_global_pid, state.parent_visible_pid);
    if (ptrace_event < 0)
        return clone_fail(&state, ptrace_event);

#ifdef CONFIG_LANDLOCK
    status = kernel_landlock_task_clone(
        parent_identity.global_tid, state.child_global_pid,
        prepare.is_thread ? parent_identity.global_tgid :
                            state.child_global_pid);
    if (status < 0) return clone_fail(&state, status);
#endif

#ifdef CONFIG_PERF_EVENTS
    kernel_perf_event_task_fork(
        parent_identity.global_tid, state.child_global_pid);
#endif
    status = process_clone_arch_publish(&state, ptrace_event);
    if (status < 0) {
#ifdef CONFIG_PERF_EVENTS
        kernel_perf_event_task_exit(state.child_global_pid);
#endif
#ifdef CONFIG_LANDLOCK
        kernel_landlock_task_exit(
            state.child_global_pid,
            prepare.is_thread ? parent_identity.global_tgid :
                                state.child_global_pid,
            0);
#endif
        return clone_fail(&state, status);
    }
    state.published = 1;

    if (state.userfaultfd_wait_ticket)
        kernel_userfaultfd_wait_fork(
            state.userfaultfd_wait_context,
            state.userfaultfd_wait_ticket,
            state.parent_visible_pid);

    if (prepare.vfork) {
        status = process_clone_arch_wait_vfork(&state);
        if (status < 0) return status;
    }
    return state.parent_visible_pid;
}
