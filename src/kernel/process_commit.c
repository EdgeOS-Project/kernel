/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent process commit runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/process_runtime.h"
#include "kernel/linux_errno.h"

static int32_t process_task_tgid(const kernel_proc_task_view_t *view) {
    return view->tgid > 0 ? view->tgid : view->tid;
}

static int process_task_view_locked(kernel_process_task_handle_t handle,
                                    kernel_proc_task_view_t *view) {
    if (!handle || !view) return -1;
    return arch_process_task_view_locked(handle, view);
}

static uint32_t process_scheduler_cpu_count(uint64_t mask) {
    uint32_t count = 0;

    while (mask) {
        mask &= mask - 1u;
        ++count;
    }
    return count ? count : 1u;
}

static uint64_t process_deadline_bandwidth(
    const edge_linux_scheduler_state_t *state) {
    const uint64_t scale = 1000000u;
    uint64_t period;
    uint64_t quotient = 0;
    uint64_t remainder = 0;
    int bit;

    if (!state || state->policy != EDGE_LINUX_SCHED_DEADLINE)
        return 0;
    period = state->period ? state->period : state->deadline;
    if (!state->runtime || !period || state->runtime > period)
        return UINT64_MAX;
    for (bit = 63; bit > 0 && !(scale & (1ull << bit)); --bit) {}
    for (; bit >= 0; --bit) {
        quotient <<= 1;
        if (remainder >= period - remainder) {
            remainder -= period - remainder;
            ++quotient;
        } else {
            remainder += remainder;
        }
        if (!(scale & (1ull << bit))) continue;
        if (remainder >= period - state->runtime) {
            remainder -= period - state->runtime;
            ++quotient;
        } else {
            remainder += state->runtime;
        }
    }
    if (remainder) ++quotient;
    return quotient;
}

static int process_deadline_admit_locked(
    int32_t target_tid,
    const edge_linux_scheduler_state_t *requested) {
    const uint64_t scale = 1000000u;
    uint64_t online = kernel_scheduler_online_cpu_mask();
    uint64_t capacity =
        (uint64_t)process_scheduler_cpu_count(online) * scale;
    uint64_t total = 0;

    if (!online) online = 1u;
    if (requested->policy == EDGE_LINUX_SCHED_DEADLINE &&
        (requested->affinity_mask & online) != online)
        return -1;
    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t task;
        const edge_linux_scheduler_state_t *state;
        uint64_t bandwidth;

        if (process_task_view_locked(handle, &task) != 0 ||
            task.state == KERNEL_PROC_TASK_ZOMBIE)
            continue;
        state = task.tid == target_tid ? requested : &task.scheduler;
        if (state->policy != EDGE_LINUX_SCHED_DEADLINE) continue;
        if ((state->affinity_mask & online) != online) return -1;
        bandwidth = process_deadline_bandwidth(state);
        if (bandwidth == UINT64_MAX || bandwidth > capacity ||
            total > capacity - bandwidth)
            return -1;
        total += bandwidth;
    }
    return total <= capacity ? 0 : -1;
}

static kernel_process_task_handle_t process_task_find_leader_locked(
    int32_t tgid, kernel_proc_task_view_t *view) {
    uint32_t capacity = arch_process_task_capacity();

    for (uint32_t slot = 0; slot < capacity; ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t candidate;
        if (process_task_view_locked(handle, &candidate) != 0)
            continue;
        if (candidate.tid != tgid || process_task_tgid(&candidate) != tgid)
            continue;
        if (view) *view = candidate;
        return handle;
    }
    return 0;
}

static int process_session_member_matches(
    const kernel_proc_task_view_t *view,
    const edge_linux_process_session_member_t *member) {
    return view && member && process_task_tgid(view) == member->pid &&
        view->ppid == member->ppid && view->pgid == member->pgid &&
        view->sid == member->sid &&
        view->execed_since_fork == member->execed_since_fork;
}

int kernel_arch_proc_task_sample(uint32_t slot,
                                 kernel_proc_task_view_t *view) {
    kernel_process_task_handle_t handle;
    uint64_t flags;
    int status;

    if (!view || slot >= arch_process_task_capacity()) return -1;
    flags = arch_process_task_lock();
    handle = arch_process_task_at_locked(slot);
    status = process_task_view_locked(handle, view);
    arch_process_task_unlock(flags);
    return status;
}

int kernel_arch_proc_task_lookup(int32_t tid,
                                 kernel_proc_task_view_t *view) {
    kernel_process_task_handle_t handle;
    uint64_t flags;
    int status;

    if (!view || tid <= 0) return -1;
    flags = arch_process_task_lock();
    handle = arch_process_task_find_locked(tid);
    status = process_task_view_locked(handle, view);
    arch_process_task_unlock(flags);
    return status == 0 ? 0 : -1;
}

int kernel_arch_proc_task_at_ordinal(uint32_t ordinal, int32_t *pid_out) {
    uint32_t capacity;
    uint64_t flags;

    if (!pid_out) return -1;
    flags = arch_process_task_lock();
    capacity = arch_process_task_capacity();
    for (uint32_t slot = 0; slot < capacity; ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_task_identity_view_t identity;
        int32_t tgid;

        if (!handle ||
            arch_process_task_identity_locked(handle, &identity) != 0)
            continue;
        tgid = identity.tgid > 0 ? identity.tgid : identity.tid;
        if (identity.tid <= 0 || tgid <= 0 || identity.tid != tgid)
            continue;
        if (ordinal) {
            --ordinal;
            continue;
        }
        *pid_out = identity.tid;
        arch_process_task_unlock(flags);
        return 0;
    }
    arch_process_task_unlock(flags);
    return -1;
}

int kernel_arch_proc_thread_at_ordinal(int32_t tgid, uint32_t ordinal,
                                       int32_t *tid_out) {
    uint32_t capacity;
    uint64_t flags;

    if (tgid <= 0 || !tid_out) return -1;
    flags = arch_process_task_lock();
    capacity = arch_process_task_capacity();
    for (uint32_t slot = 0; slot < capacity; ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_task_identity_view_t identity;
        int32_t identity_tgid;

        if (!handle ||
            arch_process_task_identity_locked(handle, &identity) != 0)
            continue;
        identity_tgid = identity.tgid > 0 ? identity.tgid : identity.tid;
        if (identity.tid <= 0 || identity_tgid != tgid) continue;
        if (ordinal) {
            --ordinal;
            continue;
        }
        *tid_out = identity.tid;
        arch_process_task_unlock(flags);
        return 0;
    }
    arch_process_task_unlock(flags);
    return -1;
}

uint32_t kernel_arch_proc_thread_group_count(int32_t tgid) {
    uint32_t threads = 0;
    uint32_t capacity;
    uint64_t flags;

    if (tgid <= 0) return 0;
    flags = arch_process_task_lock();
    capacity = arch_process_task_capacity();
    for (uint32_t slot = 0; slot < capacity; ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_task_identity_view_t identity;
        int32_t identity_tgid;

        if (!handle ||
            arch_process_task_identity_locked(handle, &identity) != 0)
            continue;
        identity_tgid = identity.tgid > 0 ? identity.tgid : identity.tid;
        if (identity.tid > 0 && identity_tgid == tgid) ++threads;
    }
    arch_process_task_unlock(flags);
    return threads;
}

int kernel_arch_current_identity_sample(kernel_task_identity_view_t *view) {
    kernel_process_task_handle_t handle;
    uint64_t flags;
    int status;

    if (!view) return -1;
    flags = arch_process_task_lock();
    handle = arch_process_current_task_locked();
    status = arch_process_task_identity_locked(handle, view);
    arch_process_task_unlock(flags);
    return status == 0 ? 0 : -1;
}

static void process_prctl_state_from_view(
    const kernel_proc_task_view_t *view,
    kernel_linux_prctl_state_t *state) {
    uint32_t index;

    state->parent_death_signal = view->parent_death_signal;
    state->dumpable = view->dumpable;
    state->no_new_privileges = view->no_new_privileges;
    state->thp_disabled = view->thp_disabled;
    state->child_subreaper = view->child_subreaper;
    state->timer_slack_ns = view->timer_slack_ns;
    for (index = 0; index < sizeof(state->name); ++index)
        state->name[index] = 0;
    for (index = 0; index + 1u < sizeof(state->name); ++index) {
        state->name[index] = view->comm[index];
        if (!view->comm[index]) break;
    }
}

int kernel_arch_current_prctl_state_commit(
    const kernel_linux_prctl_commit_t *commit) {
    kernel_process_task_handle_t handle;
    kernel_proc_task_view_t target;
    kernel_linux_prctl_state_t current = {0};
    kernel_process_task_update_t update = {0};
    uint64_t flags;

    if (!commit || commit->tid <= 0 || commit->expected_tgid <= 0)
        return -1;
    flags = arch_process_task_lock();
    handle = arch_process_task_find_locked(commit->tid);
    if (process_task_view_locked(handle, &target) != 0 ||
        target.state == KERNEL_PROC_TASK_ZOMBIE ||
        process_task_tgid(&target) != commit->expected_tgid) {
        arch_process_task_unlock(flags);
        return -1;
    }
    process_prctl_state_from_view(&target, &current);
    if (!kernel_linux_prctl_state_matches(
            &current, &commit->expected, commit->update_mask)) {
        arch_process_task_unlock(flags);
        return -1;
    }

    update.fields = KERNEL_PROCESS_TASK_UPDATE_PRCTL;
    update.prctl = commit->requested;
    update.prctl_update_mask = commit->update_mask &
        (EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL |
         EDGE_LINUX_PRCTL_UPDATE_NO_NEW_PRIVILEGES |
         EDGE_LINUX_PRCTL_UPDATE_TIMER_SLACK |
         EDGE_LINUX_PRCTL_UPDATE_NAME);
    if (update.prctl_update_mask)
        arch_process_task_apply_locked(handle, &update);

    if (commit->update_mask & EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER) {
        update.prctl_update_mask =
            EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER;
        for (uint32_t slot = 0;
             slot < arch_process_task_capacity(); ++slot) {
            kernel_process_task_handle_t peer =
                arch_process_task_at_locked(slot);
            kernel_proc_task_view_t view;
            if (process_task_view_locked(peer, &view) != 0 ||
                view.state == KERNEL_PROC_TASK_ZOMBIE ||
                process_task_tgid(&view) != commit->expected_tgid)
                continue;
            arch_process_task_apply_locked(peer, &update);
        }
    }

    update.prctl_update_mask = commit->update_mask &
        (EDGE_LINUX_PRCTL_UPDATE_DUMPABLE |
         EDGE_LINUX_PRCTL_UPDATE_THP_DISABLED);
    if (update.prctl_update_mask) {
        for (uint32_t slot = 0;
             slot < arch_process_task_capacity(); ++slot) {
            kernel_process_task_handle_t peer =
                arch_process_task_at_locked(slot);
            kernel_proc_task_view_t view;
            if (process_task_view_locked(peer, &view) != 0 ||
                view.state == KERNEL_PROC_TASK_ZOMBIE ||
                view.memory_context_id != target.memory_context_id)
                continue;
            arch_process_task_apply_locked(peer, &update);
        }
    }
    arch_process_task_unlock(flags);
    return 0;
}

edge_seccomp_state_t *kernel_arch_current_seccomp_state(void) {
    kernel_process_task_handle_t handle;
    edge_seccomp_state_t *state;
    uint64_t flags = arch_process_task_lock();
    handle = arch_process_current_task_locked();
    state = arch_process_task_seccomp_locked(handle);
    arch_process_task_unlock(flags);
    return state;
}

int kernel_arch_seccomp_synchronize_thread_group(
    const edge_seccomp_state_t *previous,
    const edge_seccomp_state_t *installed, uint32_t flags) {
    kernel_process_task_handle_t current_handle;
    kernel_proc_task_view_t current;
    uint32_t retained = 0;
    uint64_t irq_flags;
    int32_t group;

    if (!previous || !installed) return -EDGE_LINUX_EINVAL;
    irq_flags = arch_process_task_lock();
    current_handle = arch_process_current_task_locked();
    if (process_task_view_locked(current_handle, &current) != 0 ||
        !arch_process_task_seccomp_locked(current_handle)) {
        arch_process_task_unlock(irq_flags);
        return -EDGE_LINUX_EINVAL;
    }
    group = process_task_tgid(&current);

    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t peer =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t view;
        edge_seccomp_state_t *state;
        if (peer == current_handle ||
            process_task_view_locked(peer, &view) != 0 ||
            view.state == KERNEL_PROC_TASK_ZOMBIE ||
            process_task_tgid(&view) != group)
            continue;
        state = arch_process_task_seccomp_locked(peer);
        if (!state || !edge_seccomp_state_is_ancestor(state, previous)) {
            int32_t failed_tid = view.tid;
            arch_process_task_unlock(irq_flags);
            return (flags & EDGE_LINUX_SECCOMP_FILTER_FLAG_TSYNC_ESRCH) ?
                -EDGE_LINUX_ESRCH : failed_tid;
        }
    }

    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t peer =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t view;
        edge_seccomp_state_t reference;
        if (peer == current_handle ||
            process_task_view_locked(peer, &view) != 0 ||
            view.state == KERNEL_PROC_TASK_ZOMBIE ||
            process_task_tgid(&view) != group)
            continue;
        reference = *installed;
        if (edge_seccomp_state_retain(&reference) < 0) {
            while (retained--) {
                reference = *installed;
                edge_seccomp_state_release(&reference);
            }
            arch_process_task_unlock(irq_flags);
            return -EDGE_LINUX_ENOMEM;
        }
        ++retained;
    }

    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t peer =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t view;
        if (peer == current_handle ||
            process_task_view_locked(peer, &view) != 0 ||
            view.state == KERNEL_PROC_TASK_ZOMBIE ||
            process_task_tgid(&view) != group)
            continue;
        arch_process_task_seccomp_replace_locked(
            peer, installed, current.no_new_privileges != 0);
    }
    arch_process_task_unlock(irq_flags);
    return 0;
}

int kernel_arch_current_credentials_commit(
    const linux_credential_state_t *credentials,
    int clear_parent_death_signal) {
    kernel_process_task_handle_t handle;
    kernel_proc_task_view_t current;
    kernel_process_task_update_t update = {0};
    uint64_t flags;

    if (!credentials) return -1;
    flags = arch_process_task_lock();
    handle = arch_process_current_task_locked();
    if (process_task_view_locked(handle, &current) != 0 ||
        current.state == KERNEL_PROC_TASK_ZOMBIE) {
        arch_process_task_unlock(flags);
        return -1;
    }
    update.fields = KERNEL_PROCESS_TASK_UPDATE_CREDENTIALS;
    update.credentials = *credentials;
    update.clear_parent_death_signal =
        clear_parent_death_signal ? 1u : 0u;
    arch_process_task_apply_locked(handle, &update);
    arch_process_task_unlock(flags);
    return 0;
}

int kernel_arch_process_credentials_commit(
    int32_t tid, const linux_credential_state_t *credentials,
    int clear_parent_death_signal) {
    kernel_process_task_handle_t handle;
    kernel_proc_task_view_t target;
    kernel_process_task_update_t update = {0};
    uint64_t flags;

    if (tid <= 0 || !credentials) return -1;
    flags = arch_process_task_lock();
    handle = arch_process_task_find_locked(tid);
    if (process_task_view_locked(handle, &target) != 0 ||
        target.state == KERNEL_PROC_TASK_ZOMBIE) {
        arch_process_task_unlock(flags);
        return -1;
    }
    update.fields = KERNEL_PROCESS_TASK_UPDATE_CREDENTIALS;
    update.credentials = *credentials;
    update.clear_parent_death_signal =
        clear_parent_death_signal ? 1u : 0u;
    arch_process_task_apply_locked(handle, &update);
    arch_process_task_unlock(flags);
    return 0;
}

int kernel_arch_process_groups_snapshot(int32_t tid,
                                        linux_group_list_t *groups) {
    kernel_process_task_handle_t handle;
    kernel_proc_task_view_t target;
    linux_group_list_t retained;
    kernel_process_task_update_t update = {0};
    uint64_t flags;
    int result = -1;

    if (!groups || tid <= 0) return -1;
    linux_group_list_init(&retained);
    flags = arch_process_task_lock();
    handle = arch_process_task_find_locked(tid);
    if (process_task_view_locked(handle, &target) != 0) {
        arch_process_task_unlock(flags);
        return -1;
    }
    update.fields = KERNEL_PROCESS_TASK_UPDATE_GROUPS;
    update.groups = 0;
    update.previous_groups = &retained;
    update.result = &result;
    arch_process_task_apply_locked(handle, &update);
    arch_process_task_unlock(flags);
    if (result < 0) return -1;
    *groups = retained;
    return 0;
}

int kernel_arch_current_groups_commit(linux_group_list_t *groups) {
    kernel_process_task_handle_t handle;
    kernel_proc_task_view_t current;
    linux_group_list_t previous;
    kernel_process_task_update_t update = {0};
    uint64_t flags;
    int result = -1;

    if (!groups) return -1;
    linux_group_list_init(&previous);
    flags = arch_process_task_lock();
    handle = arch_process_current_task_locked();
    if (process_task_view_locked(handle, &current) != 0 ||
        current.state == KERNEL_PROC_TASK_ZOMBIE) {
        arch_process_task_unlock(flags);
        return -1;
    }
    update.fields = KERNEL_PROCESS_TASK_UPDATE_GROUPS;
    update.groups = groups;
    update.previous_groups = &previous;
    update.result = &result;
    arch_process_task_apply_locked(handle, &update);
    arch_process_task_unlock(flags);
    if (result < 0) return -1;
    linux_group_list_release(&previous);
    return 0;
}

int kernel_arch_current_umask_commit(uint16_t mask, uint16_t *previous) {
    kernel_process_task_handle_t current_handle;
    kernel_proc_task_view_t current;
    kernel_process_task_update_t update = {
        .fields = KERNEL_PROCESS_TASK_UPDATE_UMASK,
        .umask = (uint16_t)(mask & 0777u),
    };
    uint64_t flags;

    if (!previous) return -1;
    flags = arch_process_task_lock();
    current_handle = arch_process_current_task_locked();
    if (process_task_view_locked(current_handle, &current) != 0 ||
        current.state == KERNEL_PROC_TASK_ZOMBIE) {
        arch_process_task_unlock(flags);
        return -1;
    }
    *previous = (uint16_t)(current.umask & 0777u);
    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t peer;
        if (process_task_view_locked(handle, &peer) != 0 ||
            peer.state == KERNEL_PROC_TASK_ZOMBIE ||
            peer.fs_context_id != current.fs_context_id)
            continue;
        arch_process_task_apply_locked(handle, &update);
    }
    arch_process_task_unlock(flags);
    return 0;
}

int kernel_arch_current_membarrier_state(uint32_t **registrations) {
    kernel_process_task_handle_t current_handle;
    kernel_process_task_handle_t owner_handle;
    kernel_proc_task_view_t current;
    kernel_proc_task_view_t owner;
    uint64_t flags;

    if (!registrations) return -1;
    flags = arch_process_task_lock();
    current_handle = arch_process_current_task_locked();
    if (process_task_view_locked(current_handle, &current) != 0 ||
        current.state == KERNEL_PROC_TASK_ZOMBIE) {
        arch_process_task_unlock(flags);
        return -1;
    }
    owner_handle = arch_process_task_find_locked(process_task_tgid(&current));
    if (process_task_view_locked(owner_handle, &owner) != 0 ||
        owner.state == KERNEL_PROC_TASK_ZOMBIE)
        owner_handle = current_handle;
    *registrations = arch_process_task_membarrier_locked(owner_handle);
    arch_process_task_unlock(flags);
    return *registrations ? 0 : -1;
}

int kernel_arch_process_session_commit(
    const edge_linux_process_session_commit_t *commit) {
    kernel_process_task_handle_t caller_handle;
    kernel_process_task_handle_t current_handle;
    kernel_process_task_handle_t target_handle;
    kernel_proc_task_view_t caller;
    kernel_proc_task_view_t current;
    kernel_proc_task_view_t target;
    kernel_process_task_update_t update = {0};
    uint64_t flags;
    int changed = 0;

    if (!commit) return -1;
    flags = arch_process_task_lock();
    caller_handle = arch_process_current_task_locked();
    current_handle = process_task_find_leader_locked(
        commit->current.pid, &current);
    target_handle = process_task_find_leader_locked(
        commit->target.pid, &target);
    if (process_task_view_locked(caller_handle, &caller) != 0 ||
        caller.tid != commit->caller_tid ||
        process_task_tgid(&caller) != commit->current.pid ||
        !current_handle || current.state == KERNEL_PROC_TASK_ZOMBIE ||
        !target_handle ||
        !process_session_member_matches(&current, &commit->current) ||
        !process_session_member_matches(&target, &commit->target))
        goto out;

    if (commit->required_existing_pgid) {
        int found = 0;
        uint32_t capacity = arch_process_task_capacity();
        for (uint32_t slot = 0; slot < capacity; ++slot) {
            kernel_proc_task_view_t candidate;
            if (process_task_view_locked(
                    arch_process_task_at_locked(slot), &candidate) != 0 ||
                candidate.tid != process_task_tgid(&candidate))
                continue;
            if (candidate.pgid == commit->required_existing_pgid &&
                candidate.sid == commit->current.sid) {
                found = 1;
                break;
            }
        }
        if (!found) goto out;
    }

    if (commit->require_absent_process_group) {
        uint32_t capacity = arch_process_task_capacity();
        for (uint32_t slot = 0; slot < capacity; ++slot) {
            kernel_proc_task_view_t candidate;
            if (process_task_view_locked(
                    arch_process_task_at_locked(slot), &candidate) != 0 ||
                candidate.tid != process_task_tgid(&candidate))
                continue;
            if (candidate.pgid == commit->current.pid)
                goto out;
        }
    }

    update.fields = KERNEL_PROCESS_TASK_UPDATE_SESSION;
    update.pgid = commit->new_pgid;
    update.sid = commit->new_sid;
    update.detach_controlling_terminal =
        commit->detach_controlling_terminal;
    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t candidate;
        if (process_task_view_locked(handle, &candidate) != 0 ||
            process_task_tgid(&candidate) != commit->target.pid)
            continue;
        arch_process_task_apply_locked(handle, &update);
        changed = 1;
    }

out:
    arch_process_task_unlock(flags);
    return changed ? 0 : -1;
}

int kernel_arch_process_exec_committed(int32_t tgid) {
    kernel_process_task_update_t update = {
        .fields = KERNEL_PROCESS_TASK_UPDATE_EXEC,
        .execed_since_fork = 1,
    };
    uint64_t flags;
    int changed = 0;

    if (tgid <= 0) return -1;
    flags = arch_process_task_lock();
    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t candidate;
        if (process_task_view_locked(handle, &candidate) != 0 ||
            process_task_tgid(&candidate) != tgid)
            continue;
        arch_process_task_apply_locked(handle, &update);
        changed = 1;
    }
    arch_process_task_unlock(flags);
    return changed ? 0 : -1;
}

int kernel_arch_proc_cgroup_attach(int32_t pid, int32_t expected_tgid,
                                   uint32_t cgroup_id,
                                   int entire_thread_group) {
    kernel_process_task_handle_t target_handle;
    kernel_proc_task_view_t target;
    kernel_process_task_update_t update = {
        .fields = KERNEL_PROCESS_TASK_UPDATE_CGROUP,
        .cgroup_id = cgroup_id,
    };
    uint64_t flags;

    if (pid <= 0) return -1;
    flags = arch_process_task_lock();
    target_handle = arch_process_task_find_locked(pid);
    if (process_task_view_locked(target_handle, &target) != 0 ||
        target.state == KERNEL_PROC_TASK_ZOMBIE ||
        process_task_tgid(&target) != expected_tgid) {
        arch_process_task_unlock(flags);
        return -1;
    }
    if (!entire_thread_group) {
        arch_process_task_apply_locked(target_handle, &update);
        arch_process_task_unlock(flags);
        return 0;
    }
    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t member;
        if (process_task_view_locked(handle, &member) != 0 ||
            member.state == KERNEL_PROC_TASK_ZOMBIE ||
            process_task_tgid(&member) != expected_tgid)
            continue;
        arch_process_task_apply_locked(handle, &update);
    }
    arch_process_task_unlock(flags);
    return 0;
}

int kernel_arch_process_resource_limit_commit(
    int32_t tid, int32_t expected_tgid, uint32_t resource,
    const kernel_resource_limit_t *limit) {
    kernel_process_task_handle_t target_handle;
    kernel_proc_task_view_t target;
    kernel_process_task_update_t update = {0};
    uint64_t flags;

    if (!limit || expected_tgid <= 0 ||
        resource >= EDGE_LINUX_RLIMIT_COUNT)
        return -1;
    flags = arch_process_task_lock();
    target_handle = arch_process_task_find_locked(tid);
    if (process_task_view_locked(target_handle, &target) != 0 ||
        target.state == KERNEL_PROC_TASK_ZOMBIE ||
        process_task_tgid(&target) != expected_tgid) {
        arch_process_task_unlock(flags);
        return -1;
    }
    update.fields = KERNEL_PROCESS_TASK_UPDATE_RESOURCE_LIMIT;
    update.resource = resource;
    update.resource_limit = *limit;
    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t member;
        if (process_task_view_locked(handle, &member) != 0 ||
            process_task_tgid(&member) != expected_tgid)
            continue;
        arch_process_task_apply_locked(handle, &update);
    }
    arch_process_task_unlock(flags);
    return 0;
}

int kernel_arch_process_oom_score_adj_commit(
    const kernel_oom_score_adj_commit_t *commit) {
    kernel_process_task_handle_t current_handle;
    kernel_process_task_handle_t target_handle;
    kernel_proc_task_view_t current;
    kernel_proc_task_view_t target;
    kernel_process_task_update_t update = {0};
    uint64_t flags;

    if (!commit) return -1;
    flags = arch_process_task_lock();
    current_handle = arch_process_current_task_locked();
    target_handle = arch_process_task_find_locked(commit->target_tid);
    if (process_task_view_locked(current_handle, &current) != 0 ||
        process_task_view_locked(target_handle, &target) != 0 ||
        current.state == KERNEL_PROC_TASK_ZOMBIE ||
        target.state == KERNEL_PROC_TASK_ZOMBIE ||
        current.tid != commit->caller_tid ||
        current.euid != commit->caller_euid ||
        current.capabilities.effective !=
            commit->caller_effective_capabilities ||
        process_task_tgid(&target) != commit->target_tgid ||
        target.uid != commit->target_uid ||
        target.suid != commit->target_suid ||
        target.oom_score_adj_min != commit->target_minimum) {
        arch_process_task_unlock(flags);
        return -1;
    }
    update.fields = KERNEL_PROCESS_TASK_UPDATE_OOM;
    update.oom_score_adj = commit->value;
    update.oom_score_adj_min = commit->new_minimum;
    for (uint32_t slot = 0; slot < arch_process_task_capacity(); ++slot) {
        kernel_process_task_handle_t handle =
            arch_process_task_at_locked(slot);
        kernel_proc_task_view_t member;
        if (process_task_view_locked(handle, &member) != 0 ||
            member.state == KERNEL_PROC_TASK_ZOMBIE ||
            process_task_tgid(&member) != commit->target_tgid)
            continue;
        arch_process_task_apply_locked(handle, &update);
    }
    arch_process_task_unlock(flags);
    return 0;
}

int kernel_arch_process_io_priority_commit(
    const kernel_process_io_priority_commit_t *commit) {
    kernel_process_task_handle_t handle;
    kernel_proc_task_view_t target;
    kernel_process_task_update_t update = {0};
    uint64_t flags;

    if (!commit || commit->tid <= 0 || commit->expected_tgid <= 0)
        return -1;
    flags = arch_process_task_lock();
    handle = arch_process_task_find_locked(commit->tid);
    if (process_task_view_locked(handle, &target) != 0 ||
        target.state == KERNEL_PROC_TASK_ZOMBIE ||
        process_task_tgid(&target) != commit->expected_tgid ||
        target.uid != commit->expected_uid ||
        target.euid != commit->expected_euid) {
        arch_process_task_unlock(flags);
        return -1;
    }
    update.fields = KERNEL_PROCESS_TASK_UPDATE_IO_PRIORITY;
    update.io_priority = commit->io_priority;
    arch_process_task_apply_locked(handle, &update);
    arch_process_task_unlock(flags);
    return 0;
}

int kernel_arch_scheduler_state_commit(
    const kernel_scheduler_state_commit_t *commit) {
    kernel_process_task_handle_t handle;
    kernel_proc_task_view_t target;
    kernel_process_task_update_t update = {0};
    edge_linux_scheduler_state_t effective;
    uint64_t flags;

    if (!commit) return -1;
    flags = arch_process_task_lock();
    handle = arch_process_task_find_locked(commit->target.tid);
    if (process_task_view_locked(handle, &target) != 0 ||
        target.state == KERNEL_PROC_TASK_ZOMBIE ||
        process_task_tgid(&target) != commit->target.tgid ||
        target.uid != commit->target.uid ||
        target.euid != commit->target.euid ||
        target.suid != commit->target.suid ||
        !edge_linux_scheduler_state_equal(
            &target.scheduler, &commit->target.state)) {
        arch_process_task_unlock(flags);
        return -1;
    }
    effective = target.scheduler;
    edge_linux_scheduler_state_apply_updates(
        &effective, &commit->requested, commit->update_mask);
    if (process_deadline_admit_locked(commit->target.tid, &effective) < 0) {
        arch_process_task_unlock(flags);
        return -2;
    }
    update.fields = KERNEL_PROCESS_TASK_UPDATE_SCHEDULER;
    update.scheduler = commit->requested;
    update.scheduler_update_mask = commit->update_mask;
    arch_process_task_apply_locked(handle, &update);
    arch_process_task_unlock(flags);
    return 0;
}
