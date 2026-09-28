/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS process commit runtime unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdio.h>
#include <string.h>

#include "kernel/process_runtime.h"

#define TEST_TASKS 6u

typedef struct test_task {
    kernel_proc_task_view_t view;
    linux_group_list_t groups;
    edge_seccomp_state_t seccomp;
    uint32_t membarrier_registrations;
    int used;
    int detached;
    int rescheduled;
} test_task_t;

static test_task_t g_tasks[TEST_TASKS];
static uint32_t g_current;
static int g_failures;
static uint32_t g_full_view_reads;
static uint32_t g_identity_reads;

uint64_t kernel_scheduler_online_cpu_mask(void) {
    return 1u;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static int32_t test_tgid(const test_task_t *task) {
    return task->view.tgid > 0 ? task->view.tgid : task->view.tid;
}

int kernel_linux_prctl_state_matches(
    const kernel_linux_prctl_state_t *left,
    const kernel_linux_prctl_state_t *right, uint32_t update_mask) {
    if (!left || !right) return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL) &&
        left->parent_death_signal != right->parent_death_signal)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_DUMPABLE) &&
        left->dumpable != right->dumpable)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_NO_NEW_PRIVILEGES) &&
        left->no_new_privileges != right->no_new_privileges)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_TIMER_SLACK) &&
        left->timer_slack_ns != right->timer_slack_ns)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_THP_DISABLED) &&
        left->thp_disabled != right->thp_disabled)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER) &&
        left->child_subreaper != right->child_subreaper)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_NAME) &&
        memcmp(left->name, right->name, sizeof(left->name)) != 0)
        return 0;
    return 1;
}

void linux_group_list_init(linux_group_list_t *groups) {
    if (groups) memset(groups, 0, sizeof(*groups));
}

int linux_group_list_retain(linux_group_list_t *destination,
                            const linux_group_list_t *source) {
    if (!destination || !source) return -1;
    *destination = *source;
    return 0;
}

void linux_group_list_release(linux_group_list_t *groups) {
    linux_group_list_init(groups);
}

int edge_seccomp_state_retain(edge_seccomp_state_t *state) {
    return state ? 0 : -1;
}

void edge_seccomp_state_release(edge_seccomp_state_t *state) {
    if (state) memset(state, 0, sizeof(*state));
}

int edge_seccomp_state_is_ancestor(const edge_seccomp_state_t *ancestor,
                                   const edge_seccomp_state_t *descendant) {
    if (!ancestor || !descendant || ancestor->length > descendant->length)
        return 0;
    if (!ancestor->length) return ancestor->head_filter_id == 0;
    return ancestor->head_filter_id == descendant->head_filter_id;
}

uint64_t arch_process_task_lock(void) {
    return 0;
}

void arch_process_task_unlock(uint64_t flags) {
    (void)flags;
}

uint32_t arch_process_task_capacity(void) {
    return TEST_TASKS;
}

kernel_process_task_handle_t arch_process_task_at_locked(uint32_t slot) {
    return slot < TEST_TASKS ?
        (kernel_process_task_handle_t)(uintptr_t)&g_tasks[slot] : 0;
}

kernel_process_task_handle_t arch_process_task_find_locked(int32_t tid) {
    for (uint32_t slot = 0; slot < TEST_TASKS; ++slot) {
        if (g_tasks[slot].used && g_tasks[slot].view.tid == tid)
            return (kernel_process_task_handle_t)(uintptr_t)&g_tasks[slot];
    }
    return 0;
}

kernel_process_task_handle_t arch_process_current_task_locked(void) {
    return arch_process_task_at_locked(g_current);
}

int arch_process_task_view_locked(kernel_process_task_handle_t handle,
                                  kernel_proc_task_view_t *view) {
    test_task_t *task = (test_task_t *)(uintptr_t)handle;
    if (!task || !view || task < &g_tasks[0] ||
        task >= &g_tasks[TEST_TASKS])
        return -1;
    if (!task->used) return 1;
    ++g_full_view_reads;
    *view = task->view;
    return 0;
}

int arch_process_task_identity_locked(
    kernel_process_task_handle_t handle,
    kernel_task_identity_view_t *view) {
    test_task_t *task = (test_task_t *)(uintptr_t)handle;
    if (!task || !view || task < &g_tasks[0] ||
        task >= &g_tasks[TEST_TASKS] || !task->used)
        return -1;
    ++g_identity_reads;
    view->tid = task->view.tid;
    view->tgid = task->view.tgid;
    view->ppid = task->view.ppid;
    view->pgid = task->view.pgid;
    view->sid = task->view.sid;
    view->pid_namespace_id = task->view.pid_namespace_id;
    view->uid = task->view.uid;
    view->euid = task->view.euid;
    view->suid = task->view.suid;
    view->fsuid = task->view.fsuid;
    view->gid = task->view.gid;
    view->egid = task->view.egid;
    view->sgid = task->view.sgid;
    view->fsgid = task->view.fsgid;
    view->state = task->view.state;
    view->dumpable = task->view.dumpable;
    view->permitted_capabilities = task->view.permitted_capabilities;
    view->effective_capabilities = task->view.effective_capabilities;
    return 0;
}

void edge_linux_scheduler_state_apply_updates(
    edge_linux_scheduler_state_t *destination,
    const edge_linux_scheduler_state_t *requested, uint32_t update_mask) {
    if (update_mask & EDGE_SCHEDULER_UPDATE_AFFINITY)
        destination->affinity_mask = requested->affinity_mask;
    if (update_mask & EDGE_SCHEDULER_UPDATE_POLICY) {
        destination->policy = requested->policy;
        destination->priority = requested->priority;
        destination->runtime = requested->runtime;
        destination->deadline = requested->deadline;
        destination->period = requested->period;
        destination->flags = requested->flags;
    }
    if (update_mask & EDGE_SCHEDULER_UPDATE_NICE)
        destination->nice = requested->nice;
    if (update_mask & EDGE_SCHEDULER_UPDATE_UTILIZATION) {
        destination->util_min = requested->util_min;
        destination->util_max = requested->util_max;
    }
}

int edge_linux_scheduler_state_equal(
    const edge_linux_scheduler_state_t *left,
    const edge_linux_scheduler_state_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

void arch_process_task_apply_locked(
    kernel_process_task_handle_t handle,
    const kernel_process_task_update_t *update) {
    test_task_t *task = (test_task_t *)(uintptr_t)handle;
    if (!task || !task->used || !update) return;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_SESSION) {
        task->view.pgid = update->pgid;
        task->view.sid = update->sid;
        if (update->detach_controlling_terminal)
            task->detached = 1;
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_EXEC)
        task->view.execed_since_fork = update->execed_since_fork;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_CGROUP)
        task->view.cgroup_id = update->cgroup_id;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_RESOURCE_LIMIT)
        task->view.resource_limits[update->resource] =
            update->resource_limit;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_OOM) {
        task->view.oom_score_adj = update->oom_score_adj;
        task->view.oom_score_adj_min = update->oom_score_adj_min;
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_IO_PRIORITY)
        task->view.io_priority = update->io_priority;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_SCHEDULER) {
        edge_linux_scheduler_state_apply_updates(
            &task->view.scheduler, &update->scheduler,
            update->scheduler_update_mask);
        task->rescheduled =
            (update->scheduler_update_mask &
             EDGE_SCHEDULER_UPDATE_POLICY) != 0;
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_CREDENTIALS) {
        if (update->clear_parent_death_signal)
            task->view.parent_death_signal = 0;
        task->view.uid = update->credentials.uid;
        task->view.euid = update->credentials.euid;
        task->view.suid = update->credentials.suid;
        task->view.fsuid = update->credentials.fsuid;
        task->view.gid = update->credentials.gid;
        task->view.egid = update->credentials.egid;
        task->view.sgid = update->credentials.sgid;
        task->view.fsgid = update->credentials.fsgid;
        task->view.capabilities = update->credentials.capabilities;
        task->view.permitted_capabilities =
            update->credentials.capabilities.permitted;
        task->view.effective_capabilities =
            update->credentials.capabilities.effective;
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_GROUPS) {
        if (!update->groups) {
            int result = linux_group_list_retain(
                update->previous_groups, &task->groups);
            if (update->result) *update->result = result;
        } else if (update->previous_groups) {
            *update->previous_groups = task->groups;
            task->groups = *update->groups;
            linux_group_list_init(update->groups);
            if (update->result) *update->result = 0;
        }
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_UMASK)
        task->view.umask = update->umask;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_PRCTL) {
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL) {
            task->view.parent_death_signal =
                update->prctl.parent_death_signal;
        }
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_DUMPABLE)
            task->view.dumpable = update->prctl.dumpable;
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_NO_NEW_PRIVILEGES) {
            task->view.no_new_privileges =
                update->prctl.no_new_privileges;
        }
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_TIMER_SLACK)
            task->view.timer_slack_ns = update->prctl.timer_slack_ns;
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_THP_DISABLED)
            task->view.thp_disabled = update->prctl.thp_disabled;
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER) {
            task->view.child_subreaper =
                update->prctl.child_subreaper;
        }
        if (update->prctl_update_mask & EDGE_LINUX_PRCTL_UPDATE_NAME)
            memcpy(task->view.comm, update->prctl.name,
                   sizeof(task->view.comm));
    }
}

edge_seccomp_state_t *arch_process_task_seccomp_locked(
    kernel_process_task_handle_t handle) {
    test_task_t *task = (test_task_t *)(uintptr_t)handle;
    return task && task->used ? &task->seccomp : 0;
}

void arch_process_task_seccomp_replace_locked(
    kernel_process_task_handle_t handle,
    const edge_seccomp_state_t *installed, int set_no_new_privileges) {
    test_task_t *task = (test_task_t *)(uintptr_t)handle;
    if (!task || !task->used || !installed) return;
    task->seccomp = *installed;
    if (set_no_new_privileges) task->view.no_new_privileges = 1;
}

uint32_t *arch_process_task_membarrier_locked(
    kernel_process_task_handle_t handle) {
    test_task_t *task = (test_task_t *)(uintptr_t)handle;
    return task && task->used ? &task->membarrier_registrations : 0;
}

static void initialize_task(uint32_t slot, int32_t tid, int32_t tgid,
                            int32_t ppid, int32_t pgid, int32_t sid) {
    test_task_t *task = &g_tasks[slot];
    memset(task, 0, sizeof(*task));
    task->used = 1;
    task->view.tid = tid;
    task->view.tgid = tgid;
    task->view.ppid = ppid;
    task->view.pgid = pgid;
    task->view.sid = sid;
    task->view.state = KERNEL_PROC_TASK_RUNNING;
    task->view.uid = 1000u + slot;
    task->view.euid = 2000u + slot;
    task->view.suid = 3000u + slot;
    task->view.capabilities.effective = 1u << slot;
    task->view.permitted_capabilities = 3u << slot;
    task->view.effective_capabilities = 1u << slot;
    task->view.scheduler.affinity_mask = 1u;
    task->view.scheduler.util_max = EDGE_LINUX_SCHED_UTIL_SCALE;
    task->view.memory_context_id = 100u + slot;
    task->view.fs_context_id = 200u + slot;
    task->view.dumpable = 1;
    task->view.timer_slack_ns = EDGE_LINUX_DEFAULT_TIMER_SLACK_NS;
    memcpy(task->view.comm, "unit-task", sizeof("unit-task"));
    linux_group_list_init(&task->groups);
}

static void initialize_fixture(void) {
    memset(g_tasks, 0, sizeof(g_tasks));
    g_full_view_reads = 0;
    g_identity_reads = 0;
    initialize_task(0, 100, 100, 1, 100, 100);
    initialize_task(1, 200, 200, 100, 100, 100);
    initialize_task(2, 201, 200, 100, 100, 100);
    initialize_task(3, 202, 200, 100, 100, 100);
    g_tasks[3].view.state = KERNEL_PROC_TASK_ZOMBIE;
    initialize_task(4, 300, 300, 100, 300, 300);
    g_current = 0;
}

static void test_sampling_and_identity(void) {
    kernel_proc_task_view_t sample;
    kernel_task_identity_view_t identity;
    uint32_t full_view_reads;

    expect_true("sample live",
                kernel_arch_proc_task_sample(2, &sample) == 0 &&
                sample.tid == 201);
    expect_true("sample unused",
                kernel_arch_proc_task_sample(5, &sample) == 1);
    expect_true("lookup",
                kernel_arch_proc_task_lookup(200, &sample) == 0 &&
                sample.tgid == 200);
    full_view_reads = g_full_view_reads;
    expect_true("identity",
                kernel_arch_current_identity_sample(&identity) == 0 &&
                identity.tid == 100 &&
                identity.permitted_capabilities ==
                    g_tasks[0].view.permitted_capabilities);
    expect_true("identity uses compact backend sample",
                g_identity_reads == 1 &&
                g_full_view_reads == full_view_reads);
}

static void test_session_and_exec(void) {
    edge_linux_process_session_commit_t commit = {0};

    commit.caller_tid = 100;
    commit.current.pid = 100;
    commit.current.ppid = 1;
    commit.current.pgid = 100;
    commit.current.sid = 100;
    commit.target.pid = 200;
    commit.target.ppid = 100;
    commit.target.pgid = 100;
    commit.target.sid = 100;
    commit.new_pgid = 200;
    commit.new_sid = 100;
    commit.detach_controlling_terminal = 1;
    expect_true("session commit",
                kernel_arch_process_session_commit(&commit) == 0);
    expect_true("session group update",
                g_tasks[1].view.pgid == 200 &&
                g_tasks[2].view.pgid == 200 &&
                g_tasks[3].view.pgid == 200);
    expect_true("session detach",
                g_tasks[1].detached && g_tasks[2].detached &&
                g_tasks[3].detached);

    expect_true("exec commit",
                kernel_arch_process_exec_committed(200) == 0);
    expect_true("exec group update",
                g_tasks[1].view.execed_since_fork &&
                g_tasks[2].view.execed_since_fork &&
                g_tasks[3].view.execed_since_fork);
}

static void test_group_commits(void) {
    kernel_resource_limit_t limit = {123u, 456u};
    kernel_oom_score_adj_commit_t oom = {0};

    expect_true("cgroup commit",
                kernel_arch_proc_cgroup_attach(201, 200, 9, 1) == 0);
    expect_true("cgroup skips zombie",
                g_tasks[1].view.cgroup_id == 9 &&
                g_tasks[2].view.cgroup_id == 9 &&
                g_tasks[3].view.cgroup_id == 0);

    expect_true("resource commit",
                kernel_arch_process_resource_limit_commit(
                    201, 200, EDGE_LINUX_RLIMIT_NOFILE, &limit) == 0);
    expect_true("resource includes zombie",
                g_tasks[1].view.resource_limits[
                    EDGE_LINUX_RLIMIT_NOFILE].current == 123u &&
                g_tasks[3].view.resource_limits[
                    EDGE_LINUX_RLIMIT_NOFILE].maximum == 456u);

    oom.caller_tid = g_tasks[0].view.tid;
    oom.caller_euid = g_tasks[0].view.euid;
    oom.caller_effective_capabilities =
        g_tasks[0].view.capabilities.effective;
    oom.target_tid = g_tasks[1].view.tid;
    oom.target_tgid = test_tgid(&g_tasks[1]);
    oom.target_uid = g_tasks[1].view.uid;
    oom.target_suid = g_tasks[1].view.suid;
    oom.target_minimum = g_tasks[1].view.oom_score_adj_min;
    oom.value = 250;
    oom.new_minimum = -100;
    expect_true("oom commit",
                kernel_arch_process_oom_score_adj_commit(&oom) == 0);
    expect_true("oom skips zombie",
                g_tasks[1].view.oom_score_adj == 250 &&
                g_tasks[2].view.oom_score_adj == 250 &&
                g_tasks[3].view.oom_score_adj == 0);
}

static void test_single_task_commits(void) {
    kernel_process_io_priority_commit_t io = {0};
    kernel_scheduler_state_commit_t scheduler = {0};
    kernel_scheduler_state_commit_t competing = {0};

    io.tid = g_tasks[2].view.tid;
    io.expected_tgid = test_tgid(&g_tasks[2]);
    io.expected_uid = g_tasks[2].view.uid;
    io.expected_euid = g_tasks[2].view.euid;
    io.io_priority = 0x1234u;
    expect_true("io priority commit",
                kernel_arch_process_io_priority_commit(&io) == 0 &&
                g_tasks[2].view.io_priority == 0x1234u);

    scheduler.target.tid = g_tasks[2].view.tid;
    scheduler.target.tgid = test_tgid(&g_tasks[2]);
    scheduler.target.uid = g_tasks[2].view.uid;
    scheduler.target.euid = g_tasks[2].view.euid;
    scheduler.target.suid = g_tasks[2].view.suid;
    scheduler.target.state = g_tasks[2].view.scheduler;
    scheduler.requested = scheduler.target.state;
    scheduler.requested.policy = EDGE_LINUX_SCHED_FIFO;
    scheduler.requested.priority = 7;
    scheduler.update_mask = EDGE_SCHEDULER_UPDATE_POLICY;
    expect_true("scheduler commit",
                kernel_arch_scheduler_state_commit(&scheduler) == 0);
    expect_true("scheduler update",
                g_tasks[2].view.scheduler.policy ==
                    EDGE_LINUX_SCHED_FIFO &&
                g_tasks[2].view.scheduler.priority == 7 &&
                g_tasks[2].rescheduled);

    scheduler.target.state = g_tasks[2].view.scheduler;
    scheduler.requested = scheduler.target.state;
    scheduler.requested.affinity_mask = 1u;
    scheduler.requested.policy = EDGE_LINUX_SCHED_DEADLINE;
    scheduler.requested.priority = 0;
    scheduler.requested.runtime = 6000000u;
    scheduler.requested.deadline = 8000000u;
    scheduler.requested.period = 10000000u;
    expect_true("deadline admission accepts available bandwidth",
                kernel_arch_scheduler_state_commit(&scheduler) == 0);

    competing.target.tid = g_tasks[1].view.tid;
    competing.target.tgid = test_tgid(&g_tasks[1]);
    competing.target.uid = g_tasks[1].view.uid;
    competing.target.euid = g_tasks[1].view.euid;
    competing.target.suid = g_tasks[1].view.suid;
    competing.target.state = g_tasks[1].view.scheduler;
    competing.requested = competing.target.state;
    competing.requested.affinity_mask = 1u;
    competing.requested.policy = EDGE_LINUX_SCHED_DEADLINE;
    competing.requested.runtime = 5000000u;
    competing.requested.deadline = 8000000u;
    competing.requested.period = 10000000u;
    competing.update_mask = EDGE_SCHEDULER_UPDATE_POLICY;
    expect_true("deadline admission rejects overcommit",
                kernel_arch_scheduler_state_commit(&competing) == -2);

    scheduler.target.state = g_tasks[2].view.scheduler;
    scheduler.requested = scheduler.target.state;
    scheduler.requested.policy = EDGE_LINUX_SCHED_FIFO;
    scheduler.requested.priority = 7;
    scheduler.requested.runtime = 0;
    scheduler.requested.deadline = 0;
    scheduler.requested.period = 0;
    expect_true("deadline bandwidth is released on policy change",
                kernel_arch_scheduler_state_commit(&scheduler) == 0);
}

static void test_security_and_shared_state_commits(void) {
    kernel_linux_prctl_commit_t prctl = {0};
    linux_credential_state_t credentials = {0};
    linux_group_list_t groups;
    linux_group_list_t snapshot;
    edge_seccomp_state_t installed = {2u, 7u, 8u};
    uint32_t *registrations = 0;
    uint16_t previous_umask = 0;

    g_current = 1;
    g_tasks[1].view.memory_context_id = 77u;
    g_tasks[2].view.memory_context_id = 77u;
    g_tasks[1].view.fs_context_id = 88u;
    g_tasks[2].view.fs_context_id = 88u;
    g_tasks[1].view.parent_death_signal = 9u;
    g_tasks[1].view.no_new_privileges = 1u;
    g_tasks[1].seccomp = (edge_seccomp_state_t){1u, 7u, 4u};
    g_tasks[2].seccomp = g_tasks[1].seccomp;

    prctl.tid = g_tasks[1].view.tid;
    prctl.expected_tgid = test_tgid(&g_tasks[1]);
    prctl.expected.parent_death_signal = 9u;
    prctl.expected.dumpable = 1u;
    memcpy(prctl.expected.name, g_tasks[1].view.comm,
           sizeof(prctl.expected.name));
    prctl.requested = prctl.expected;
    prctl.requested.parent_death_signal = 12u;
    prctl.requested.dumpable = 0u;
    memcpy(prctl.requested.name, "shared-policy",
           sizeof("shared-policy"));
    prctl.update_mask =
        EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL |
        EDGE_LINUX_PRCTL_UPDATE_DUMPABLE |
        EDGE_LINUX_PRCTL_UPDATE_NAME;
    expect_true("prctl commit",
                kernel_arch_current_prctl_state_commit(&prctl) == 0);
    expect_true("prctl task update",
                g_tasks[1].view.parent_death_signal == 12u &&
                strcmp(g_tasks[1].view.comm, "shared-policy") == 0);
    expect_true("prctl memory update",
                g_tasks[1].view.dumpable == 0u &&
                g_tasks[2].view.dumpable == 0u);

    expect_true("seccomp state",
                kernel_arch_current_seccomp_state() ==
                    &g_tasks[1].seccomp);
    expect_true("seccomp synchronize",
                kernel_arch_seccomp_synchronize_thread_group(
                    &g_tasks[1].seccomp, &installed, 0) == 0);
    expect_true("seccomp peer update",
                g_tasks[2].seccomp.length == installed.length &&
                g_tasks[2].seccomp.head_filter_id ==
                    installed.head_filter_id);

    credentials.uid = 11u;
    credentials.euid = 12u;
    credentials.suid = 13u;
    credentials.fsuid = 14u;
    credentials.gid = 21u;
    credentials.egid = 22u;
    credentials.sgid = 23u;
    credentials.fsgid = 24u;
    credentials.capabilities.permitted = 0x55u;
    credentials.capabilities.effective = 0x44u;
    expect_true("credentials commit",
                kernel_arch_current_credentials_commit(
                    &credentials, 1) == 0);
    expect_true("credentials update",
                g_tasks[1].view.uid == 11u &&
                g_tasks[1].view.fsgid == 24u &&
                g_tasks[1].view.parent_death_signal == 0u &&
                g_tasks[1].view.effective_capabilities == 0x44u);

    linux_group_list_init(&groups);
    groups.count = 3u;
    expect_true("groups commit",
                kernel_arch_current_groups_commit(&groups) == 0 &&
                groups.count == 0u && g_tasks[1].groups.count == 3u);
    linux_group_list_init(&snapshot);
    expect_true("groups snapshot",
                kernel_arch_process_groups_snapshot(
                    g_tasks[1].view.tid, &snapshot) == 0 &&
                snapshot.count == 3u);

    g_tasks[1].view.umask = 0022u;
    g_tasks[2].view.umask = 0022u;
    expect_true("umask commit",
                kernel_arch_current_umask_commit(
                    0077u, &previous_umask) == 0 &&
                previous_umask == 0022u);
    expect_true("umask context update",
                g_tasks[1].view.umask == 0077u &&
                g_tasks[2].view.umask == 0077u);

    g_tasks[1].membarrier_registrations = 0x33u;
    expect_true("membarrier owner",
                kernel_arch_current_membarrier_state(&registrations) == 0 &&
                registrations == &g_tasks[1].membarrier_registrations &&
                *registrations == 0x33u);
}

int main(void) {
    initialize_fixture();
    test_sampling_and_identity();
    test_session_and_exec();
    test_group_commits();
    test_single_task_commits();
    test_security_and_shared_state_commits();
    if (g_failures) return 1;
    puts("process_commit_unit: PASS");
    return 0;
}
