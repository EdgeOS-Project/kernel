/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS shared process-clone transaction unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/clone_runtime.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/scheduler_policy.h"

enum clone_test_event {
    EVENT_VALIDATE_CGROUP = 1,
    EVENT_PREPARE,
    EVENT_CONFIGURE,
    EVENT_ATTACH_CGROUP,
    EVENT_VALIDATE_PIDS,
    EVENT_INSTALL_PIDFD,
    EVENT_PARENT_TID,
    EVENT_CHILD_TID,
    EVENT_PREPARE_VFORK,
    EVENT_PTRACE,
    EVENT_PUBLISH,
    EVENT_WAIT_VFORK,
    EVENT_ABORT,
};

static int g_failures;
static int g_events[32];
static uint32_t g_event_count;
static int g_fail_event;
static int g_fail_status;
static int g_ptrace_result;
static int g_prepare_bad_state;
static kernel_clone_prepare_t g_prepare;
static kernel_clone_configuration_t g_configuration;
static uint64_t g_cgroup_descriptor;
static uint64_t g_pidfd_destination;
static uint64_t g_parent_tid_destination;
static uint64_t g_child_tid_destination;
static uint64_t g_ptrace_flags;
static int32_t g_ptrace_child;
static int32_t g_ptrace_visible_child;
static int g_publish_event;
static edge_linux_scheduler_state_t g_parent_scheduler;
static int g_userfaultfd_forks;
static int g_userfaultfd_releases;
static int g_userfaultfd_waits;
static int g_userfaultfd_replay;
static int64_t g_userfaultfd_replay_result;

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    if (!identity) return -1;
    memset(identity, 0, sizeof(*identity));
    identity->global_tid = 1;
    return 0;
}

int kernel_scheduler_state_get(int32_t tid,
                               edge_linux_scheduler_state_t *state) {
    if (tid != 1 || !state) return -1;
    *state = g_parent_scheduler;
    return 0;
}

int kernel_user_namespace_capabilities_grant(int32_t global_pid) {
    return global_pid > 0 ? 0 : -1;
}

int kernel_io_uring_task_restrictions_clone(
        int32_t parent_task_id, int32_t child_task_id) {
    return parent_task_id == 1 && child_task_id == 101 ? 0 :
           -EDGE_LINUX_EINVAL;
}

void kernel_io_uring_task_release(int32_t task_id) {
    (void)task_id;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static void record_event(int event) {
    if (g_event_count < sizeof(g_events) / sizeof(g_events[0]))
        g_events[g_event_count] = event;
    ++g_event_count;
}

static int event_result(int event) {
    record_event(event);
    return g_fail_event == event ? g_fail_status : 0;
}

static void reset_mocks(void) {
    memset(g_events, 0, sizeof(g_events));
    memset(&g_prepare, 0, sizeof(g_prepare));
    memset(&g_configuration, 0, sizeof(g_configuration));
    g_event_count = 0;
    g_fail_event = 0;
    g_fail_status = 0;
    g_ptrace_result = 0;
    g_prepare_bad_state = 0;
    g_cgroup_descriptor = 0;
    g_pidfd_destination = 0;
    g_parent_tid_destination = 0;
    g_child_tid_destination = 0;
    g_ptrace_flags = 0;
    g_ptrace_child = 0;
    g_ptrace_visible_child = 0;
    g_publish_event = -1;
    memset(&g_parent_scheduler, 0, sizeof(g_parent_scheduler));
    g_userfaultfd_forks = 0;
    g_userfaultfd_releases = 0;
    g_userfaultfd_waits = 0;
    g_userfaultfd_replay = 0;
    g_userfaultfd_replay_result = 0;
    g_parent_scheduler.affinity_mask = 1u;
    g_parent_scheduler.policy = EDGE_LINUX_SCHED_OTHER;
}

static void expect_events(const char *name, const int *events,
                          uint32_t count) {
    expect_true(name, g_event_count == count);
    if (g_event_count != count) return;
    for (uint32_t index = 0; index < count; ++index) {
        if (g_events[index] == events[index]) continue;
        fprintf(stderr, "FAIL: %s event %u got %d expected %d\n",
                name, index, g_events[index], events[index]);
        ++g_failures;
    }
}

int process_clone_arch_validate_cgroup(uint64_t descriptor) {
    g_cgroup_descriptor = descriptor;
    return event_result(EVENT_VALIDATE_CGROUP);
}

int process_clone_arch_prepare(const kernel_clone_prepare_t *prepare,
                               kernel_clone_state_t *state) {
    int status = event_result(EVENT_PREPARE);
    if (status < 0) return status;
    g_prepare = *prepare;
    state->prepared = 1;
    state->child_global_pid = 101;
    state->parent_visible_pid = 44;
    state->child_visible_pid = 7;
    state->parent_address_space = 0x1000u;
    state->child_address_space = prepare->share_vm ? 0x1000u : 0x2000u;
    if (g_prepare_bad_state)
        state->child_visible_pid = 0;
    return 0;
}

int process_clone_arch_configure(
    const kernel_clone_configuration_t *configuration,
    kernel_clone_state_t *state) {
    (void)state;
    g_configuration = *configuration;
    return event_result(EVENT_CONFIGURE);
}

int process_clone_arch_attach_cgroup(uint64_t descriptor,
                                     kernel_clone_state_t *state) {
    g_cgroup_descriptor = descriptor;
    {
        int result = event_result(EVENT_ATTACH_CGROUP);
        if (result == 0) state->cgroup_accounted = 1;
        return result;
    }
}

int cgroupfs_pids_validate_task(int32_t pid, int already_counted) {
    expect_true("pids validation child", pid == 101);
    expect_true("pids validation accounting",
                already_counted == (g_cgroup_descriptor != 0));
    return event_result(EVENT_VALIDATE_PIDS);
}

int process_clone_arch_install_pidfd(uint64_t user_destination,
                                     kernel_clone_state_t *state) {
    int status;
    g_pidfd_destination = user_destination;
    status = event_result(EVENT_INSTALL_PIDFD);
    if (status < 0) return status;
    state->pidfd = 12;
    return 0;
}

int process_clone_arch_write_parent_tid(uint64_t user_destination,
                                        kernel_clone_state_t *state) {
    (void)state;
    g_parent_tid_destination = user_destination;
    return event_result(EVENT_PARENT_TID);
}

int process_clone_arch_write_child_tid(uint64_t user_destination,
                                       kernel_clone_state_t *state) {
    (void)state;
    g_child_tid_destination = user_destination;
    return event_result(EVENT_CHILD_TID);
}

int process_clone_arch_prepare_vfork(kernel_clone_state_t *state) {
    (void)state;
    return event_result(EVENT_PREPARE_VFORK);
}

int process_clone_arch_publish(kernel_clone_state_t *state,
                               int ptrace_event) {
    (void)state;
    g_publish_event = ptrace_event;
    return event_result(EVENT_PUBLISH);
}

int process_clone_arch_wait_vfork(kernel_clone_state_t *state) {
    (void)state;
    return event_result(EVENT_WAIT_VFORK);
}

void process_clone_arch_abort(kernel_clone_state_t *state) {
    record_event(EVENT_ABORT);
    state->prepared = 0;
}

int kernel_userfaultfd_address_space_fork(
        uint64_t parent_address_space, uint64_t child_address_space,
        int32_t child_owner_pid, int *wait_context,
        uint64_t *wait_ticket) {
    expect_true("userfaultfd parent address space",
                parent_address_space == 0x1000u);
    expect_true("userfaultfd child address space",
                child_address_space == 0x2000u);
    expect_true("userfaultfd child owner", child_owner_pid == 101);
    expect_true("userfaultfd wait outputs",
                wait_context != 0 && wait_ticket != 0);
    *wait_context = 3;
    *wait_ticket = 9u;
    ++g_userfaultfd_forks;
    return 0;
}

void kernel_userfaultfd_wait_fork(int context_id, uint64_t ticket,
                                  int64_t completion_result) {
    expect_true("userfaultfd wait context", context_id == 3);
    expect_true("userfaultfd wait ticket", ticket == 9u);
    expect_true("userfaultfd wait result", completion_result == 44);
    ++g_userfaultfd_waits;
}

int kernel_userfaultfd_consume_completed_fork(
        int64_t *completion_result) {
    if (!g_userfaultfd_replay) return 0;
    expect_true("userfaultfd replay destination", completion_result != 0);
    if (completion_result)
        *completion_result = g_userfaultfd_replay_result;
    return 1;
}

void kernel_userfaultfd_address_space_release(uint64_t address_space) {
    expect_true("userfaultfd released child address space",
                address_space == 0x2000u);
    ++g_userfaultfd_releases;
}

int edge_linux_ptrace_clone_stop(void *user_registers, uint64_t clone_flags,
                                 int32_t child_global_pid,
                                 int32_t child_visible_pid) {
    expect_true("ptrace registers", user_registers == (void *)0x1234u);
    record_event(EVENT_PTRACE);
    g_ptrace_flags = clone_flags;
    g_ptrace_child = child_global_pid;
    g_ptrace_visible_child = child_visible_pid;
    return g_ptrace_result;
}

static kernel_clone_request_t base_request(void) {
    kernel_clone_request_t request;
    memset(&request, 0, sizeof(request));
    request.user_registers = (void *)0x1234u;
    request.exit_signal = EDGE_LINUX_SIGCHLD;
    return request;
}

static void test_full_vfork_transaction(void) {
    static const int expected[] = {
        EVENT_VALIDATE_CGROUP,
        EVENT_PREPARE,
        EVENT_CONFIGURE,
        EVENT_ATTACH_CGROUP,
        EVENT_VALIDATE_PIDS,
        EVENT_INSTALL_PIDFD,
        EVENT_PARENT_TID,
        EVENT_CHILD_TID,
        EVENT_PREPARE_VFORK,
        EVENT_PTRACE,
        EVENT_PUBLISH,
        EVENT_WAIT_VFORK,
    };
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    request.flags =
        EDGE_LINUX_CLONE_VM |
        EDGE_LINUX_CLONE_FS |
        EDGE_LINUX_CLONE_FILES |
        EDGE_LINUX_CLONE_SIGHAND |
        EDGE_LINUX_CLONE_PIDFD |
        EDGE_LINUX_CLONE_VFORK |
        EDGE_LINUX_CLONE_SETTLS |
        EDGE_LINUX_CLONE_PARENT_SETTID |
        EDGE_LINUX_CLONE_CHILD_SETTID |
        EDGE_LINUX_CLONE_CHILD_CLEARTID |
        EDGE_LINUX_CLONE_INTO_CGROUP |
        EDGE_LINUX_CLONE_NEWNS;
    request.child_stack = 0x7000u;
    request.parent_tid_user = 0x8000u;
    request.child_tid_user = 0x9000u;
    request.tls = 0xa000u;
    request.pidfd_user = 0xb000u;
    request.cgroup_descriptor = 19u;
    g_ptrace_result = 1;

    result = kernel_process_clone(&request);
    expect_true("full result", result == 44);
    expect_events("full order", expected,
                  sizeof(expected) / sizeof(expected[0]));
    expect_true("prepare namespace",
                g_prepare.namespace_flags == EDGE_LINUX_CLONE_NEWNS);
    expect_true("prepare shared vm", g_prepare.share_vm == 1);
    expect_true("prepare shared files", g_prepare.share_files == 1);
    expect_true("prepare vfork", g_prepare.vfork == 1);
    expect_true("prepare process", g_prepare.is_thread == 0);
    expect_true("configuration stack",
                g_configuration.child_stack == 0x7000u);
    expect_true("configuration tls",
                g_configuration.set_tls &&
                g_configuration.tls == 0xa000u);
    expect_true("configuration clear tid",
                g_configuration.clear_child_tid == 0x9000u);
    expect_true("configuration sighand",
                g_configuration.signal_handlers ==
                    KERNEL_CLONE_SIGNAL_HANDLERS_SHARE);
    expect_true("configuration parent",
                g_configuration.parent ==
                    KERNEL_CLONE_PARENT_CURRENT);
    expect_true("configuration shares",
                g_configuration.share_fs &&
                g_configuration.share_files);
    expect_true("configuration altstack",
                g_configuration.disable_altstack == 0);
    expect_true("destinations",
                g_cgroup_descriptor == 19u &&
                g_pidfd_destination == 0xb000u &&
                g_parent_tid_destination == 0x8000u &&
                g_child_tid_destination == 0x9000u);
    expect_true("ptrace values",
                g_ptrace_flags == request.flags + request.exit_signal &&
                g_ptrace_child == 101 &&
                g_ptrace_visible_child == 44);
    expect_true("publish event", g_publish_event == 1);
}

static void test_plain_fork_configuration(void) {
    static const int expected[] = {
        EVENT_PREPARE,
        EVENT_CONFIGURE,
        EVENT_VALIDATE_PIDS,
        EVENT_PTRACE,
        EVENT_PUBLISH,
    };
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    result = kernel_process_clone(&request);
    expect_true("fork result", result == 44);
    expect_events("fork order", expected,
                  sizeof(expected) / sizeof(expected[0]));
    expect_true("fork private resources",
                !g_prepare.share_vm && !g_prepare.share_files &&
                !g_configuration.share_fs &&
                !g_configuration.share_files);
    expect_true("fork copied sighand",
                g_configuration.signal_handlers ==
                    KERNEL_CLONE_SIGNAL_HANDLERS_COPY);
    expect_true("fork parent",
                g_configuration.parent ==
                    KERNEL_CLONE_PARENT_CURRENT);
    expect_true("fork signal",
                g_configuration.exit_signal == EDGE_LINUX_SIGCHLD);
    expect_true("fork cloned userfaultfd", g_userfaultfd_forks == 1);
    expect_true("fork waited for userfaultfd", g_userfaultfd_waits == 1);
    expect_true("fork kept child address space",
                g_userfaultfd_releases == 0);
}

static void test_thread_configuration(void) {
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    request.flags = EDGE_LINUX_CLONE_VM |
        EDGE_LINUX_CLONE_SIGHAND |
        EDGE_LINUX_CLONE_THREAD;
    request.exit_signal = 0;
    request.child_stack = 0x7000u;
    result = kernel_process_clone(&request);
    expect_true("thread result", result == 44);
    expect_true("thread prepare", g_prepare.is_thread == 1);
    expect_true("thread parent",
                g_configuration.parent ==
                    KERNEL_CLONE_PARENT_THREAD_GROUP);
    expect_true("thread exit signal",
                g_configuration.exit_signal == 0);
    expect_true("thread altstack disabled",
                g_configuration.disable_altstack == 1);
}

static void test_failure_rolls_back(void) {
    static const int expected[] = {
        EVENT_PREPARE,
        EVENT_CONFIGURE,
        EVENT_ABORT,
    };
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    g_fail_event = EVENT_CONFIGURE;
    g_fail_status = -EDGE_LINUX_ENOMEM;
    result = kernel_process_clone(&request);
    expect_true("configure failure result",
                result == -EDGE_LINUX_ENOMEM);
    expect_events("configure rollback", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_user_copy_failure_is_efault(void) {
    static const int expected[] = {
        EVENT_PREPARE,
        EVENT_CONFIGURE,
        EVENT_VALIDATE_PIDS,
        EVENT_INSTALL_PIDFD,
        EVENT_PARENT_TID,
        EVENT_ABORT,
    };
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    request.flags =
        EDGE_LINUX_CLONE_PIDFD |
        EDGE_LINUX_CLONE_PARENT_SETTID;
    request.pidfd_user = 0x2000u;
    request.parent_tid_user = 0x3000u;
    g_fail_event = EVENT_PARENT_TID;
    g_fail_status = -EDGE_LINUX_EIO;
    result = kernel_process_clone(&request);
    expect_true("copy failure result",
                result == -EDGE_LINUX_EFAULT);
    expect_events("copy rollback", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_cgroup_failure_is_eacces(void) {
    static const int expected[] = {
        EVENT_VALIDATE_CGROUP,
        EVENT_PREPARE,
        EVENT_CONFIGURE,
        EVENT_ATTACH_CGROUP,
        EVENT_ABORT,
    };
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    request.flags = EDGE_LINUX_CLONE_INTO_CGROUP;
    request.cgroup_descriptor = 9u;
    g_fail_event = EVENT_ATTACH_CGROUP;
    g_fail_status = -EDGE_LINUX_EBADF;
    result = kernel_process_clone(&request);
    expect_true("cgroup attach failure result",
                result == -EDGE_LINUX_EACCES);
    expect_events("cgroup rollback", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_ptrace_failure_rolls_back(void) {
    static const int expected[] = {
        EVENT_PREPARE,
        EVENT_CONFIGURE,
        EVENT_VALIDATE_PIDS,
        EVENT_PTRACE,
        EVENT_ABORT,
    };
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    g_ptrace_result = -EDGE_LINUX_ESRCH;
    result = kernel_process_clone(&request);
    expect_true("ptrace failure result",
                result == -EDGE_LINUX_ESRCH);
    expect_events("ptrace rollback", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_incomplete_prepare_rolls_back(void) {
    static const int expected[] = {
        EVENT_PREPARE,
        EVENT_ABORT,
    };
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    g_prepare_bad_state = 1;
    result = kernel_process_clone(&request);
    expect_true("bad prepare result",
                result == -EDGE_LINUX_EIO);
    expect_events("bad prepare rollback", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_pids_limit_rolls_back(void) {
    static const int expected[] = {
        EVENT_PREPARE,
        EVENT_CONFIGURE,
        EVENT_VALIDATE_PIDS,
        EVENT_ABORT,
    };
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    g_fail_event = EVENT_VALIDATE_PIDS;
    g_fail_status = -1;
    result = kernel_process_clone(&request);
    expect_true("pids limit result", result == -EDGE_LINUX_EAGAIN);
    expect_events("pids limit rollback", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_deadline_requires_reset_on_fork(void) {
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    g_parent_scheduler.policy = EDGE_LINUX_SCHED_DEADLINE;
    result = kernel_process_clone(&request);
    expect_true("deadline fork without reset is rejected",
                result == -EDGE_LINUX_EAGAIN);
    expect_events("deadline fork stops before allocation", 0, 0);
}

static void test_userfaultfd_replay_does_not_clone_again(void) {
    kernel_clone_request_t request = base_request();
    int64_t result;

    reset_mocks();
    g_userfaultfd_replay = 1;
    g_userfaultfd_replay_result = 44;
    result = kernel_process_clone(&request);
    expect_true("userfaultfd replay result", result == 44);
    expect_true("userfaultfd replay did not allocate", g_event_count == 0);
    expect_true("userfaultfd replay did not fork",
                g_userfaultfd_forks == 0);
}

int main(void) {
    test_full_vfork_transaction();
    test_plain_fork_configuration();
    test_thread_configuration();
    test_failure_rolls_back();
    test_user_copy_failure_is_efault();
    test_cgroup_failure_is_eacces();
    test_ptrace_failure_rolls_back();
    test_incomplete_prepare_rolls_back();
    test_pids_limit_rolls_back();
    test_deadline_requires_reset_on_fork();
    test_userfaultfd_replay_does_not_clone_again();
    if (g_failures) {
        fprintf(stderr, "process clone unit: %d failure(s)\n", g_failures);
        return 1;
    }
    puts("process clone unit: PASS");
    return 0;
}
