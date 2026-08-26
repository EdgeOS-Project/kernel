/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS shared process-exec transaction unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/exec_runtime.h"
#include "kernel/linux_errno.h"

enum exec_test_event {
    EVENT_INITIALIZE = 1,
    EVENT_CAPTURE_ARGUMENTS,
    EVENT_CAPTURE_ENVIRONMENT,
    EVENT_RESOLVE,
    EVENT_PROBE,
    EVENT_READ,
    EVENT_PREPARE,
    EVENT_UNSHARE,
    EVENT_DE_THREAD,
    EVENT_COMMIT,
    EVENT_RESET,
    EVENT_GET_CREDENTIALS,
    EVENT_SET_CREDENTIALS,
    EVENT_IDENTITY,
    EVENT_DELETE_TIMERS,
    EVENT_WAKE_VFORK,
    EVENT_PUBLISH,
    EVENT_CLOSE,
    EVENT_ENTER,
    EVENT_ABORT,
    EVENT_FATAL,
    EVENT_RELEASE_PAYLOAD,
};

static int g_failures;
static int g_events[64];
static uint32_t g_event_count;
static int g_fail_event;
static int g_enter_result;
static int g_resolve_symlink;
static int g_script;
static char g_path[KERNEL_EXEC_PATH_CAPACITY];
static char g_script_path[KERNEL_EXEC_PATH_CAPACITY];
static linux_exec_payload_t g_payload;
static kernel_exec_credentials_t g_credentials;
static kernel_exec_credentials_t g_committed_credentials;
static char g_identity[64];
static char g_interpreter[256];
static char g_interpreter_argument[256];
static char g_interpreter_script[256];

void spinlock_contention_relax(void) {
}

vfs_superblock_t *vfs_superblock_stable(vfs_superblock_t *superblock) {
    return superblock;
}

int kernel_fanotify_permission_check(const char *canonical_path,
                                     uint64_t mask) {
    (void)canonical_path;
    (void)mask;
    return 0;
}

void kernel_fanotify_notify_path(const char *canonical_path,
                                 uint32_t mask) {
    (void)canonical_path;
    (void)mask;
}

int vfs_inode_open(vfs_superblock_t *superblock,
                   const vfs_inode_t *inode) {
    (void)superblock;
    (void)inode;
    return 0;
}

void vfs_inode_close(vfs_superblock_t *superblock,
                     const vfs_inode_t *inode) {
    (void)superblock;
    (void)inode;
}

int kernel_landlock_check_path(const char *path,
                               uint64_t requested_access) {
    (void)path;
    (void)requested_access;
    return 0;
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
    return g_fail_event == event ? -EDGE_LINUX_EIO : 0;
}

static void reset_mocks(void) {
    memset(g_events, 0, sizeof(g_events));
    memset(g_path, 0, sizeof(g_path));
    memset(g_script_path, 0, sizeof(g_script_path));
    memset(&g_payload, 0, sizeof(g_payload));
    memset(&g_credentials, 0, sizeof(g_credentials));
    memset(&g_committed_credentials, 0,
           sizeof(g_committed_credentials));
    memset(g_identity, 0, sizeof(g_identity));
    memset(g_interpreter, 0, sizeof(g_interpreter));
    memset(g_interpreter_argument, 0, sizeof(g_interpreter_argument));
    memset(g_interpreter_script, 0, sizeof(g_interpreter_script));
    g_event_count = 0;
    g_fail_event = 0;
    g_enter_result = -EDGE_LINUX_EFAULT;
    g_resolve_symlink = 0;
    g_script = 0;
    g_credentials.identity.uid = 1000;
    g_credentials.identity.euid = 1000;
    g_credentials.identity.suid = 1000;
    g_credentials.identity.fsuid = 1000;
    g_credentials.identity.gid = 1000;
    g_credentials.identity.egid = 1000;
    g_credentials.identity.sgid = 1000;
    g_credentials.identity.fsgid = 1000;
    g_credentials.identity.capabilities.bounding =
        EDGE_LINUX_CAP_FULL_SET;
    g_credentials.parent_death_signal = 9;
    g_credentials.dumpable = 1;
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

int kernel_exec_payload_acquire(int32_t owner_pid,
                                kernel_exec_payload_handle_t *handle,
                                linux_exec_payload_t **payload_out) {
    expect_true("payload owner", owner_pid == 41);
    handle->slot = &g_payload;
    handle->generation = 1;
    *payload_out = &g_payload;
    return 0;
}

void kernel_exec_payload_release(kernel_exec_payload_handle_t *handle) {
    if (!handle || !handle->slot) return;
    record_event(EVENT_RELEASE_PAYLOAD);
    handle->slot = 0;
    handle->generation = 0;
}

int linux_exec_payload_capture_vector_with(
    linux_exec_payload_t *payload, void *copy_context,
    linux_exec_copy_from_user_fn copy_from_user, uint64_t user_vector,
    uint8_t vector_word_size, int environment) {
    (void)payload;
    (void)copy_context;
    (void)copy_from_user;
    (void)user_vector;
    expect_true("exec vector word size", vector_word_size == sizeof(uint64_t));
    record_event(environment ?
                 EVENT_CAPTURE_ENVIRONMENT : EVENT_CAPTURE_ARGUMENTS);
    return 0;
}

int linux_exec_payload_append(linux_exec_payload_t *payload,
                              const char *string, int environment,
                              uint32_t *offset_out) {
    (void)payload;
    expect_true("kernel exec string", string && string[0]);
    if (offset_out) *offset_out = 0;
    record_event(environment ?
                 EVENT_CAPTURE_ENVIRONMENT : EVENT_CAPTURE_ARGUMENTS);
    return 0;
}

int linux_exec_payload_prepend_script(
    linux_exec_payload_t *payload, const char *interpreter,
    const char *interpreter_argument, const char *script_path) {
    (void)payload;
    snprintf(g_interpreter, sizeof(g_interpreter), "%s", interpreter);
    snprintf(g_interpreter_argument, sizeof(g_interpreter_argument), "%s",
             interpreter_argument ? interpreter_argument : "");
    snprintf(g_interpreter_script, sizeof(g_interpreter_script), "%s",
             script_path);
    return 0;
}

int linux_exec_payload_ensure_argv0(linux_exec_payload_t *payload,
                                    const char *path) {
    (void)payload;
    return path && path[0] ? 0 : -EDGE_LINUX_EINVAL;
}

void linux_capabilities_init_root(linux_capability_state_t *state) {
    memset(state, 0, sizeof(*state));
    state->permitted = EDGE_LINUX_CAP_FULL_SET;
    state->effective = EDGE_LINUX_CAP_FULL_SET;
    state->bounding = EDGE_LINUX_CAP_FULL_SET;
}

int process_exec_arch_initialize(kernel_exec_state_t *state) {
    record_event(EVENT_INITIALIZE);
    state->task = (void *)0x1234u;
    state->path = g_path;
    state->script_path = g_script_path;
    state->path_capacity = sizeof(g_path);
    state->owner_pid = 41;
    state->process_id = 17;
    return 0;
}

int process_exec_arch_supply_file(kernel_exec_state_t *state,
                                  const vfs_inode_t *inode,
                                  vfs_superblock_t *superblock) {
    (void)state;
    (void)inode;
    (void)superblock;
    return 0;
}

int kernel_exec_descriptor_source_acquire(
    int32_t descriptor, kernel_exec_descriptor_source_t *source) {
    (void)descriptor;
    (void)source;
    return -EDGE_LINUX_EBADF;
}

void kernel_exec_descriptor_source_release(
    kernel_exec_descriptor_source_t *source) {
    if (source) source->active = 0;
}

int process_exec_arch_copy_from_user(void *context, void *destination,
                                    uint64_t source, uint64_t size) {
    (void)context;
    (void)destination;
    (void)source;
    (void)size;
    return 0;
}

int process_exec_arch_resolve(kernel_exec_state_t *state, int nofollow) {
    int status = event_result(EVENT_RESOLVE);
    if (status < 0) return status;
    memset(&state->file, 0, sizeof(state->file));
    state->file.mode =
        g_resolve_symlink && nofollow ? 0120777u : 0106755u;
    state->file.uid = 0;
    state->file.gid = 0;
    return 0;
}

int process_exec_arch_probe_image(kernel_exec_state_t *state) {
    int status = event_result(EVENT_PROBE);
    if (status < 0) return status;
    if (g_script && strcmp(state->path, "/tmp/test-script") == 0)
        return -EDGE_LINUX_ENOEXEC;
    return 0;
}

int process_exec_arch_read_image(kernel_exec_state_t *state,
                                 void *destination, uint32_t capacity) {
    static const char line[] = "#! /bin/interpreter --one two \n";
    (void)state;
    record_event(EVENT_READ);
    if (capacity < sizeof(line) - 1u) return -EDGE_LINUX_E2BIG;
    memcpy(destination, line, sizeof(line) - 1u);
    return sizeof(line) - 1u;
}

int process_exec_arch_prepare_image(kernel_exec_state_t *state) {
    expect_true("prepared credentials available",
                state && state->credentials_prepared &&
                state->credentials.identity.euid == 0 &&
                state->credentials.identity.egid == 0 &&
                state->secure_exec == 1);
    return event_result(EVENT_PREPARE);
}

int process_exec_arch_unshare_files(kernel_exec_state_t *state) {
    (void)state;
    return event_result(EVENT_UNSHARE);
}

int process_exec_arch_de_thread(kernel_exec_state_t *state) {
    (void)state;
    return event_result(EVENT_DE_THREAD);
}

int process_exec_arch_commit_image(kernel_exec_state_t *state) {
    int status = event_result(EVENT_COMMIT);
    if (status < 0) return status;
    state->point_of_no_return = 1;
    return 0;
}

int process_exec_arch_reset_state(
    kernel_exec_state_t *state,
    const kernel_exec_reset_configuration_t *configuration) {
    (void)state;
    expect_true("reset configuration",
                configuration->detach_signal_handlers &&
                configuration->reset_signal_dispositions &&
                configuration->disable_signal_altstack &&
                configuration->reset_thread_state &&
                configuration->reset_membarrier &&
                configuration->reset_architecture_tls &&
                configuration->reset_floating_point);
    return event_result(EVENT_RESET);
}

int process_exec_arch_get_credentials(
    kernel_exec_state_t *state, kernel_exec_credentials_t *credentials) {
    (void)state;
    record_event(EVENT_GET_CREDENTIALS);
    *credentials = g_credentials;
    return 0;
}

int process_exec_arch_set_credentials(
    kernel_exec_state_t *state,
    const kernel_exec_credentials_t *credentials) {
    (void)state;
    record_event(EVENT_SET_CREDENTIALS);
    g_committed_credentials = *credentials;
    return 0;
}

int process_exec_arch_set_identity(kernel_exec_state_t *state,
                                   const char *command_name) {
    (void)state;
    record_event(EVENT_IDENTITY);
    snprintf(g_identity, sizeof(g_identity), "%s", command_name);
    return 0;
}

int process_exec_arch_close_on_exec(kernel_exec_state_t *state) {
    (void)state;
    return event_result(EVENT_CLOSE);
}

void process_exec_arch_wake_vfork_parent(kernel_exec_state_t *state) {
    (void)state;
    record_event(EVENT_WAKE_VFORK);
}

int process_exec_arch_enter(kernel_exec_state_t *state) {
    (void)state;
    record_event(EVENT_ENTER);
    return g_enter_result;
}

void process_exec_arch_abort(kernel_exec_state_t *state) {
    (void)state;
    record_event(EVENT_ABORT);
}

int process_exec_arch_fatal(kernel_exec_state_t *state, int status) {
    (void)state;
    record_event(EVENT_FATAL);
    return status;
}

void kernel_posix_timer_delete_process(int32_t process_id) {
    expect_true("timer process", process_id == 17);
    record_event(EVENT_DELETE_TIMERS);
}

void kernel_current_exec_committed(void) {
    record_event(EVENT_PUBLISH);
}

static kernel_exec_request_t base_request(const char *path) {
    kernel_exec_request_t request;
    memset(&request, 0, sizeof(request));
    request.path = (char *)path;
    request.argv_user = 0x1000u;
    request.envp_user = 0x2000u;
    request.vector_word_size = sizeof(uint64_t);
    return request;
}

static void test_complete_transaction(void) {
    static const int expected[] = {
        EVENT_INITIALIZE,
        EVENT_CAPTURE_ARGUMENTS,
        EVENT_CAPTURE_ENVIRONMENT,
        EVENT_RESOLVE,
        EVENT_PROBE,
        EVENT_GET_CREDENTIALS,
        EVENT_PREPARE,
        EVENT_UNSHARE,
        EVENT_DE_THREAD,
        EVENT_COMMIT,
        EVENT_RESET,
        EVENT_SET_CREDENTIALS,
        EVENT_IDENTITY,
        EVENT_DELETE_TIMERS,
        EVENT_WAKE_VFORK,
        EVENT_PUBLISH,
        EVENT_CLOSE,
        EVENT_ENTER,
        EVENT_FATAL,
    };
    kernel_exec_request_t request = base_request("/usr/bin/program");
    int64_t result;

    reset_mocks();
    result = kernel_process_exec(&request);
    expect_true("complete result", result == -EDGE_LINUX_EFAULT);
    expect_events("complete order", expected,
                  sizeof(expected) / sizeof(expected[0]));
    expect_true("setuid credential",
                g_committed_credentials.identity.euid == 0 &&
                g_committed_credentials.identity.suid == 0 &&
                g_committed_credentials.identity.fsuid == 0);
    expect_true("setgid credential",
                g_committed_credentials.identity.egid == 0 &&
                g_committed_credentials.identity.sgid == 0 &&
                g_committed_credentials.identity.fsgid == 0);
    expect_true("privilege state",
                g_committed_credentials.dumpable == 0 &&
                g_committed_credentials.parent_death_signal == 0);
    expect_true("root capabilities",
                g_committed_credentials.identity.capabilities.effective ==
                EDGE_LINUX_CAP_FULL_SET);
    expect_true("identity basename",
                strcmp(g_identity, "program") == 0);
}

static void test_shebang_policy(void) {
    static const int expected[] = {
        EVENT_INITIALIZE,
        EVENT_CAPTURE_ARGUMENTS,
        EVENT_CAPTURE_ENVIRONMENT,
        EVENT_RESOLVE,
        EVENT_PROBE,
        EVENT_READ,
        EVENT_RESOLVE,
        EVENT_PROBE,
        EVENT_GET_CREDENTIALS,
        EVENT_PREPARE,
        EVENT_UNSHARE,
        EVENT_DE_THREAD,
        EVENT_COMMIT,
        EVENT_RESET,
        EVENT_SET_CREDENTIALS,
        EVENT_IDENTITY,
        EVENT_DELETE_TIMERS,
        EVENT_WAKE_VFORK,
        EVENT_PUBLISH,
        EVENT_CLOSE,
        EVENT_ENTER,
        EVENT_FATAL,
    };
    kernel_exec_request_t request = base_request("/tmp/test-script");

    reset_mocks();
    g_script = 1;
    (void)kernel_process_exec(&request);
    expect_events("shebang order", expected,
                  sizeof(expected) / sizeof(expected[0]));
    expect_true("shebang interpreter",
                strcmp(g_interpreter, "/bin/interpreter") == 0);
    expect_true("shebang argument",
                strcmp(g_interpreter_argument, "--one two") == 0);
    expect_true("shebang script",
                strcmp(g_interpreter_script, "/tmp/test-script") == 0);
    expect_true("shebang identity",
                strcmp(g_identity, "interpreter") == 0);
}

static void test_nofollow_rejects_symlink(void) {
    static const int expected[] = {
        EVENT_INITIALIZE,
        EVENT_CAPTURE_ARGUMENTS,
        EVENT_CAPTURE_ENVIRONMENT,
        EVENT_RESOLVE,
        EVENT_ABORT,
        EVENT_RELEASE_PAYLOAD,
    };
    kernel_exec_request_t request = base_request("/tmp/link");
    int64_t result;

    reset_mocks();
    g_resolve_symlink = 1;
    request.nofollow = 1;
    result = kernel_process_exec(&request);
    expect_true("nofollow result", result == -EDGE_LINUX_ELOOP);
    expect_events("nofollow order", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_precommit_failure_rolls_back(void) {
    static const int expected[] = {
        EVENT_INITIALIZE,
        EVENT_CAPTURE_ARGUMENTS,
        EVENT_CAPTURE_ENVIRONMENT,
        EVENT_RESOLVE,
        EVENT_PROBE,
        EVENT_GET_CREDENTIALS,
        EVENT_PREPARE,
        EVENT_UNSHARE,
        EVENT_ABORT,
        EVENT_RELEASE_PAYLOAD,
    };
    kernel_exec_request_t request = base_request("/bin/program");
    int64_t result;

    reset_mocks();
    g_fail_event = EVENT_UNSHARE;
    result = kernel_process_exec(&request);
    expect_true("precommit failure", result == -EDGE_LINUX_EIO);
    expect_events("precommit rollback", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_postcommit_failure_is_fatal(void) {
    static const int expected[] = {
        EVENT_INITIALIZE,
        EVENT_CAPTURE_ARGUMENTS,
        EVENT_CAPTURE_ENVIRONMENT,
        EVENT_RESOLVE,
        EVENT_PROBE,
        EVENT_GET_CREDENTIALS,
        EVENT_PREPARE,
        EVENT_UNSHARE,
        EVENT_DE_THREAD,
        EVENT_COMMIT,
        EVENT_RESET,
        EVENT_SET_CREDENTIALS,
        EVENT_IDENTITY,
        EVENT_DELETE_TIMERS,
        EVENT_WAKE_VFORK,
        EVENT_PUBLISH,
        EVENT_CLOSE,
        EVENT_FATAL,
    };
    kernel_exec_request_t request = base_request("/bin/program");
    int64_t result;

    reset_mocks();
    g_fail_event = EVENT_CLOSE;
    result = kernel_process_exec(&request);
    expect_true("postcommit failure", result == -EDGE_LINUX_EIO);
    expect_events("postcommit fatal", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_kernel_vectors_defer_user_entry(void) {
    static const char *const arguments[] = {
        "/sbin/request-key", "create",
    };
    static const char *const environment[] = {
        "HOME=/",
    };
    static const int expected[] = {
        EVENT_INITIALIZE,
        EVENT_CAPTURE_ARGUMENTS,
        EVENT_CAPTURE_ARGUMENTS,
        EVENT_CAPTURE_ENVIRONMENT,
        EVENT_RESOLVE,
        EVENT_PROBE,
        EVENT_GET_CREDENTIALS,
        EVENT_PREPARE,
        EVENT_UNSHARE,
        EVENT_DE_THREAD,
        EVENT_COMMIT,
        EVENT_RESET,
        EVENT_SET_CREDENTIALS,
        EVENT_IDENTITY,
        EVENT_DELETE_TIMERS,
        EVENT_WAKE_VFORK,
        EVENT_PUBLISH,
        EVENT_CLOSE,
        EVENT_ENTER,
    };
    kernel_exec_request_t request = base_request("/sbin/request-key");
    int64_t result;

    reset_mocks();
    request.argv_user = 0;
    request.envp_user = 0;
    request.argv_kernel = arguments;
    request.argc_kernel = sizeof(arguments) / sizeof(arguments[0]);
    request.envp_kernel = environment;
    request.envc_kernel = sizeof(environment) / sizeof(environment[0]);
    g_enter_result = KERNEL_EXEC_ENTER_DEFERRED;
    result = kernel_process_exec(&request);
    expect_true("kernel exec deferred result", result == 0);
    expect_events("kernel exec deferred order", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

static void test_dethread_failure_rolls_back(void) {
    static const int expected[] = {
        EVENT_INITIALIZE,
        EVENT_CAPTURE_ARGUMENTS,
        EVENT_CAPTURE_ENVIRONMENT,
        EVENT_RESOLVE,
        EVENT_PROBE,
        EVENT_GET_CREDENTIALS,
        EVENT_PREPARE,
        EVENT_UNSHARE,
        EVENT_DE_THREAD,
        EVENT_ABORT,
        EVENT_RELEASE_PAYLOAD,
    };
    kernel_exec_request_t request = base_request("/bin/program");
    int64_t result;

    reset_mocks();
    g_fail_event = EVENT_DE_THREAD;
    result = kernel_process_exec(&request);
    expect_true("de-thread failure", result == -EDGE_LINUX_EIO);
    expect_events("de-thread rollback", expected,
                  sizeof(expected) / sizeof(expected[0]));
}

int main(void) {
    test_complete_transaction();
    test_shebang_policy();
    test_nofollow_rejects_symlink();
    test_precommit_failure_rolls_back();
    test_dethread_failure_rolls_back();
    test_postcommit_failure_is_fatal();
    test_kernel_vectors_defer_user_entry();
    if (g_failures) {
        fprintf(stderr, "process exec unit failures: %d\n", g_failures);
        return 1;
    }
    printf("process exec unit: PASS\n");
    return 0;
}
