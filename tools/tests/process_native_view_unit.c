/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side regression tests for shared native task view policy. */

#include "kernel/linux_errno.h"
#include "kernel/namespace_runtime.h"
#include "kernel/process_runtime.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static kernel_process_native_view_t current;
static kernel_process_native_view_t target;
static const edge_namespace_set_t *committed_namespaces;
static int32_t fs_snapshot_pid;
static int32_t fs_set_pid;
static int fs_set_root;
static int32_t fs_unshare_pid;
static char fs_set_path[64];

int edge_process_runtime_current_view(
    kernel_process_native_view_t *view) {
    if (!view || !current.context_token) return -1;
    *view = current;
    return 0;
}

int edge_process_runtime_view(
    int32_t pid, kernel_process_native_view_t *view) {
    if (!view || pid != target.pid) return -1;
    *view = target;
    return 0;
}

void edge_process_runtime_namespace_committed(
    const edge_namespace_set_t *namespaces) {
    committed_namespaces = namespaces;
}

int edge_process_runtime_fs_snapshot(
    int32_t pid, char *cwd, uint32_t cwd_capacity,
    char *root, uint32_t root_capacity) {
    fs_snapshot_pid = pid;
    if (pid != target.pid && pid != current.pid)
        return -EDGE_LINUX_ESRCH;
    if (cwd) {
        if (cwd_capacity < 6u) return -EDGE_LINUX_ENAMETOOLONG;
        strcpy(cwd, "/work");
    }
    if (root) {
        if (root_capacity < 2u) return -EDGE_LINUX_ENAMETOOLONG;
        strcpy(root, "/");
    }
    return 0;
}

int edge_process_runtime_fs_set_location(
    int32_t pid, const char *path, int set_root) {
    fs_set_pid = pid;
    fs_set_root = set_root;
    strcpy(fs_set_path, path);
    return 0;
}

int edge_process_runtime_fs_unshare(int32_t pid) {
    fs_unshare_pid = pid;
    return 0;
}

static void initialize_views(void) {
    static kernel_linux_thread_state_t current_thread;
    static kernel_linux_thread_state_t target_thread;
    static edge_namespace_set_t namespaces;
    static edge_linux_ptrace_state_t ptrace;
    static uint64_t signal_mask;

    memset(&current, 0, sizeof(current));
    memset(&target, 0, sizeof(target));
    memset(&current_thread, 0, sizeof(current_thread));
    memset(&target_thread, 0, sizeof(target_thread));
    memset(&namespaces, 0, sizeof(namespaces));
    memset(&ptrace, 0, sizeof(ptrace));
    current.context_token = 0x1234u;
    current.pid = 7;
    current.comm = "current";
    current.linux_thread = &current_thread;
    current.namespaces = &namespaces;
    target.context_token = 0x5678u;
    target.pid = 42;
    target.tgid = 40;
    target.ppid = 3;
    target.uid = 11;
    target.euid = 12;
    target.suid = 13;
    target.gid = 21;
    target.egid = 22;
    target.sgid = 23;
    target.dumpable = 1;
    target.stopped = 1;
    target.stop_reported = 1;
    target.stop_signal = 19;
    target.linux_thread = &target_thread;
    target.ptrace = &ptrace;
    target.signal_actions = 0;
    target.signal_mask = &signal_mask;
    target_thread.rseq.address = 0x1000u;
    target_thread.rseq.length = 32u;
    target_thread.rseq.signature = 0x53053053u;
    committed_namespaces = 0;
    fs_snapshot_pid = 0;
    fs_set_pid = 0;
    fs_set_root = -1;
    fs_unshare_pid = 0;
    fs_set_path[0] = 0;
}

static void test_current_view(void) {
    kernel_linux_thread_state_t *thread = 0;

    assert(kernel_arch_current_linux_thread_state(&thread) == 0);
    assert(thread == current.linux_thread);
    assert(strcmp(kernel_current_comm(), "current") == 0);
    assert(kernel_current_context_token() == 0x1234u);
    assert(kernel_arch_current_namespace_set() == current.namespaces);
    kernel_arch_current_namespace_committed(current.namespaces);
    assert(committed_namespaces == current.namespaces);
    committed_namespaces = 0;
    kernel_arch_current_namespace_committed(0);
    assert(!committed_namespaces);
}

static void test_target_view(void) {
    kernel_linux_thread_state_t *thread = 0;
    edge_linux_ptrace_task_runtime_t runtime;

    assert(kernel_arch_process_linux_thread_state(42, &thread) == 0);
    assert(thread == target.linux_thread);
    target.zombie = 1;
    assert(kernel_arch_process_linux_thread_state(42, &thread) < 0);
    target.zombie = 0;
    memset(&runtime, 0, sizeof(runtime));
    assert(kernel_arch_ptrace_task_runtime(42, &runtime) == 0);
    assert(runtime.pid == 42);
    assert(runtime.tgid == 40);
    assert(runtime.ppid == 3);
    assert(runtime.uid == 11);
    assert(runtime.euid == 12);
    assert(runtime.suid == 13);
    assert(runtime.gid == 21);
    assert(runtime.egid == 22);
    assert(runtime.sgid == 23);
    assert(runtime.dumpable == 1);
    assert(runtime.stopped == 1);
    assert(runtime.stop_reported == 1);
    assert(runtime.stop_signal == 19);
    assert(runtime.ptrace == target.ptrace);
    assert(runtime.signal_mask == target.signal_mask);
    assert(runtime.rseq_address == 0x1000u);
    assert(runtime.rseq_size == 32u);
    assert(runtime.rseq_signature == 0x53053053u);
}

static void test_fs_view(void) {
    char cwd[16];
    char root[16];

    assert(kernel_arch_current_fs_snapshot(
               cwd, sizeof(cwd), root, sizeof(root)) == 0);
    assert(fs_snapshot_pid == current.pid);
    assert(strcmp(cwd, "/work") == 0);
    assert(strcmp(root, "/") == 0);
    assert(kernel_arch_current_fs_set_location("/new", 1) == 0);
    assert(fs_set_pid == current.pid);
    assert(fs_set_root == 1);
    assert(strcmp(fs_set_path, "/new") == 0);
    assert(kernel_arch_current_fs_unshare() == 0);
    assert(fs_unshare_pid == current.pid);

    memset(cwd, 0, sizeof(cwd));
    memset(root, 0, sizeof(root));
    assert(kernel_arch_proc_task_fs_snapshot(
               target.pid, cwd, sizeof(cwd), root, sizeof(root)) == 0);
    assert(fs_snapshot_pid == target.pid);
    assert(strcmp(cwd, "/work") == 0);
    assert(strcmp(root, "/") == 0);
    assert(kernel_arch_proc_task_fs_snapshot(
               0, cwd, sizeof(cwd), root, sizeof(root)) ==
           -EDGE_LINUX_EINVAL);
}

static void test_missing_views(void) {
    kernel_linux_thread_state_t *thread = 0;
    edge_linux_ptrace_task_runtime_t runtime;

    current.context_token = 0;
    assert(kernel_arch_current_linux_thread_state(&thread) < 0);
    assert(strcmp(kernel_current_comm(), "unknown") == 0);
    assert(kernel_current_context_token() == 0);
    assert(!kernel_arch_current_namespace_set());
    assert(kernel_arch_process_linux_thread_state(99, &thread) < 0);
    assert(kernel_arch_ptrace_task_runtime(99, &runtime) ==
           -EDGE_LINUX_ESRCH);
    assert(kernel_arch_current_fs_snapshot(
               (char[2]){0}, 2u, (char[2]){0}, 2u) ==
           -EDGE_LINUX_EIO);
    assert(kernel_arch_current_fs_set_location("/", 0) ==
           -EDGE_LINUX_EIO);
    assert(kernel_arch_current_fs_unshare() == -EDGE_LINUX_EIO);
}

int main(void) {
    initialize_views();
    test_current_view();
    test_target_view();
    test_fs_view();
    test_missing_views();
    puts("process_native_view_unit: PASS");
    return 0;
}
