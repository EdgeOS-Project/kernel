/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS shared readlink policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/vfs_runtime.h"

static int g_failures;
static int32_t g_last_fd_pid;
static int32_t g_last_fd;
static int g_arch_path_calls;
static kernel_procfd_link_kind_t g_fd_kind = KERNEL_PROCFD_LINK_PIPE;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static void expect_target(const char *name, const char *path,
                          uint32_t capacity, const char *expected) {
    char target[128];
    int result;
    size_t expected_length = strlen(expected);

    memset(target, 0, sizeof(target));
    result = kernel_vfs_readlink_target(path, target, capacity);
    if (expected_length > capacity) expected_length = capacity;
    expect_true(name, result == (int)expected_length &&
                memcmp(target, expected, expected_length) == 0);
}

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    memset(identity, 0, sizeof(*identity));
    identity->global_tgid = 100;
    identity->global_tid = 101;
    identity->tgid = 7;
    identity->tid = 8;
    return 0;
}

int kernel_proc_task_snapshot(int32_t pid,
                              kernel_proc_task_snapshot_t *snapshot) {
    if (!snapshot || (pid != 42 && pid != 100 && pid != 101))
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    memcpy(snapshot->exec_path, "/bin/demo", sizeof("/bin/demo"));
    return 0;
}

int kernel_proc_task_fs_snapshot(int32_t pid, char *cwd,
                                 uint32_t cwd_capacity, char *root,
                                 uint32_t root_capacity) {
    if (pid != 42 && pid != 100 && pid != 101) return -1;
    if (cwd && cwd_capacity >= sizeof("/home/demo"))
        memcpy(cwd, "/home/demo", sizeof("/home/demo"));
    if (root && root_capacity >= sizeof("/"))
        memcpy(root, "/", sizeof("/"));
    return 0;
}

int arch_procfd_link_view(int32_t pid, int32_t descriptor,
                          kernel_procfd_link_view_t *view) {
    static const char path[] = "/fd/path";
    uint32_t length = sizeof(path) - 1u;

    g_last_fd_pid = pid;
    g_last_fd = descriptor;
    view->kind = g_fd_kind;
    view->identity = 77;
    if (view->kind == KERNEL_PROCFD_LINK_PATH) {
        if (length > view->path_capacity)
            length = view->path_capacity;
        memcpy(view->path, path, length);
        view->path_length = length;
    }
    return 0;
}

int arch_vfs_readlink_path(const char *path, char *target,
                           uint32_t capacity) {
    static const char disk_target[] = "disk-link";
    uint32_t length = sizeof(disk_target) - 1u;

    ++g_arch_path_calls;
    if (!path || strcmp(path, "/disk/link") != 0)
        return -EDGE_LINUX_ENOENT;
    if (length > capacity) length = capacity;
    memcpy(target, disk_target, length);
    return (int)length;
}

static void test_validation_and_aliases(void) {
    char target[8];

    expect_true("null path",
                kernel_vfs_readlink_target(0, target, sizeof(target)) ==
                    -EDGE_LINUX_EFAULT);
    expect_true("null target",
                kernel_vfs_readlink_target("/proc/self", 0,
                                           sizeof(target)) ==
                    -EDGE_LINUX_EFAULT);
    expect_true("zero capacity",
                kernel_vfs_readlink_target("/proc/self", target, 0) ==
                    -EDGE_LINUX_EFAULT);
    expect_target("self alias", "/proc/self", 32, "7");
    expect_target("thread-self alias", "/proc/thread-self", 32,
                  "7/task/8");
    expect_target("alias truncation", "/proc/thread-self", 3,
                  "7/task/8");
}

static void test_task_links(void) {
    expect_target("self executable", "/proc/self/exe", 64, "/bin/demo");
    expect_target("numeric executable", "/proc/42/exe", 64, "/bin/demo");
    expect_target("numeric cwd", "/proc/42/cwd", 64, "/home/demo");
    expect_target("numeric root", "/proc/42/root", 64, "/");
    expect_true("missing task",
                kernel_vfs_readlink_target(
                    "/proc/99/exe", (char[8]){0}, 8) ==
                    -EDGE_LINUX_ENOENT);
}

static void test_descriptor_links(void) {
    char target[64];

    g_fd_kind = KERNEL_PROCFD_LINK_PIPE;
    expect_target("self descriptor", "/proc/self/fd/9", 64,
                  "pipe:[77]");
    expect_true("self descriptor identity",
                g_last_fd_pid == 100 && g_last_fd == 9);
    expect_target("thread descriptor", "/proc/thread-self/fd/5", 64,
                  "pipe:[77]");
    expect_true("thread descriptor identity",
                g_last_fd_pid == 101 && g_last_fd == 5);
    expect_target("numeric descriptor", "/proc/42/fd/6", 64,
                  "pipe:[77]");
    expect_true("numeric descriptor identity",
                g_last_fd_pid == 42 && g_last_fd == 6);
    expect_target("task descriptor", "/proc/42/task/43/fd/4", 64,
                  "pipe:[77]");
    expect_true("task descriptor identity",
                g_last_fd_pid == 43 && g_last_fd == 4);
    expect_target("standard input", "/dev/stdin", 64, "pipe:[77]");
    expect_true("standard input identity",
                g_last_fd_pid == 100 && g_last_fd == 0);
    g_fd_kind = KERNEL_PROCFD_LINK_SOCKET;
    expect_target("socket descriptor", "/proc/self/fd/9", 64,
                  "socket:[77]");
    g_fd_kind = KERNEL_PROCFD_LINK_PIDFD;
    expect_target("pidfd descriptor", "/proc/self/fd/9", 64,
                  "anon_inode:[pidfd]");
    g_fd_kind = KERNEL_PROCFD_LINK_ANONYMOUS;
    expect_target("anonymous descriptor", "/proc/self/fd/9", 64,
                  "anon_inode:[edge-fd-9]");
    g_fd_kind = KERNEL_PROCFD_LINK_PATH;
    expect_target("path descriptor", "/proc/self/fd/9", 64,
                  "/fd/path");
    expect_true("malformed descriptor",
                kernel_vfs_readlink_target(
                    "/proc/self/fd/x", target, sizeof(target)) ==
                    -EDGE_LINUX_ENOENT);
}

static void test_native_path_fallback(void) {
    expect_target("native symlink", "/disk/link", 64, "disk-link");
    expect_true("native path dispatch", g_arch_path_calls == 1);
}

int main(void) {
    test_validation_and_aliases();
    test_task_links();
    test_descriptor_links();
    test_native_path_fallback();
    if (g_failures) return 1;
    puts("vfs_readlink_unit: PASS");
    return 0;
}
