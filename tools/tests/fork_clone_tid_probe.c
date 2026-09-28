/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_clone
#define SYS_clone 56
#endif

#ifndef SYS_clone3
#define SYS_clone3 435
#endif

#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID 0x00100000
#endif

#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID 0x00200000
#endif

#ifndef CLONE_CHILD_SETTID
#define CLONE_CHILD_SETTID 0x01000000
#endif

#ifndef SIGCHLD
#define SIGCHLD 17
#endif

struct edge_test_clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

static int wait_for_exit(pid_t pid, int want_code, const char *label) {
    int status = 0;
    pid_t got = waitpid(pid, &status, 0);
    if (got != pid) {
        printf("%s_wait_rc:%ld errno:%d\n", label, (long)got, errno);
        return 1;
    }
    printf("%s_status:0x%x exited:%d code:%d\n",
           label, status, WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return !(WIFEXITED(status) && WEXITSTATUS(status) == want_code);
}

static int test_libc_fork(void) {
    pid_t pid = fork();
    if (pid < 0) {
        printf("fork_rc:-1 errno:%d\n", errno);
        return 1;
    }
    if (pid == 0) _exit(23);
    printf("fork_child:%ld\n", (long)pid);
    return wait_for_exit(pid, 23, "fork");
}

static int test_clone_child_tid(void) {
    volatile int child_tid = -1;
#if defined(__aarch64__)
    long rc = syscall(SYS_clone,
                      (long)(SIGCHLD | CLONE_CHILD_SETTID |
                             CLONE_CHILD_CLEARTID),
                      0, 0, 0, &child_tid);
#else
    long rc = syscall(SYS_clone,
                      (long)(SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID),
                      0, 0, &child_tid, 0);
#endif
    if (rc < 0) {
        printf("clone_child_tid_rc:%ld errno:%d\n", rc, errno);
        return 1;
    }
    if (rc == 0) {
        int tid = (int)syscall(SYS_gettid);
        _exit(child_tid == tid ? 24 : 124);
    }
    printf("clone_child_tid_child:%ld parent_seen_tid:%d\n", rc, child_tid);
    if (child_tid != -1) return 1;
    return wait_for_exit((pid_t)rc, 24, "clone_child_tid");
}

static int test_clone_parent_tid(void) {
    int parent_tid = -1;
    long rc = syscall(SYS_clone,
                      (long)(SIGCHLD | CLONE_PARENT_SETTID),
                      0, &parent_tid, 0, 0);
    if (rc < 0) {
        printf("clone_parent_tid_rc:%ld errno:%d\n", rc, errno);
        return 1;
    }
    if (rc == 0) _exit(25);
    printf("clone_parent_tid_child:%ld parent_tid:%d\n", rc, parent_tid);
    if (parent_tid != (int)rc) return 1;
    return wait_for_exit((pid_t)rc, 25, "clone_parent_tid");
}

static int test_clone3_child_tid(void) {
    volatile int child_tid = -1;
    struct edge_test_clone_args ca;
    long rc;

    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    ca.exit_signal = SIGCHLD;
    ca.child_tid = (uint64_t)(uintptr_t)&child_tid;
    rc = syscall(SYS_clone3, &ca, sizeof(ca));
    if (rc < 0) {
        printf("clone3_child_tid_rc:%ld errno:%d\n", rc, errno);
        return 1;
    }
    if (rc == 0) {
        int tid = (int)syscall(SYS_gettid);
        _exit(child_tid == tid ? 26 : 126);
    }
    printf("clone3_child_tid_child:%ld parent_seen_tid:%d\n", rc, child_tid);
    if (child_tid != -1) return 1;
    return wait_for_exit((pid_t)rc, 26, "clone3_child_tid");
}

static int test_clone3_parent_tid(void) {
    int parent_tid = -1;
    struct edge_test_clone_args ca;
    long rc;

    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE_PARENT_SETTID;
    ca.exit_signal = SIGCHLD;
    ca.parent_tid = (uint64_t)(uintptr_t)&parent_tid;
    rc = syscall(SYS_clone3, &ca, sizeof(ca));
    if (rc < 0) {
        printf("clone3_parent_tid_rc:%ld errno:%d\n", rc, errno);
        return 1;
    }
    if (rc == 0) _exit(27);
    printf("clone3_parent_tid_child:%ld parent_tid:%d\n", rc, parent_tid);
    if (parent_tid != (int)rc) return 1;
    return wait_for_exit((pid_t)rc, 27, "clone3_parent_tid");
}

int main(void) {
    int failed = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    failed |= test_libc_fork();
    failed |= test_clone_child_tid();
    failed |= test_clone_parent_tid();
    failed |= test_clone3_child_tid();
    failed |= test_clone3_parent_tid();
    printf("FORK_CLONE_TID_PROBE_%s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
