/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test for Linux child-subreaper process semantics.
 * Copyright (c) EdgeOS Contributors.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void fail(const char *operation) {
    fprintf(stderr, "FAIL: %s: errno=%d (%s)\n",
            operation, errno, strerror(errno));
    ++failures;
}

static int subreaper_get(void) {
    int value = -1;
    if (prctl(PR_GET_CHILD_SUBREAPER, &value, 0L, 0L, 0L) < 0) {
        fail("PR_GET_CHILD_SUBREAPER");
        return -1;
    }
    return value;
}

static void *thread_check(void *argument) {
    int *result = argument;
    *result = subreaper_get();
    if (*result == 1 &&
        prctl(PR_SET_CHILD_SUBREAPER, 0L, 0L, 0L, 0L) < 0)
        *result = -1;
    return NULL;
}

static int exec_check(void) {
    return subreaper_get() == 1 ? 0 : 90;
}

static int wait_exit(pid_t pid, int expected) {
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        fail("waitpid");
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expected) {
        fprintf(stderr, "FAIL: pid %ld status=0x%x expected=%d\n",
                (long)pid, status, expected);
        ++failures;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    pthread_t thread;
    int thread_result = -1;
    int child_pid_pipe[2];
    int grandchild_report_pipe[2];
    int release_pipe[2];
    pid_t child;
    pid_t grandchild;
    pid_t observed_parent = -1;
    pid_t self = getpid();

    if (argc == 2 && strcmp(argv[1], "--exec-check") == 0)
        return exec_check();

    if (subreaper_get() != 0) {
        fprintf(stderr, "FAIL: initial child subreaper state is not zero\n");
        ++failures;
    }
    errno = 0;
    if (prctl(PR_GET_CHILD_SUBREAPER, (int *)0, 0L, 0L, 0L) != -1 ||
        errno != EFAULT) {
        fprintf(stderr, "FAIL: null GET result errno=%d\n", errno);
        ++failures;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 7L, 0L, 0L, 0L) < 0)
        fail("PR_SET_CHILD_SUBREAPER nonzero");
    if (subreaper_get() != 1) {
        fprintf(stderr, "FAIL: nonzero SET did not enable subreaper\n");
        ++failures;
    }

    if (pthread_create(&thread, NULL, thread_check, &thread_result) != 0) {
        fail("pthread_create");
    } else {
        if (pthread_join(thread, NULL) != 0) fail("pthread_join");
        if (thread_result != 1 || subreaper_get() != 0) {
            fprintf(stderr,
                    "FAIL: child subreaper state is not process-wide\n");
            ++failures;
        }
    }

    if (prctl(PR_SET_CHILD_SUBREAPER, 1L, 0L, 0L, 0L) < 0)
        fail("enable subreaper");

    child = fork();
    if (child < 0) {
        fail("fork for exec preservation");
    } else if (child == 0) {
        if (subreaper_get() != 0) _exit(91);
        if (prctl(PR_SET_CHILD_SUBREAPER, 1L, 0L, 0L, 0L) < 0)
            _exit(92);
        execl(argv[0], argv[0], "--exec-check", (char *)NULL);
        _exit(93);
    } else {
        (void)wait_exit(child, 0);
    }

    if (pipe(child_pid_pipe) < 0 || pipe(grandchild_report_pipe) < 0 ||
        pipe(release_pipe) < 0) {
        fail("pipe");
        return 1;
    }

    child = fork();
    if (child < 0) {
        fail("fork reparent parent");
        return 1;
    }
    if (child == 0) {
        char release;
        close(child_pid_pipe[0]);
        close(grandchild_report_pipe[0]);
        close(release_pipe[1]);
        if (subreaper_get() != 0) _exit(94);
        grandchild = fork();
        if (grandchild < 0) _exit(95);
        if (grandchild == 0) {
            close(child_pid_pipe[1]);
            if (read(release_pipe[0], &release, 1) != 1) _exit(96);
            observed_parent = getppid();
            if (write(grandchild_report_pipe[1], &observed_parent,
                      sizeof(observed_parent)) != sizeof(observed_parent))
                _exit(97);
            _exit(17);
        }
        if (write(child_pid_pipe[1], &grandchild, sizeof(grandchild)) !=
            sizeof(grandchild))
            _exit(98);
        _exit(23);
    }

    close(child_pid_pipe[1]);
    close(grandchild_report_pipe[1]);
    close(release_pipe[0]);
    if (read(child_pid_pipe[0], &grandchild, sizeof(grandchild)) !=
        sizeof(grandchild)) {
        fail("read grandchild pid");
        return 1;
    }
    (void)wait_exit(child, 23);
    if (write(release_pipe[1], "x", 1) != 1) fail("release grandchild");
    if (read(grandchild_report_pipe[0], &observed_parent,
             sizeof(observed_parent)) != sizeof(observed_parent)) {
        fail("read adopted parent");
    } else if (observed_parent != self) {
        fprintf(stderr, "FAIL: adopted parent=%ld expected=%ld\n",
                (long)observed_parent, (long)self);
        ++failures;
    }
    (void)wait_exit(grandchild, 17);

    if (prctl(PR_SET_CHILD_SUBREAPER, 0L, 0L, 0L, 0L) < 0)
        fail("disable subreaper");
    if (subreaper_get() != 0) {
        fprintf(stderr, "FAIL: final child subreaper state is not zero\n");
        ++failures;
    }

    if (failures) {
        fprintf(stderr, "subreaper_abi_probe: FAIL (%d)\n", failures);
        return 1;
    }
    puts("subreaper_abi_probe: PASS");
    return 0;
}
