/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int sync_pipe[2];
    pid_t child;
    int status = 0;
    char byte = 0;
    ssize_t n;
    int rc;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (pipe(sync_pipe) < 0) {
        printf("killpg_pipe_errno:%d\n", errno);
        return 1;
    }

    child = fork();
    if (child < 0) {
        printf("killpg_fork_errno:%d\n", errno);
        return 1;
    }

    if (child == 0) {
        close(sync_pipe[0]);
        if (setpgid(0, 0) < 0) {
            byte = 'E';
            (void)write(sync_pipe[1], &byte, 1);
            _exit(20);
        }
        byte = 'R';
        if (write(sync_pipe[1], &byte, 1) != 1) _exit(21);
        for (;;) pause();
    }

    close(sync_pipe[1]);
    n = read(sync_pipe[0], &byte, 1);
    printf("killpg_sync_read:%ld byte:%c errno:%d\n", (long)n, byte ? byte : '?', errno);
    if (n != 1 || byte != 'R') {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
        return 1;
    }

    rc = kill(-child, SIGKILL);
    printf("killpg_rc:%d errno:%d\n", rc, errno);
    if (rc != 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
        return 1;
    }

    rc = waitpid(child, &status, 0);
    printf("killpg_wait_rc:%d status:0x%x signaled:%d termsig:%d exited:%d exitstatus:%d\n",
           rc, status, WIFSIGNALED(status), WTERMSIG(status),
           WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    if (rc != child) return 1;
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) return 1;

    printf("KILL_PGID_WAIT_PROBE_PASS\n");
    return 0;
}
