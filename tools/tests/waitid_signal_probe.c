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
    pid_t child;
    siginfo_t si;
    int status = 0;
    int rc;

    setvbuf(stdout, NULL, _IONBF, 0);

    child = fork();
    if (child < 0) {
        printf("waitid_fork_errno:%d\n", errno);
        return 1;
    }

    if (child == 0) {
        for (;;) pause();
    }

    if (kill(child, SIGKILL) < 0) {
        printf("waitid_kill_errno:%d\n", errno);
        return 1;
    }

    memset(&si, 0x5a, sizeof(si));
    rc = waitid(P_PID, child, &si, WEXITED | WNOWAIT);
    printf("waitid_signal_rc:%d errno:%d signo:%d code:%d pid:%d status:%d\n",
           rc, errno, si.si_signo, si.si_code, si.si_pid, si.si_status);
    if (rc != 0) return 1;
    if (si.si_signo != SIGCHLD) return 1;
    if (si.si_code != CLD_KILLED) return 1;
    if (si.si_pid != child) return 1;
    if (si.si_status != SIGKILL) return 1;

    rc = waitpid(child, &status, 0);
    printf("waitid_reap_rc:%d status:0x%x signaled:%d termsig:%d exited:%d exitstatus:%d\n",
           rc, status, WIFSIGNALED(status), WTERMSIG(status),
           WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    if (rc != child) return 1;
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) return 1;

    memset(&si, 0, sizeof(si));
    errno = 0;
    rc = waitid(P_PID, child, &si, WEXITED | WNOHANG);
    printf("waitid_after_reap_rc:%d errno:%d signo:%d pid:%d status:%d\n",
           rc, errno, si.si_signo, si.si_pid, si.si_status);
    if (rc == 0) return 1;
    if (errno != ECHILD) return 1;

    printf("WAITID_SIGNAL_PROBE_PASS\n");
    return 0;
}
