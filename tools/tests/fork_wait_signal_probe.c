/* SPDX-License-Identifier: MPL-2.0 */
/* Repeated fork, SIGCHLD delivery, and wait4 register-frame regression probe. */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t child_signals;

static void child_signal(int signal_number) {
    (void)signal_number;
    child_signals++;
}

int main(int argc, char **argv) {
    struct sigaction action;
    unsigned long limit = 1000;
    unsigned long fanout = 1;

    if (argc > 1) {
        char *end = 0;
        limit = strtoul(argv[1], &end, 10);
        if (!end || *end || !limit) return 2;
    }
    if (argc > 2) {
        char *end = 0;
        fanout = strtoul(argv[2], &end, 10);
        if (!end || *end || !fanout || fanout > 64) return 2;
    }
    action.sa_handler = child_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGCHLD, &action, 0) < 0) {
        perror("sigaction");
        return 1;
    }
    for (unsigned long iteration = 0; iteration < limit; ++iteration) {
        pid_t children[64];

        for (unsigned long child_index = 0; child_index < fanout;
             ++child_index) {
            children[child_index] = fork();
            if (children[child_index] < 0) {
                perror("fork");
                return 1;
            }
            if (!children[child_index])
                _exit((int)((iteration + child_index) & 7u));
        }
        for (unsigned long child_index = 0; child_index < fanout;
             ++child_index) {
            int status = 0;
            for (;;) {
                pid_t waited = waitpid(children[child_index], &status, 0);

                if (waited == children[child_index]) break;
                if (waited < 0 && errno == EINTR) continue;
                perror("waitpid");
                return 1;
            }
            if (!WIFEXITED(status) ||
                WEXITSTATUS(status) !=
                    (int)((iteration + child_index) & 7u)) {
                fprintf(stderr,
                        "invalid child status at iteration %lu child %lu: %#x\n",
                        iteration, child_index, status);
                return 1;
            }
        }
    }
    printf("FORK_WAIT_SIGNAL_PROBE_PASS count=%lu fanout=%lu signals=%d\n",
           limit, fanout, (int)child_signals);
    return 0;
}
