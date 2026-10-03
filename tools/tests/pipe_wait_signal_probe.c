/* SPDX-License-Identifier: MPL-2.0 */
/* Command-substitution-style pipe EOF, SIGCHLD, and wait4 frame probe. */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t child_signals;

static void child_signal(int signal_number) {
    (void)signal_number;
    child_signals++;
}

int main(int argc, char **argv) {
    static const char payload[] = "HeLLo\n";
    struct sigaction action;
    unsigned long limit = 1000;

    if (argc > 1) {
        char *end = 0;
        limit = strtoul(argv[1], &end, 10);
        if (!end || *end || !limit) return 2;
    }
    action.sa_handler = child_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGCHLD, &action, 0) < 0) {
        perror("sigaction");
        return 1;
    }
    for (unsigned long iteration = 0; iteration < limit; ++iteration) {
        char output[sizeof(payload)] = {0};
        int descriptors[2];
        int status = 0;
        size_t used = 0;
        pid_t child;

        if (pipe(descriptors) < 0) {
            perror("pipe");
            return 1;
        }
        child = fork();
        if (child < 0) {
            perror("fork");
            return 1;
        }
        if (!child) {
            close(descriptors[0]);
            if (write(descriptors[1], payload, sizeof(payload) - 1u) !=
                (ssize_t)(sizeof(payload) - 1u))
                _exit(20);
            close(descriptors[1]);
            _exit(0);
        }
        close(descriptors[1]);
        for (;;) {
            ssize_t amount = read(descriptors[0], output + used,
                                  sizeof(output) - used);

            if (amount > 0) {
                used += (size_t)amount;
                continue;
            }
            if (!amount) break;
            if (errno == EINTR) continue;
            perror("read");
            return 1;
        }
        close(descriptors[0]);
        while (waitpid(child, &status, 0) < 0) {
            if (errno == EINTR) continue;
            perror("waitpid");
            return 1;
        }
        if (used != sizeof(payload) - 1u ||
            memcmp(output, payload, sizeof(payload) - 1u) ||
            !WIFEXITED(status) || WEXITSTATUS(status)) {
            fprintf(stderr, "invalid result at iteration %lu\n", iteration);
            return 1;
        }
    }
    printf("PIPE_WAIT_SIGNAL_PROBE_PASS count=%lu signals=%d\n",
           limit, (int)child_signals);
    return 0;
}
