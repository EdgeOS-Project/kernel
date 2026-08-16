/*
 * EdgeOS original code, licensed under MPL-2.0.
 *
 * Verify Linux PR_SET_PDEATHSIG semantics used by short-lived desktop helper
 * supervisors: the setting is not inherited by fork, survives exec, and is
 * delivered when the task that created the child exits.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t parent_died;

static void parent_death_handler(int signal_number) {
    (void)signal_number;
    parent_died = 1;
}

static int write_exact(int fd, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int read_exact(int fd, void *buffer, size_t length) {
    unsigned char *cursor = buffer;
    while (length > 0) {
        ssize_t received = read(fd, cursor, length);
        if (received == 0) return -1;
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        cursor += (size_t)received;
        length -= (size_t)received;
    }
    return 0;
}

static int exec_child_mode(int ready_fd, int result_fd) {
    struct sigaction action;
    int configured_signal = -1;
    char ready = 'R';
    char result = 'P';

    memset(&action, 0, sizeof(action));
    action.sa_handler = parent_death_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) < 0) return 20;
    if (prctl(PR_GET_PDEATHSIG, &configured_signal, 0, 0, 0) < 0) return 21;
    if (configured_signal != SIGUSR1) return 22;
    if (write_exact(ready_fd, &ready, sizeof(ready)) < 0) return 23;

    while (!parent_died) pause();
    if (write_exact(result_fd, &result, sizeof(result)) < 0) return 24;
    return 0;
}

static int check_fork_clears_setting(void) {
    int report[2];
    int child_value = -1;
    int status = 0;
    pid_t child;

    if (pipe(report) < 0) return -1;
    if (prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) < 0) return -1;
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        int value = -1;
        close(report[0]);
        if (prctl(PR_GET_PDEATHSIG, &value, 0, 0, 0) < 0) _exit(30);
        if (write_exact(report[1], &value, sizeof(value)) < 0) _exit(31);
        _exit(0);
    }

    close(report[1]);
    if (prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) < 0) return -1;
    if (read_exact(report[0], &child_value, sizeof(child_value)) < 0) return -1;
    close(report[0]);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return -1;
    return child_value == 0 ? 0 : -1;
}

static int check_credential_change_clears_setting(void) {
    int report[2];
    int child_value = -1;
    int status = 0;
    pid_t child;

    if (pipe(report) < 0) return -1;
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        int value = -1;
        close(report[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) < 0) _exit(32);
        if (seteuid(123) < 0) _exit(33);
        if (prctl(PR_GET_PDEATHSIG, &value, 0, 0, 0) < 0) _exit(34);
        if (write_exact(report[1], &value, sizeof(value)) < 0) _exit(35);
        _exit(0);
    }

    close(report[1]);
    if (read_exact(report[0], &child_value, sizeof(child_value)) < 0)
        return -1;
    close(report[0]);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return -1;
    return child_value == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    int ready_pipe[2];
    int result_pipe[2];
    int status = 0;
    int configured_signal = -1;
    char ready = 0;
    char result = 0;
    char ready_fd_text[24];
    char result_fd_text[24];
    pid_t supervisor;

    if (argc == 4 && strcmp(argv[1], "--exec-child") == 0) {
        return exec_child_mode(atoi(argv[2]), atoi(argv[3]));
    }

    errno = 0;
    if (prctl(PR_SET_PDEATHSIG, 65, 0, 0, 0) != -1 || errno != EINVAL) {
        fprintf(stderr, "invalid parent-death signal was not rejected\n");
        return 1;
    }
    if (check_fork_clears_setting() < 0) {
        fprintf(stderr, "fork did not clear parent-death signal state\n");
        return 2;
    }
    if (check_credential_change_clears_setting() < 0) {
        fprintf(stderr,
                "credential transition did not clear parent-death signal state\n");
        return 8;
    }
    if (pipe(ready_pipe) < 0 || pipe(result_pipe) < 0) return 3;

    supervisor = fork();
    if (supervisor < 0) return 4;
    if (supervisor == 0) {
        pid_t child;
        close(result_pipe[0]);
        child = fork();
        if (child < 0) _exit(40);
        if (child == 0) {
            close(ready_pipe[0]);
            if (prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) < 0) _exit(41);
            snprintf(ready_fd_text, sizeof(ready_fd_text), "%d", ready_pipe[1]);
            snprintf(result_fd_text, sizeof(result_fd_text), "%d", result_pipe[1]);
            execl(argv[0], argv[0], "--exec-child", ready_fd_text,
                  result_fd_text, (char *)NULL);
            _exit(42);
        }
        close(ready_pipe[1]);
        close(result_pipe[1]);
        if (read_exact(ready_pipe[0], &ready, sizeof(ready)) < 0 || ready != 'R') _exit(43);
        close(ready_pipe[0]);
        _exit(0);
    }

    close(ready_pipe[0]);
    close(ready_pipe[1]);
    close(result_pipe[1]);
    if (waitpid(supervisor, &status, 0) != supervisor ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "supervisor did not exit normally\n");
        return 5;
    }
    {
        struct pollfd wait_result = {
            .fd = result_pipe[0],
            .events = POLLIN,
        };
        int poll_result = poll(&wait_result, 1, 5000);
        if (poll_result != 1 || !(wait_result.revents & POLLIN) ||
            read_exact(result_pipe[0], &result, sizeof(result)) < 0 || result != 'P') {
            fprintf(stderr, "parent-death signal was not delivered after exec\n");
            return 6;
        }
    }
    close(result_pipe[0]);

    if (prctl(PR_GET_PDEATHSIG, &configured_signal, 0, 0, 0) < 0 || configured_signal != 0) {
        fprintf(stderr, "caller parent-death signal state changed unexpectedly\n");
        return 7;
    }
    puts("PRCTL_PDEATHSIG_PROBE_PASS");
    return 0;
}
