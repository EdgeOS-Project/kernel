/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux VT activation and wait ABI regression test. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct edge_linux_vt_stat {
    unsigned short active;
    unsigned short signal;
    unsigned short state;
};

#define EDGE_LINUX_VT_GETSTATE 0x5603u
#define EDGE_LINUX_VT_ACTIVATE 0x5606u
#define EDGE_LINUX_VT_WAITACTIVE 0x5607u

static void sleep_milliseconds(long milliseconds) {
    struct timespec delay;

    delay.tv_sec = milliseconds / 1000;
    delay.tv_nsec = (milliseconds % 1000) * 1000000L;
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
}

static int wait_child(pid_t child, int *status) {
    for (int attempt = 0; attempt < 100; ++attempt) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 0;
        if (result < 0) return -1;
        sleep_milliseconds(10);
    }
    errno = ETIMEDOUT;
    return -1;
}

int main(void) {
    struct edge_linux_vt_stat state;
    int ready[2];
    int original;
    int target;
    int descriptor;
    int status;
    char byte;
    pid_t child;

    descriptor = open("/dev/tty0", O_RDWR | O_CLOEXEC);
    if (descriptor < 0) {
        perror("open /dev/tty0");
        return 1;
    }
    if (ioctl(descriptor, EDGE_LINUX_VT_GETSTATE, &state) < 0) {
        perror("VT_GETSTATE");
        return 1;
    }
    original = state.active;
    target = original == 63 ? 62 : 63;
    if (pipe(ready) < 0 ||
        fcntl(ready[0], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(ready[1], F_SETFD, FD_CLOEXEC) < 0) {
        perror("pipe");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        close(ready[0]);
        if (write(ready[1], "R", 1) != 1) _exit(2);
        if (ioctl(descriptor, EDGE_LINUX_VT_WAITACTIVE, target) < 0) _exit(3);
        _exit(0);
    }

    close(ready[1]);
    if (read(ready[0], &byte, 1) != 1) {
        perror("child readiness");
        kill(child, SIGKILL);
        return 1;
    }
    sleep_milliseconds(100);
    if (waitpid(child, &status, WNOHANG) != 0) {
        fprintf(stderr, "VT_WAITACTIVE returned before activation\n");
        return 1;
    }
    if (ioctl(descriptor, EDGE_LINUX_VT_ACTIVATE, target) < 0) {
        perror("VT_ACTIVATE target");
        kill(child, SIGKILL);
        return 1;
    }
    if (wait_child(child, &status) < 0) {
        perror("wait for VT_WAITACTIVE child");
        kill(child, SIGKILL);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "VT_WAITACTIVE child status=%d\n", status);
        return 1;
    }
    if (ioctl(descriptor, EDGE_LINUX_VT_GETSTATE, &state) < 0 ||
        state.active != target) {
        fprintf(stderr, "active VT mismatch: got=%u expected=%d errno=%d\n",
                state.active, target, errno);
        return 1;
    }
    if (ioctl(descriptor, EDGE_LINUX_VT_ACTIVATE, original) < 0 ||
        ioctl(descriptor, EDGE_LINUX_VT_WAITACTIVE, original) < 0) {
        perror("restore original VT");
        return 1;
    }

    puts("vt_waitactive_abi_probe: PASS");
    return 0;
}
