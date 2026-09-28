/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux pipe worker-notification ABI regression test. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PIPE_WORKER_COUNT
#define PIPE_WORKER_COUNT 18
#endif

enum { WORKERS = PIPE_WORKER_COUNT };

static int fail(const char *operation) {
    fprintf(stderr, "pipe_worker_abi_probe: %s: %s\n",
            operation, strerror(errno));
    return 1;
}

int main(void) {
    int descriptors[2];
    pid_t children[WORKERS];
    uint32_t received[WORKERS];
    size_t bytes = 0;

    if (pipe2(descriptors, O_CLOEXEC | O_NONBLOCK) < 0)
        return fail("pipe2");
    if ((fcntl(descriptors[0], F_GETFL) & O_NONBLOCK) == 0 ||
        (fcntl(descriptors[1], F_GETFL) & O_NONBLOCK) == 0) {
        errno = EINVAL;
        return fail("O_NONBLOCK flags");
    }
    if ((fcntl(descriptors[0], F_GETFD) & FD_CLOEXEC) == 0 ||
        (fcntl(descriptors[1], F_GETFD) & FD_CLOEXEC) == 0) {
        errno = EINVAL;
        return fail("FD_CLOEXEC flags");
    }

    for (uint32_t index = 0; index < WORKERS; ++index) {
        pid_t child = fork();
        if (child < 0) return fail("fork");
        if (child == 0) {
            ssize_t written;
            close(descriptors[0]);
            written = write(descriptors[1], &index, sizeof(index));
            _exit(written == (ssize_t)sizeof(index) ? 0 : 100 + errno);
        }
        children[index] = child;
    }
    close(descriptors[1]);

    for (uint32_t index = 0; index < WORKERS; ++index) {
        int status;
        if (waitpid(children[index], &status, 0) != children[index])
            return fail("waitpid");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr,
                    "pipe_worker_abi_probe: worker %u status=%d\n",
                    index, status);
            return 1;
        }
    }

    while (bytes < sizeof(received)) {
        struct pollfd ready = {
            .fd = descriptors[0],
            .events = POLLIN | POLLHUP,
        };
        ssize_t count;
        int status = poll(&ready, 1, 5000);
        if (status < 0) return fail("poll");
        if (status == 0) {
            errno = ETIMEDOUT;
            return fail("worker result timeout");
        }
        count = read(descriptors[0], (char *)received + bytes,
                     sizeof(received) - bytes);
        if (count > 0) {
            bytes += (size_t)count;
            continue;
        }
        if (count == 0) break;
        if (errno != EAGAIN) return fail("read");
    }
    close(descriptors[0]);
    if (bytes != sizeof(received)) {
        fprintf(stderr,
                "pipe_worker_abi_probe: expected %zu result bytes, got %zu\n",
                sizeof(received), bytes);
        return 1;
    }

    puts("pipe_worker_abi_probe: PASS");
    return 0;
}
