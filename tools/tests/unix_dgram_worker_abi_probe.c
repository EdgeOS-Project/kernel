/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Unix datagram worker-notification ABI regression test. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef UNIX_DGRAM_WORKER_COUNT
#define UNIX_DGRAM_WORKER_COUNT 18
#endif

enum { WORKERS = UNIX_DGRAM_WORKER_COUNT };

static int fail(const char *operation) {
    fprintf(stderr, "unix_dgram_worker_abi_probe: %s: %s\n",
            operation, strerror(errno));
    return 1;
}

static int test_queue_and_blocking_wakeup(void) {
    enum { MAX_RECORDS = 4096 };
    int descriptors[2];
    uint32_t value = 0;
    uint32_t queued = 0;
    pid_t child;

    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, descriptors) < 0)
        return fail("blocking socketpair");
    if (fcntl(descriptors[1], F_SETFL,
              fcntl(descriptors[1], F_GETFL) | O_NONBLOCK) < 0)
        return fail("writer O_NONBLOCK");
    while (queued < MAX_RECORDS) {
        value = queued;
        if (write(descriptors[1], &value, sizeof(value)) ==
            (ssize_t)sizeof(value)) {
            ++queued;
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return fail("fill datagram queue");
        break;
    }
    if (queued < WORKERS || queued == MAX_RECORDS) {
        errno = queued < WORKERS ? ENOBUFS : EOVERFLOW;
        return fail("datagram queue capacity");
    }
    if (fcntl(descriptors[1], F_SETFL,
              fcntl(descriptors[1], F_GETFL) & ~O_NONBLOCK) < 0)
        return fail("writer blocking mode");

    child = fork();
    if (child < 0) return fail("blocking writer fork");
    if (child == 0) {
        uint32_t sentinel = UINT32_MAX;
        ssize_t written;
        close(descriptors[0]);
        written = write(descriptors[1], &sentinel, sizeof(sentinel));
        _exit(written == (ssize_t)sizeof(sentinel) ? 0 : 100 + errno);
    }
    usleep(50000);
    {
        int status;
        if (waitpid(child, &status, WNOHANG) != 0) {
            errno = EPROTO;
            return fail("full queue did not block writer");
        }
    }
    if (read(descriptors[0], &value, sizeof(value)) != (ssize_t)sizeof(value))
        return fail("free datagram queue slot");
    for (unsigned attempt = 0; attempt < 500u; ++attempt) {
        int status;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                errno = EIO;
                return fail("blocked writer status");
            }
            close(descriptors[0]);
            close(descriptors[1]);
            return 0;
        }
        if (waited < 0) return fail("blocked writer waitpid");
        usleep(10000);
    }
    errno = ETIMEDOUT;
    return fail("blocked writer wakeup");
}

int main(void) {
    int descriptors[2];
    pid_t children[WORKERS];
    uint32_t received[WORKERS];
    uint8_t seen[WORKERS] = {0};

    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, descriptors) < 0)
        return fail("socketpair");
    if ((fcntl(descriptors[0], F_GETFD) & FD_CLOEXEC) == 0 ||
        (fcntl(descriptors[1], F_GETFD) & FD_CLOEXEC) == 0) {
        errno = EINVAL;
        return fail("FD_CLOEXEC flags");
    }
    if (fcntl(descriptors[0], F_SETFL,
              fcntl(descriptors[0], F_GETFL) | O_NONBLOCK) < 0)
        return fail("reader O_NONBLOCK");

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
                    "unix_dgram_worker_abi_probe: worker %u status=%d\n",
                    index, status);
            return 1;
        }
    }

    for (uint32_t count = 0; count < WORKERS; ++count) {
        struct pollfd ready = {
            .fd = descriptors[0],
            .events = POLLIN | POLLHUP,
        };
        ssize_t bytes;
        int status = poll(&ready, 1, 5000);
        if (status < 0) return fail("poll");
        if (status == 0) {
            errno = ETIMEDOUT;
            return fail("worker result timeout");
        }
        bytes = read(descriptors[0], &received[count], sizeof(received[count]));
        if (bytes != (ssize_t)sizeof(received[count]))
            return fail("datagram read");
        if (received[count] >= WORKERS || seen[received[count]]) {
            errno = EPROTO;
            return fail("datagram boundary or payload");
        }
        seen[received[count]] = 1;
    }
    close(descriptors[0]);

    if (test_queue_and_blocking_wakeup() != 0) return 1;

    puts("unix_dgram_worker_abi_probe: PASS");
    return 0;
}
