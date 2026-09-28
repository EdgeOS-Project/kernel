/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS high-index Unix socket wakeup regression test.
 * Copyright (c) EdgeOS Contributors.
 *
 * Keep enough Unix sockets alive to place the tested SOCK_SEQPACKET pair
 * above slot 255, then verify that a blocked recvmsg is awakened by a
 * rights-bearing message. This catches accidental socket-index truncation.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define HOLDER_COUNT 2
#define SOCKETS_PER_HOLDER 140

struct holder {
    pid_t process_id;
    int ready_read;
    int stop_write;
};

static int fail(const char *operation) {
    fprintf(stderr, "socket_high_index_rights_wake_probe: %s: %s\n",
            operation, strerror(errno));
    return 1;
}

static void stop_holders(struct holder holders[HOLDER_COUNT]) {
    for (int index = 0; index < HOLDER_COUNT; ++index) {
        if (holders[index].stop_write >= 0) {
            (void)write(holders[index].stop_write, "X", 1);
            close(holders[index].stop_write);
            holders[index].stop_write = -1;
        }
    }
    for (int index = 0; index < HOLDER_COUNT; ++index) {
        if (holders[index].process_id > 0)
            (void)waitpid(holders[index].process_id, NULL, 0);
        if (holders[index].ready_read >= 0)
            close(holders[index].ready_read);
    }
}

static int start_holder(struct holder *holder) {
    int ready[2];
    int stop[2];
    pid_t child;

    if (pipe(ready) < 0 || pipe(stop) < 0)
        return -1;
    child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        int sockets[SOCKETS_PER_HOLDER];
        char byte;

        close(ready[0]);
        close(stop[1]);
        for (int index = 0; index < SOCKETS_PER_HOLDER; ++index) {
            sockets[index] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (sockets[index] < 0)
                _exit(100 + (errno & 63));
        }
        if (write(ready[1], "R", 1) != 1)
            _exit(90);
        close(ready[1]);
        if (read(stop[0], &byte, 1) != 1)
            _exit(91);
        for (int index = 0; index < SOCKETS_PER_HOLDER; ++index)
            close(sockets[index]);
        _exit(0);
    }

    close(ready[1]);
    close(stop[0]);
    holder->process_id = child;
    holder->ready_read = ready[0];
    holder->stop_write = stop[1];
    return 0;
}

static int send_descriptor(int socket_fd, int descriptor) {
    char first[] = "filesystem ";
    char second[] = "broker";
    struct iovec vectors[2] = {
        {.iov_base = first, .iov_len = sizeof(first) - 1u},
        {.iov_base = second, .iov_len = sizeof(second) - 1u},
    };
    char control[CMSG_SPACE(sizeof(descriptor))];
    struct msghdr message;
    struct cmsghdr *header;

    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_iov = vectors;
    message.msg_iovlen = 2;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(descriptor));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
    return sendmsg(socket_fd, &message, 0) == 17 ? 0 : -1;
}

static int receive_and_check(int socket_fd) {
    char payload[32];
    struct iovec vector = {.iov_base = payload, .iov_len = sizeof(payload)};
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr message;
    struct cmsghdr *header;
    int descriptor = -1;
    char byte = 0;
    ssize_t count;

    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    memset(payload, 0, sizeof(payload));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    alarm(5);
    count = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
    alarm(0);
    if (count != 17 || memcmp(payload, "filesystem broker", 17) != 0)
        return -1;
    header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len < CMSG_LEN(sizeof(descriptor))) {
        errno = EBADMSG;
        return -1;
    }
    memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
    if (read(descriptor, &byte, 1) != 1 || byte != 'D') {
        close(descriptor);
        errno = EIO;
        return -1;
    }
    close(descriptor);
    return 0;
}

int main(void) {
    struct holder holders[HOLDER_COUNT];
    int sockets[2] = {-1, -1};
    int data_pipe[2] = {-1, -1};
    int ready_pipe[2] = {-1, -1};
    pid_t receiver = -1;
    int status = 0;
    char byte;

    memset(holders, 0, sizeof(holders));
    for (int index = 0; index < HOLDER_COUNT; ++index) {
        holders[index].process_id = -1;
        holders[index].ready_read = -1;
        holders[index].stop_write = -1;
        if (start_holder(&holders[index]) < 0) {
            stop_holders(holders);
            return fail("start holder");
        }
        if (read(holders[index].ready_read, &byte, 1) != 1) {
            stop_holders(holders);
            errno = EIO;
            return fail("wait for holder");
        }
    }

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) < 0 ||
        pipe(data_pipe) < 0 || pipe(ready_pipe) < 0) {
        stop_holders(holders);
        return fail("create test descriptors");
    }
    if (write(data_pipe[1], "D", 1) != 1) {
        stop_holders(holders);
        return fail("prime passed descriptor");
    }

    receiver = fork();
    if (receiver < 0) {
        stop_holders(holders);
        return fail("fork receiver");
    }
    if (receiver == 0) {
        int result;

        close(sockets[0]);
        close(data_pipe[0]);
        close(data_pipe[1]);
        close(ready_pipe[0]);
        if (write(ready_pipe[1], "W", 1) != 1)
            _exit(92);
        close(ready_pipe[1]);
        result = receive_and_check(sockets[1]);
        _exit(result == 0 ? 0 : 93);
    }

    close(sockets[1]);
    close(ready_pipe[1]);
    if (read(ready_pipe[0], &byte, 1) != 1) {
        stop_holders(holders);
        return fail("wait for blocked receiver");
    }
    {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000};
        nanosleep(&delay, NULL);
    }
    if (send_descriptor(sockets[0], data_pipe[0]) < 0) {
        kill(receiver, SIGKILL);
        stop_holders(holders);
        return fail("send rights-bearing message");
    }
    if (waitpid(receiver, &status, 0) != receiver ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        stop_holders(holders);
        errno = EPROTO;
        return fail("blocked receiver wakeup");
    }

    close(sockets[0]);
    close(data_pipe[0]);
    close(data_pipe[1]);
    close(ready_pipe[0]);
    stop_holders(holders);
    puts("socket_high_index_rights_wake_probe: PASS");
    return 0;
}
