/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS pidfd SCM_RIGHTS Linux ABI regression test.
 * Copyright (c) EdgeOS Contributors.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

static int fail(const char *operation) {
    fprintf(stderr, "pidfd_scm_rights_abi_probe: %s: %s\n",
            operation, strerror(errno));
    return 1;
}

static int send_descriptor(int socket_fd, int descriptor) {
    char payload = 'P';
    struct iovec vector = {
        .iov_base = &payload,
        .iov_len = sizeof(payload),
    };
    char control[CMSG_SPACE(sizeof(descriptor))];
    struct msghdr message;
    struct cmsghdr *header;

    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(descriptor));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));

    if (sendmsg(socket_fd, &message, 0) != (ssize_t)sizeof(payload))
        return -1;
    return 0;
}

static int receive_descriptor(int socket_fd) {
    char payload = 0;
    struct iovec vector = {
        .iov_base = &payload,
        .iov_len = sizeof(payload),
    };
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr message;
    struct cmsghdr *header;
    int descriptor = -1;

    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    if (recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC) !=
        (ssize_t)sizeof(payload))
        return -1;
    if (payload != 'P' || (message.msg_flags & MSG_CTRUNC)) {
        errno = EPROTO;
        return -1;
    }
    header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len < CMSG_LEN(sizeof(descriptor))) {
        errno = EBADMSG;
        return -1;
    }
    memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
    return descriptor;
}

static int fdinfo_has_pid(int descriptor, pid_t expected) {
    char path[64];
    char text[1024];
    char expected_line[64];
    int fd;
    ssize_t count;

    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", descriptor);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    count = read(fd, text, sizeof(text) - 1u);
    close(fd);
    if (count < 0) return -1;
    text[count] = '\0';
    snprintf(expected_line, sizeof(expected_line), "Pid:\t%d\n", expected);
    if (!strstr(text, expected_line)) {
        fprintf(stderr, "pidfd_scm_rights_abi_probe: fdinfo was:\n%s", text);
        errno = ENOTTY;
        return -1;
    }
    snprintf(expected_line, sizeof(expected_line), "NSpid:\t%d\n", expected);
    if (!strstr(text, expected_line)) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int main(void) {
    int sockets[2];
    int received;
    pid_t child;
    struct pollfd watched;
    int status;
    char acknowledgement = 'A';

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0)
        return fail("socketpair");
    child = fork();
    if (child < 0) return fail("fork");
    if (child == 0) {
        int pidfd;
        char byte;

        close(sockets[0]);
        pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
        if (pidfd < 0 || send_descriptor(sockets[1], pidfd) < 0)
            _exit(100 + (errno & 63));
        close(pidfd);
        if (read(sockets[1], &byte, sizeof(byte)) != (ssize_t)sizeof(byte) ||
            byte != acknowledgement)
            _exit(90);
        _exit(0);
    }

    close(sockets[1]);
    received = receive_descriptor(sockets[0]);
    if (received < 0) return fail("receive pidfd");
    if ((fcntl(received, F_GETFD) & FD_CLOEXEC) == 0) {
        errno = EINVAL;
        return fail("MSG_CMSG_CLOEXEC");
    }
    if (fdinfo_has_pid(received, child) < 0)
        return fail("pidfd fdinfo identity");

    watched.fd = received;
    watched.events = POLLIN;
    watched.revents = 0;
    if (poll(&watched, 1, 0) != 0) {
        errno = EBUSY;
        return fail("live pidfd readiness");
    }
    if (write(sockets[0], &acknowledgement, sizeof(acknowledgement)) !=
        (ssize_t)sizeof(acknowledgement))
        return fail("child acknowledgement");
    if (waitpid(child, &status, 0) != child)
        return fail("waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = ECHILD;
        return fail("child status");
    }
    watched.revents = 0;
    if (poll(&watched, 1, 1000) != 1 ||
        !(watched.revents & (POLLIN | POLLHUP))) {
        errno = ETIMEDOUT;
        return fail("exited pidfd readiness");
    }

    close(received);
    close(sockets[0]);
    puts("pidfd_scm_rights_abi_probe: PASS");
    return 0;
}
