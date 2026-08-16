/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Validate Linux AF_UNIX stream association between payload bytes and
 * SCM_RIGHTS records while two processes concurrently read one socket.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MESSAGE_COUNT 512
#define RECEIVER_COUNT 2

static int send_descriptor(int socket_fd, int descriptor) {
    char payload = 'R';
    struct iovec vector = {
        .iov_base = &payload,
        .iov_len = sizeof(payload),
    };
    char control[CMSG_SPACE(sizeof(descriptor))];
    struct msghdr message;
    struct cmsghdr *header;
    ssize_t result;

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

    do {
        result = sendmsg(socket_fd, &message, 0);
    } while (result < 0 && errno == EINTR);
    return result == 1 ? 0 : -1;
}

static int receive_messages(int socket_fd, int acknowledgement_fd) {
    for (;;) {
        char payload = 0;
        struct iovec vector = {
            .iov_base = &payload,
            .iov_len = sizeof(payload),
        };
        char control[CMSG_SPACE(sizeof(int))];
        struct msghdr message;
        struct cmsghdr *header;
        int received_descriptor = -1;
        int descriptor_count = 0;
        ssize_t result;

        memset(&message, 0, sizeof(message));
        memset(control, 0, sizeof(control));
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        do {
            result = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
        } while (result < 0 && errno == EINTR);
        if (result == 0) return 0;
        if (result != 1 || payload != 'R' ||
            (message.msg_flags & MSG_CTRUNC))
            return 10;

        for (header = CMSG_FIRSTHDR(&message); header;
             header = CMSG_NXTHDR(&message, header)) {
            if (header->cmsg_level == SOL_SOCKET &&
                header->cmsg_type == SCM_RIGHTS &&
                header->cmsg_len >= CMSG_LEN(sizeof(int))) {
                memcpy(&received_descriptor, CMSG_DATA(header),
                       sizeof(received_descriptor));
                ++descriptor_count;
            }
        }
        if (descriptor_count != 1 || received_descriptor < 0)
            return 11;
        if ((fcntl(received_descriptor, F_GETFD) & FD_CLOEXEC) == 0) {
            close(received_descriptor);
            return 12;
        }
        close(received_descriptor);
        if (write(acknowledgement_fd, "A", 1) != 1)
            return 13;
    }
}

int main(void) {
    int sockets[2];
    int acknowledgements[2];
    int passed_descriptor;
    pid_t receivers[RECEIVER_COUNT];
    int acknowledged = 0;
    int failures = 0;
    char buffer[64];

    alarm(30);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0 ||
        pipe2(acknowledgements, O_CLOEXEC) < 0) {
        perror("socket_scm_rights_concurrency_abi_test: setup");
        return 1;
    }
    passed_descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (passed_descriptor < 0) {
        perror("socket_scm_rights_concurrency_abi_test: open");
        return 1;
    }

    for (int index = 0; index < RECEIVER_COUNT; ++index) {
        receivers[index] = fork();
        if (receivers[index] < 0) {
            perror("socket_scm_rights_concurrency_abi_test: fork");
            return 1;
        }
        if (receivers[index] == 0) {
            int result;
            close(sockets[0]);
            close(acknowledgements[0]);
            close(passed_descriptor);
            result = receive_messages(sockets[1], acknowledgements[1]);
            close(sockets[1]);
            close(acknowledgements[1]);
            _exit(result);
        }
    }

    close(sockets[1]);
    close(acknowledgements[1]);
    for (int index = 0; index < MESSAGE_COUNT; ++index) {
        if (send_descriptor(sockets[0], passed_descriptor) < 0) {
            perror("socket_scm_rights_concurrency_abi_test: sendmsg");
            failures = 1;
            break;
        }
    }
    close(passed_descriptor);
    shutdown(sockets[0], SHUT_WR);
    close(sockets[0]);

    for (;;) {
        ssize_t count = read(acknowledgements[0], buffer, sizeof(buffer));
        if (count > 0) {
            acknowledged += (int)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            perror("socket_scm_rights_concurrency_abi_test: read");
            failures = 1;
        }
        break;
    }
    close(acknowledgements[0]);

    for (int index = 0; index < RECEIVER_COUNT; ++index) {
        int status;
        if (waitpid(receivers[index], &status, 0) != receivers[index] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr,
                    "socket_scm_rights_concurrency_abi_test: receiver %d failed\n",
                    index);
            failures = 1;
        }
    }
    if (acknowledged != MESSAGE_COUNT) {
        fprintf(stderr,
                "socket_scm_rights_concurrency_abi_test: acknowledged %d of %d\n",
                acknowledged, MESSAGE_COUNT);
        failures = 1;
    }
    if (failures) return 1;
    puts("socket_scm_rights_concurrency_abi_test: PASS");
    return 0;
}
