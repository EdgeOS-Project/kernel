/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux open-description lifetime and SCM_RIGHTS regression probe.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

static void expect(int condition, const char *name) {
    printf("%s %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) ++failures;
}

static int send_descriptor(int socket_descriptor, int descriptor) {
    char byte = 'F';
    struct iovec vector = {
        .iov_base = &byte,
        .iov_len = sizeof(byte),
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
    return sendmsg(socket_descriptor, &message, 0);
}

static int receive_descriptor(int socket_descriptor, int flags) {
    char byte;
    struct iovec vector = {
        .iov_base = &byte,
        .iov_len = sizeof(byte),
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
    if (recvmsg(socket_descriptor, &message, flags) != 1)
        return -1;
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

static int send_empty_descriptor(int socket_descriptor, int descriptor) {
    char control[CMSG_SPACE(sizeof(descriptor))];
    struct msghdr message;
    struct cmsghdr *header;

    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(descriptor));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
    return sendmsg(socket_descriptor, &message, 0);
}

static int receive_empty_descriptor(int socket_descriptor) {
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr message;
    struct cmsghdr *header;
    int descriptor = -1;

    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    if (recvmsg(socket_descriptor, &message, 0) != 0)
        return -1;
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

int main(void) {
    struct epoll_event event;
    struct epoll_event observed;
    int sockets[2] = {-1, -1};
    int pipe_descriptors[2] = {-1, -1};
    int epoll_descriptor = -1;
    int received = -1;
    int received_cloexec = -1;
    int received_empty = -1;
    int status_flags;
    char byte = 'R';
    char result = 0;

    if (socketpair(
            AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets) < 0 ||
        pipe2(pipe_descriptors, O_CLOEXEC) < 0) {
        perror("open_description_scm_abi_probe setup");
        return 1;
    }
    epoll_descriptor = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_descriptor < 0) {
        perror("epoll_create1");
        return 1;
    }
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.u64 = UINT64_C(0x454447454f4644);
    expect(epoll_ctl(
               epoll_descriptor, EPOLL_CTL_ADD,
               pipe_descriptors[0], &event) == 0,
           "epoll add shared description");

    expect(send_descriptor(sockets[0], pipe_descriptors[0]) == 1,
           "queue SCM_RIGHTS description");
    status_flags = fcntl(pipe_descriptors[0], F_GETFL);
    expect(status_flags >= 0 &&
               fcntl(pipe_descriptors[0], F_SETFL,
                     status_flags | O_NONBLOCK) == 0,
           "change shared status while queued");
    close(pipe_descriptors[0]);
    pipe_descriptors[0] = -1;

    expect(write(pipe_descriptors[1], &byte, sizeof(byte)) == 1,
           "make queued description readable");
    memset(&observed, 0, sizeof(observed));
    expect(epoll_wait(epoll_descriptor, &observed, 1, 1000) == 1 &&
               observed.data.u64 == event.data.u64 &&
               (observed.events & EPOLLIN),
           "epoll observes SCM-only description");

    received = receive_descriptor(sockets[1], 0);
    expect(received >= 0, "receive SCM_RIGHTS without CLOEXEC");
    if (received >= 0) {
        expect((fcntl(received, F_GETFD) & FD_CLOEXEC) == 0,
               "SCM_RIGHTS clears sender CLOEXEC");
        status_flags = fcntl(received, F_GETFL);
        expect(status_flags >= 0 && (status_flags & O_NONBLOCK),
               "SCM_RIGHTS preserves shared status updates");
        expect(read(received, &result, sizeof(result)) == 1 &&
                   result == byte,
               "SCM_RIGHTS preserves readable backing object");
        expect(fcntl(received, F_SETFD, FD_CLOEXEC) == 0,
               "set sender descriptor CLOEXEC");
        expect(send_descriptor(sockets[0], received) == 1,
               "queue second SCM_RIGHTS description");
        received_cloexec =
            receive_descriptor(sockets[1], MSG_CMSG_CLOEXEC);
        expect(received_cloexec >= 0 &&
                   (fcntl(received_cloexec, F_GETFD) &
                    FD_CLOEXEC) != 0,
               "MSG_CMSG_CLOEXEC sets receiver flag");
        expect(send_empty_descriptor(sockets[0], received) == 0,
               "queue zero-payload SCM_RIGHTS datagram");
        received_empty = receive_empty_descriptor(sockets[1]);
        expect(received_empty >= 0,
               "zero-payload datagram delivers SCM_RIGHTS");
    }

    if (received_empty >= 0) close(received_empty);
    if (received_cloexec >= 0) close(received_cloexec);
    if (received >= 0) close(received);
    if (pipe_descriptors[0] >= 0) close(pipe_descriptors[0]);
    if (pipe_descriptors[1] >= 0) close(pipe_descriptors[1]);
    if (epoll_descriptor >= 0) close(epoll_descriptor);
    close(sockets[0]);
    close(sockets[1]);
    printf("OPEN_DESCRIPTION_SCM_ABI_%s failures=%d\n",
           failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
