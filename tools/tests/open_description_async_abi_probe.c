/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t g_signal_count;
static int g_failures;

static void signal_handler(int signal_number) {
    if (signal_number == SIGUSR1) ++g_signal_count;
}

static void expect(int condition, const char *name) {
    printf("%s %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) ++g_failures;
}

static int send_descriptor(int socket_descriptor, int descriptor) {
    char payload = 'A';
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
    return sendmsg(socket_descriptor, &message, 0);
}

static int receive_descriptor(int socket_descriptor) {
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
    if (recvmsg(socket_descriptor, &message, 0) != 1 ||
        payload != 'A')
        return -1;
    header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len < CMSG_LEN(sizeof(descriptor)))
        return -1;
    memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
    return descriptor;
}

static void wait_for_signal(void) {
    for (uint32_t attempt = 0;
         attempt < 1000u && !g_signal_count; ++attempt)
        usleep(1000);
}

int main(void) {
    struct sigaction action;
    int pipes[2] = { -1, -1 };
    int sockets[2] = { -1, -1 };
    int duplicate = -1;
    int received = -1;
    int enabled;
    int flags;
    char byte = 'S';

    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    expect(sigaction(SIGUSR1, &action, 0) == 0,
           "install async signal handler");
    if (pipe2(pipes, O_CLOEXEC | O_NONBLOCK) < 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
                   0, sockets) < 0) {
        perror("open_description_async_abi_probe setup");
        return 2;
    }
    duplicate = dup(pipes[0]);
    expect(duplicate >= 0, "duplicate async description");
    if (duplicate < 0) return 2;

    expect(fcntl(pipes[0], F_SETOWN, getpid()) == 0,
           "set async owner");
    expect(fcntl(duplicate, F_GETOWN) == getpid(),
           "dup shares async owner");
    expect(fcntl(duplicate, F_SETSIG, SIGUSR1) == 0,
           "set custom async signal");
    expect(fcntl(pipes[0], F_GETSIG) == SIGUSR1,
           "dup shares custom async signal");

    flags = fcntl(pipes[0], F_GETFL);
    expect(flags >= 0 &&
               fcntl(duplicate, F_SETFL, flags | O_ASYNC) == 0,
           "enable O_ASYNC through duplicate");
    expect((fcntl(pipes[0], F_GETFL) & O_ASYNC) != 0,
           "O_ASYNC is shared description state");
    g_signal_count = 0;
    expect(write(pipes[1], &byte, sizeof(byte)) == 1,
           "publish async readiness");
    wait_for_signal();
    expect(g_signal_count > 0,
           "shared description delivers configured signal");
    (void)read(pipes[0], &byte, sizeof(byte));

    expect(send_descriptor(sockets[0], pipes[0]) == 1,
           "queue async description through SCM_RIGHTS");
    close(duplicate);
    duplicate = -1;
    close(pipes[0]);
    pipes[0] = -1;
    received = receive_descriptor(sockets[1]);
    expect(received >= 0,
           "receive async description through SCM_RIGHTS");
    if (received >= 0) {
        expect(fcntl(received, F_GETOWN) == getpid(),
               "SCM_RIGHTS preserves async owner");
        expect(fcntl(received, F_GETSIG) == SIGUSR1,
               "SCM_RIGHTS preserves async signal");
        expect((fcntl(received, F_GETFL) & O_ASYNC) != 0,
               "SCM_RIGHTS preserves O_ASYNC");
        errno = 0;
        expect(fcntl(received, F_SETSIG, 65) == -1 &&
                   errno == EINVAL,
               "reject invalid async signal");

        expect(fcntl(received, F_SETOWN, -getpgrp()) == 0 &&
                   fcntl(received, F_GETOWN) == -getpgrp(),
               "share process-group async owner");
        expect(fcntl(received, F_SETOWN, 0) == 0,
               "clear async owner");
        enabled = 0;
        expect(ioctl(received, FIOASYNC, &enabled) == 0,
               "disable async through FIOASYNC");
        enabled = 1;
        expect(ioctl(received, FIOASYNC, &enabled) == 0,
               "enable async through FIOASYNC");
        expect(fcntl(received, F_GETOWN) == 0,
               "FIOASYNC does not invent an owner");
    }

    if (received >= 0) close(received);
    if (duplicate >= 0) close(duplicate);
    if (pipes[0] >= 0) close(pipes[0]);
    if (pipes[1] >= 0) close(pipes[1]);
    close(sockets[0]);
    close(sockets[1]);
    printf("OPEN_DESCRIPTION_ASYNC_ABI_%s failures=%d\n",
           g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
