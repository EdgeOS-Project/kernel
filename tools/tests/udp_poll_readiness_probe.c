/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Regression probe for AF_INET UDP poll/read queue agreement.
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *operation) {
    fprintf(stderr, "%s: %s\n", operation, strerror(errno));
    exit(1);
}

int main(void) {
    static const uint8_t request[] = {0x45, 0x64, 0x67, 0x65};
    static const uint8_t response[] = {0x4f, 0x53, 0x2d, 0x4f, 0x4b};
    struct sockaddr_in address;
    socklen_t address_length = sizeof(address);
    struct pollfd descriptor;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
    uint8_t buffer[32];
    pid_t child;
    int server;
    int client;
    int status;
    ssize_t length;

    server = socket(AF_INET, SOCK_DGRAM, 0);
    if (server < 0) fail("socket(server)");
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1)
        fail("inet_pton");
    address.sin_port = 0;
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0)
        fail("bind");
    if (getsockname(server, (struct sockaddr *)&address, &address_length) < 0)
        fail("getsockname");

    client = socket(AF_INET, SOCK_DGRAM, 0);
    if (client < 0) fail("socket(client)");
    if (fcntl(client, F_SETFL, fcntl(client, F_GETFL, 0) | O_NONBLOCK) < 0)
        fail("fcntl");
    if (connect(client, (struct sockaddr *)&address, address_length) < 0)
        fail("connect");

    child = fork();
    if (child < 0) fail("fork");
    if (child == 0) {
        struct sockaddr_in peer;
        socklen_t peer_length = sizeof(peer);

        close(client);
        length = recvfrom(server, buffer, sizeof(buffer), 0,
                          (struct sockaddr *)&peer, &peer_length);
        if (length != (ssize_t)sizeof(request) ||
            memcmp(buffer, request, sizeof(request)) != 0)
            _exit(2);
        if (nanosleep(&delay, 0) < 0) _exit(3);
        length = sendto(server, response, sizeof(response), 0,
                        (struct sockaddr *)&peer, peer_length);
        _exit(length == (ssize_t)sizeof(response) ? 0 : 4);
    }

    close(server);
    length = send(client, request, sizeof(request), 0);
    if (length != (ssize_t)sizeof(request)) fail("send");

    descriptor.fd = client;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    status = poll(&descriptor, 1, 2000);
    if (status != 1 || (descriptor.revents & POLLIN) == 0) {
        fprintf(stderr, "poll: status=%d revents=0x%x\n",
                status, descriptor.revents);
        return 5;
    }

    length = recv(client, buffer, sizeof(buffer), MSG_PEEK);
    if (length != (ssize_t)sizeof(response) ||
        memcmp(buffer, response, sizeof(response)) != 0) {
        fprintf(stderr, "peek: length=%zd errno=%d\n", length, errno);
        return 6;
    }
    length = recv(client, buffer, sizeof(buffer), 0);
    if (length != (ssize_t)sizeof(response) ||
        memcmp(buffer, response, sizeof(response)) != 0) {
        fprintf(stderr, "recv: length=%zd errno=%d\n", length, errno);
        return 7;
    }

    descriptor.revents = 0;
    status = poll(&descriptor, 1, 0);
    if (status != 0 || descriptor.revents != 0) {
        fprintf(stderr, "poll-after-drain: status=%d revents=0x%x\n",
                status, descriptor.revents);
        return 8;
    }
    if (waitpid(child, &status, 0) != child) fail("waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "server: status=0x%x\n", status);
        return 9;
    }

    close(client);
    puts("udp_poll_readiness_probe: PASS");
    return 0;
}
