/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

static int expect_event(int ep, uint32_t want, uint32_t forbid, const char *tag) {
    struct epoll_event ev;
    int n;

    memset(&ev, 0, sizeof(ev));
    n = epoll_wait(ep, &ev, 1, 1000);
    printf("%s_wait:%d errno:%d events:0x%x\n", tag, n, errno, n > 0 ? ev.events : 0);
    if (n != 1) return 1;
    if ((ev.events & want) != want) return 1;
    if (ev.events & forbid) return 1;
    return 0;
}

static int test_zero_length_datagram_edges(void) {
    int sv[2];
    int ep;
    struct epoll_event ev;
    char byte;
    int failed = 0;

    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                   0, sv) < 0) {
        printf("dgram_socketpair_errno:%d\n", errno);
        return 1;
    }
    ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) {
        printf("dgram_epoll_create_errno:%d\n", errno);
        close(sv[0]);
        close(sv[1]);
        return 1;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, sv[1], &ev) < 0) {
        printf("dgram_epoll_ctl_errno:%d\n", errno);
        failed = 1;
        goto done;
    }
    if (send(sv[0], "", 0, 0) != 0) {
        printf("dgram_zero_send_first_errno:%d\n", errno);
        failed = 1;
        goto done;
    }
    failed |= expect_event(ep, EPOLLIN, 0, "dgram_zero_first");
    if (epoll_wait(ep, &ev, 1, 0) != 0) {
        printf("dgram_zero_repeated_without_edge events:0x%x\n",
               ev.events);
        failed = 1;
    }
    if (send(sv[0], "", 0, 0) != 0) {
        printf("dgram_zero_send_second_errno:%d\n", errno);
        failed = 1;
        goto done;
    }
    failed |= expect_event(ep, EPOLLIN, 0, "dgram_zero_second");
    if (recv(sv[1], &byte, sizeof(byte), 0) != 0 ||
        recv(sv[1], &byte, sizeof(byte), 0) != 0) {
        printf("dgram_zero_receive_errno:%d\n", errno);
        failed = 1;
    }
    errno = 0;
    if (recv(sv[1], &byte, sizeof(byte), 0) >= 0 ||
        (errno != EAGAIN && errno != EWOULDBLOCK)) {
        printf("dgram_zero_queue_not_empty errno:%d\n", errno);
        failed = 1;
    }

done:
    close(ep);
    close(sv[0]);
    close(sv[1]);
    return failed;
}

static int test_stream_write_space_edge(void) {
    uint8_t buffer[4096];
    int sv[2];
    int ep;
    struct epoll_event ev;
    int filled = 0;
    int failed = 0;

    memset(buffer, 0xa5, sizeof(buffer));
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                   0, sv) < 0) {
        printf("write_space_socketpair_errno:%d\n", errno);
        return 1;
    }
    ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) {
        printf("write_space_epoll_create_errno:%d\n", errno);
        close(sv[0]);
        close(sv[1]);
        return 1;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLOUT | EPOLLET;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &ev) < 0) {
        printf("write_space_epoll_ctl_errno:%d\n", errno);
        failed = 1;
        goto done;
    }
    failed |= expect_event(ep, EPOLLOUT, 0, "write_space_initial");
    while (filled < 8 * 1024 * 1024) {
        ssize_t sent = send(sv[0], buffer, sizeof(buffer), 0);
        if (sent > 0) {
            filled += (int)sent;
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        printf("write_space_fill_errno:%d\n", errno);
        failed = 1;
        goto done;
    }
    if (filled >= 8 * 1024 * 1024) {
        printf("write_space_did_not_block filled:%d\n", filled);
        failed = 1;
        goto done;
    }
    if (epoll_wait(ep, &ev, 1, 0) != 0) {
        printf("write_space_still_writable events:0x%x\n", ev.events);
        failed = 1;
    }
    if (recv(sv[1], buffer, sizeof(buffer), 0) <= 0) {
        printf("write_space_drain_errno:%d\n", errno);
        failed = 1;
        goto done;
    }
    failed |= expect_event(ep, EPOLLOUT, 0, "write_space_rearmed");

done:
    close(ep);
    close(sv[0]);
    close(sv[1]);
    return failed;
}

int main(void) {
    int sv[2];
    int ep;
    struct epoll_event ev;
    char c = 'x';
    int failed = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) < 0) {
        printf("socketpair_errno:%d\n", errno);
        return 1;
    }

    ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) {
        printf("epoll_create_errno:%d\n", errno);
        return 1;
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLET | EPOLLRDNORM;
    ev.data.u64 = 0x1234;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, sv[1], &ev) < 0) {
        printf("epoll_ctl_read_errno:%d\n", errno);
        return 1;
    }
    if (write(sv[0], &c, 1) != 1) {
        printf("write_read_edge_errno:%d\n", errno);
        return 1;
    }
    failed |= expect_event(ep, EPOLLRDNORM, EPOLLIN, "rdnorm");
    if (epoll_wait(ep, &ev, 1, 0) != 0) {
        printf("rdnorm_repeated_without_edge events:0x%x\n", ev.events);
        failed = 1;
    }
    if (write(sv[0], &c, 1) != 1) {
        printf("write_second_edge_errno:%d\n", errno);
        return 1;
    }
    failed |= expect_event(ep, EPOLLRDNORM, EPOLLIN, "rdnorm_second");

    if (epoll_ctl(ep, EPOLL_CTL_DEL, sv[1], NULL) < 0) {
        printf("epoll_ctl_del_errno:%d\n", errno);
        return 1;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLET | EPOLLWRNORM;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &ev) < 0) {
        printf("epoll_ctl_write_errno:%d\n", errno);
        return 1;
    }
    failed |= expect_event(ep, EPOLLWRNORM, EPOLLOUT, "wrnorm");

    failed |= test_zero_length_datagram_edges();
    failed |= test_stream_write_space_edge();

    printf("epoll_unix_ready_mask:%s\n", failed ? "FAIL" : "OK");
    return failed ? 1 : 0;
}
