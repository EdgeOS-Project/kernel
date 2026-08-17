/*
 * Original EdgeOS regression probe.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Validate Linux IP socket options commonly used by musl, BIND, and curl, then
 * exercise the nonblocking TCP connect sequence used by HTTP clients.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#ifndef IP_RECVERR
#define IP_RECVERR 11
#endif
#ifndef IP_PKTINFO
#define IP_PKTINFO 8
#endif
#ifndef IP_RECVTTL
#define IP_RECVTTL 12
#endif
#ifndef IP_TOS
#define IP_TOS 1
#endif

static long ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int probe_sockopts(void) {
    static const struct {
        int opt;
        int val;
        const char *name;
    } opts[] = {
        { IP_RECVERR, 1, "IP_RECVERR" },
        { IP_PKTINFO, 1, "IP_PKTINFO" },
        { IP_RECVTTL, 1, "IP_RECVTTL" },
        { IP_TOS, 0x10, "IP_TOS" },
    };
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned char multicast_ttl = 7;
    if (fd < 0) {
        printf("SOCKOPT_SOCKET_FAIL errno=%d %s\n", errno, strerror(errno));
        return 1;
    }
    for (unsigned i = 0; i < sizeof(opts) / sizeof(opts[0]); ++i) {
        int rc;
        errno = 0;
        rc = setsockopt(fd, IPPROTO_IP, opts[i].opt, &opts[i].val, sizeof(opts[i].val));
        printf("SOCKOPT %s opt=%d rc=%d errno=%d %s\n",
               opts[i].name, opts[i].opt, rc, errno, strerror(errno));
        if (rc != 0) {
            close(fd);
            return 1;
        }
    }
    errno = 0;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL,
                   &multicast_ttl, sizeof(multicast_ttl)) != 0) {
        printf("SOCKOPT IP_MULTICAST_TTL_BYTE errno=%d %s\n",
               errno, strerror(errno));
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

static int probe_ipv6_multicast_hops(void) {
    int hops = 9;
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("IPV6_SOCKET_FAIL errno=%d %s\n", errno, strerror(errno));
        return 1;
    }
    errno = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                   &hops, sizeof(hops)) != 0) {
        printf("SOCKOPT IPV6_MULTICAST_HOPS errno=%d %s\n",
               errno, strerror(errno));
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

static int make_addr(struct sockaddr_in *sin) {
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(80);
    return inet_pton(AF_INET, "34.117.59.81", &sin->sin_addr) == 1 ? 0 : -1;
}

static int probe_nonblocking_connect(void) {
    struct sockaddr_in sin;
    struct pollfd pfd;
    int fd;
    int rc;
    int soerr = -1;
    socklen_t sl = sizeof(soerr);
    long start;

    if (make_addr(&sin) < 0) return 1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        close(fd);
        return 1;
    }

    start = ms_now();
    errno = 0;
    rc = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
    printf("NONBLOCK_CONNECT rc=%d errno=%d %s elapsed=%ld\n",
           rc, errno, strerror(errno), ms_now() - start);
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return 1;
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT | POLLERR | POLLHUP;
    errno = 0;
    rc = poll(&pfd, 1, 8000);
    printf("NONBLOCK_POLL rc=%d revents=0x%x errno=%d %s elapsed=%ld\n",
           rc, pfd.revents, errno, strerror(errno), ms_now() - start);
    if (rc <= 0) {
        close(fd);
        return 1;
    }
    errno = 0;
    rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
    printf("NONBLOCK_SO_ERROR rc=%d soerr=%d errno=%d %s elapsed=%ld\n",
           rc, soerr, errno, strerror(errno), ms_now() - start);
    close(fd);
    return (rc == 0 && soerr == 0) ? 0 : 1;
}

static int probe_select_connect(int use_pselect) {
    struct sockaddr_in sin;
    fd_set wfds;
    int fd;
    int rc;
    int soerr = -1;
    socklen_t sl = sizeof(soerr);
    long start;

    if (make_addr(&sin) < 0) return 1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        close(fd);
        return 1;
    }

    start = ms_now();
    errno = 0;
    rc = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
    printf("%s_CONNECT rc=%d errno=%d %s elapsed=%ld\n",
           use_pselect ? "PSELECT" : "SELECT", rc, errno, strerror(errno), ms_now() - start);
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return 1;
    }

    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    errno = 0;
    if (use_pselect) {
        struct timespec ts;
        ts.tv_sec = 8;
        ts.tv_nsec = 0;
        rc = pselect(fd + 1, NULL, &wfds, NULL, &ts, NULL);
    } else {
        struct timeval tv;
        tv.tv_sec = 8;
        tv.tv_usec = 0;
        rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    }
    printf("%s_WAIT rc=%d isset=%d errno=%d %s elapsed=%ld\n",
           use_pselect ? "PSELECT" : "SELECT", rc, FD_ISSET(fd, &wfds),
           errno, strerror(errno), ms_now() - start);
    if (rc <= 0 || !FD_ISSET(fd, &wfds)) {
        close(fd);
        return 1;
    }
    errno = 0;
    rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
    printf("%s_SO_ERROR rc=%d soerr=%d errno=%d %s elapsed=%ld\n",
           use_pselect ? "PSELECT" : "SELECT", rc, soerr, errno, strerror(errno), ms_now() - start);
    close(fd);
    return (rc == 0 && soerr == 0) ? 0 : 1;
}

static int probe_tcp_keepalive_opts(void) {
    static const struct {
        int opt;
        int val;
        const char *name;
    } opts[] = {
        { TCP_KEEPIDLE, 60, "TCP_KEEPIDLE" },
        { TCP_KEEPINTVL, 30, "TCP_KEEPINTVL" },
        { TCP_KEEPCNT, 3, "TCP_KEEPCNT" },
    };
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    for (unsigned i = 0; i < sizeof(opts) / sizeof(opts[0]); ++i) {
        int rc;
        errno = 0;
        rc = setsockopt(fd, IPPROTO_TCP, opts[i].opt, &opts[i].val, sizeof(opts[i].val));
        printf("TCP_SOCKOPT %s opt=%d rc=%d errno=%d %s\n",
               opts[i].name, opts[i].opt, rc, errno, strerror(errno));
        if (rc != 0) {
            close(fd);
            return 1;
        }
    }
    close(fd);
    return 0;
}

int main(void) {
    int failed = 0;
    failed |= probe_sockopts();
    failed |= probe_ipv6_multicast_hops();
    failed |= probe_tcp_keepalive_opts();
    failed |= probe_nonblocking_connect();
    failed |= probe_select_connect(0);
    failed |= probe_select_connect(1);
    printf("SOCKET_IP_SOCKOPTS_PROBE_%s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
