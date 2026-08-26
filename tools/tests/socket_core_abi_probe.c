/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding raw Linux socket-core ABI probe.  It validates socket and
 * socketpair argument policy, descriptor flags, listen errors, shutdown
 * ordering, and AF_UNIX stream half-close behavior without libc wrappers.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_socket 41
#define SYS_sendto 44
#define SYS_listen 50
#define SYS_shutdown 48
#define SYS_socketpair 53
#define SYS_getsockopt 55
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_fcntl 72
#define SYS_ppoll 271
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_ppoll 73
#define SYS_read 63
#define SYS_write 64
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_sendto 206
#define SYS_listen 201
#define SYS_getsockopt 209
#define SYS_shutdown 210
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit 93
#else
#error "socket_core_abi_probe requires a Linux 64-bit architecture"
#endif

#define EAGAIN 11
#define EBADF 9
#define EFAULT 14
#define EINVAL 22
#define ENOTSOCK 88
#define EPROTONOSUPPORT 93
#define ESOCKTNOSUPPORT 94
#define EOPNOTSUPP 95
#define EAFNOSUPPORT 97
#define EPIPE 32
#define ENOTCONN 107
#define ECONNREFUSED 111

#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_SEQPACKET 5
#define SOCK_NONBLOCK 0x800
#define SOCK_CLOEXEC 0x80000

#define F_GETFD 1
#define F_SETFL 4
#define F_GETFL 3
#define FD_CLOEXEC 1
#define O_NONBLOCK 0x800

#define SOL_SOCKET 1
#define SO_TYPE 3
#define SO_PROTOCOL 38

#define IPPROTO_RAW 255

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

#define MSG_NOSIGNAL 0x4000

#define SIGCHLD 17

#define POLLIN 0x0001
#define POLLOUT 0x0004
#define POLLHUP 0x0010
#define POLLRDHUP 0x2000

struct edge_pollfd {
    int fd;
    int16_t events;
    int16_t revents;
};

struct edge_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

static long raw_syscall6(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4,
                         long argument5) {
    long result;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = argument3;
    register long r8 __asm__("r8") = argument4;
    register long r9 __asm__("r9") = argument5;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    register long x3 __asm__("x3") = argument3;
    register long x4 __asm__("x4") = argument4;
    register long x5 __asm__("x5") = argument5;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, 0, 0);
}

static long raw_syscall5(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4) {
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, argument4, 0);
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
}

static long raw_syscall2(long number, long argument0, long argument1) {
    return raw_syscall6(number, argument0, argument1, 0, 0, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall6(number, argument0, 0, 0, 0, 0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
}

static void putdec(long value) {
    char buffer[24];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        putstr("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    if (!magnitude) {
        putstr("0");
        return;
    }
    while (magnitude && position) {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    }
    (void)raw_syscall3(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned)position));
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": result=");
    putdec(actual);
    putstr(" expected=");
    putdec(expected);
    putstr("\n");
    return 1;
}

static int expect_mask(const char *name, long actual, long mask) {
    if (actual >= 0 && (actual & mask) == mask) return 0;
    putstr(name);
    putstr(": result=");
    putdec(actual);
    putstr(" missing-mask=");
    putdec(mask);
    putstr("\n");
    return 1;
}

static int close_if_open(long descriptor) {
    if (descriptor < 0) return 0;
    return expect_result("close", raw_syscall1(SYS_close, descriptor), 0);
}

static int expect_poll(const char *name, int descriptor, int expected) {
    struct edge_pollfd pollfd;
    struct edge_timespec timeout = {0, 0};
    long result;
    int failures = 0;
    pollfd.fd = descriptor;
    pollfd.events = POLLIN | POLLOUT | POLLRDHUP;
    pollfd.revents = 0;
    result = raw_syscall5(SYS_ppoll, (long)&pollfd, 1, (long)&timeout, 0, 0);
    failures += expect_result(name, result, expected ? 1 : 0);
    failures += expect_result(name, pollfd.revents, expected);
    return failures;
}

static __attribute__((noreturn)) void process_exit(int status) {
    (void)raw_syscall1(SYS_exit, status);
    for (;;) {}
}

static int run_blocked_shutdown_read_probe(int socket_type,
                                           const char *case_name,
                                           long post_shutdown_result) {
    int pair[2] = {-1, -1};
    int ready_pipe[2] = {-1, -1};
    int wait_status = -1;
    struct edge_timespec settle = {0, 50000000};
    char byte = 0;
    long child;
    long result;
    int failures = 0;

    result = raw_syscall4(SYS_socketpair, AF_UNIX, socket_type, 0,
                          (long)pair);
    failures += expect_result("blocked_shutdown_socketpair", result, 0);
    if (result != 0) goto out;
    result = raw_syscall2(SYS_pipe2, (long)ready_pipe, 0);
    failures += expect_result("blocked_shutdown_pipe", result, 0);
    if (result != 0) goto out;

    child = raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (child == 0) {
        (void)raw_syscall1(SYS_close, ready_pipe[0]);
        byte = 'R';
        result = raw_syscall3(SYS_write, ready_pipe[1], (long)&byte, 1);
        if (result != 1) process_exit(101);
        result = raw_syscall3(SYS_read, pair[0], (long)&byte, 1);
        process_exit(result == 0 ? 0 : 102);
    }
    if (child < 0) {
        failures += expect_result("blocked_shutdown_clone", child, 0);
        goto out;
    }

    (void)raw_syscall1(SYS_close, ready_pipe[1]);
    ready_pipe[1] = -1;
    result = raw_syscall3(SYS_read, ready_pipe[0], (long)&byte, 1);
    failures += expect_result("blocked_shutdown_ready", result, 1);
    result = raw_syscall5(SYS_ppoll, 0, 0, (long)&settle, 0, 0);
    failures += expect_result("blocked_shutdown_settle", result, 0);
    result = raw_syscall2(SYS_shutdown, pair[0], SHUT_RD);
    failures += expect_result("blocked_shutdown_call", result, 0);
    result = raw_syscall4(SYS_wait4, child, (long)&wait_status, 0, 0);
    failures += expect_result("blocked_shutdown_wait", result, child);
    failures += expect_result("blocked_shutdown_child_status", wait_status,
                              0);

    result = raw_syscall3(SYS_fcntl, pair[0], F_SETFL, O_NONBLOCK);
    failures += expect_result("blocked_shutdown_nonblock", result, 0);
    result = raw_syscall3(SYS_read, pair[0], (long)&byte, 1);
    failures += expect_result("blocked_shutdown_post_read", result,
                              post_shutdown_result);

out:
    failures += close_if_open(ready_pipe[0]);
    failures += close_if_open(ready_pipe[1]);
    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    if (failures) {
        putstr("blocked_shutdown_case=");
        putstr(case_name);
        putstr("\n");
    }
    return failures;
}

static int run_probe(void) {
    int pair[2] = {-1, -1};
    int pipe_descriptors[2] = {-1, -1};
    int socket_option;
    uint32_t socket_option_length;
    int fill_count;
    char byte = 'S';
    long descriptor;
    long result;
    int failures = 0;

    failures += run_blocked_shutdown_read_probe(
        SOCK_STREAM, "stream", 0);
    failures += run_blocked_shutdown_read_probe(
        SOCK_DGRAM, "dgram", -EAGAIN);
    failures += run_blocked_shutdown_read_probe(
        SOCK_SEQPACKET, "seqpacket", 0);

    result = raw_syscall3(SYS_socket, AF_UNSPEC, SOCK_STREAM, 0);
    failures += expect_result("socket_bad_domain", result, -EAFNOSUPPORT);
    result = raw_syscall3(SYS_socket, AF_UNIX, 0, 0);
    failures += expect_result("socket_bad_type", result, -ESOCKTNOSUPPORT);
    result = raw_syscall3(SYS_socket, AF_UNIX, SOCK_RAW, 0);
    if (result < 0) {
        failures += expect_result("socket_unix_raw", result, 0);
    } else {
        descriptor = result;
        socket_option = -1;
        socket_option_length = sizeof(socket_option);
        result = raw_syscall5(SYS_getsockopt, descriptor, SOL_SOCKET,
                              SO_TYPE, (long)&socket_option,
                              (long)&socket_option_length);
        failures += expect_result("socket_unix_raw_get_type", result, 0);
        failures += expect_result("socket_unix_raw_type", socket_option,
                                  SOCK_DGRAM);
        failures += close_if_open(descriptor);
    }
    result = raw_syscall3(SYS_socket, AF_INET, SOCK_SEQPACKET, 0);
    failures += expect_result("socket_inet_seqpacket", result,
                              -ESOCKTNOSUPPORT);
    result = raw_syscall3(SYS_socket, AF_INET, SOCK_STREAM, 17);
    failures += expect_result("socket_inet_bad_protocol", result,
                              -EPROTONOSUPPORT);
    result = raw_syscall3(SYS_socket, AF_INET, SOCK_RAW, 0);
    failures += expect_result("socket_inet_raw_zero_protocol", result,
                              -EPROTONOSUPPORT);
    result = raw_syscall3(SYS_socket, AF_INET6, SOCK_RAW, 0);
    failures += expect_result("socket_inet6_raw_zero_protocol", result,
                              -EPROTONOSUPPORT);
    result = raw_syscall3(SYS_socket, AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (result < 0) {
        failures += expect_result("socket_inet6_raw_protocol", result, 0);
    } else {
        descriptor = result;
        socket_option = -1;
        socket_option_length = sizeof(socket_option);
        result = raw_syscall5(SYS_getsockopt, descriptor, SOL_SOCKET,
                              SO_PROTOCOL, (long)&socket_option,
                              (long)&socket_option_length);
        failures += expect_result("socket_inet6_raw_get_protocol", result, 0);
        failures += expect_result("socket_inet6_raw_protocol_value",
                                  socket_option, IPPROTO_RAW);
        failures += close_if_open(descriptor);
    }
    result = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM | 0x400000, 0);
    failures += expect_result("socket_bad_flag", result, -EINVAL);
    result = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 1);
    if (result < 0) {
        failures += expect_result("socket_unix_protocol", result, 0);
    } else {
        descriptor = result;
        socket_option = -1;
        socket_option_length = sizeof(socket_option);
        result = raw_syscall5(SYS_getsockopt, descriptor, SOL_SOCKET,
                              SO_PROTOCOL, (long)&socket_option,
                              (long)&socket_option_length);
        failures += expect_result("socket_unix_get_protocol", result, 0);
        failures += expect_result("socket_unix_protocol_value",
                                  socket_option, 0);
        failures += close_if_open(descriptor);
    }

    descriptor = raw_syscall3(SYS_socket, AF_UNIX,
                              SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        failures += expect_result("socket_flags_create", descriptor, 0);
    } else {
        result = raw_syscall3(SYS_fcntl, descriptor, F_GETFD, 0);
        failures += expect_mask("socket_cloexec", result, FD_CLOEXEC);
        result = raw_syscall3(SYS_fcntl, descriptor, F_GETFL, 0);
        failures += expect_mask("socket_nonblock", result, O_NONBLOCK);
        failures += close_if_open(descriptor);
    }

    result = raw_syscall4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, 0);
    failures += expect_result("socketpair_bad_pointer", result, -EFAULT);
    result = raw_syscall4(SYS_socketpair, AF_INET, SOCK_STREAM, 0,
                          (long)pair);
    failures += expect_result("socketpair_bad_domain", result, -EOPNOTSUPP);
    result = raw_syscall4(SYS_socketpair, 999, SOCK_STREAM, 0, (long)pair);
    failures += expect_result("socketpair_unknown_domain", result,
                              -EAFNOSUPPORT);
    result = raw_syscall4(SYS_socketpair, AF_UNIX,
                          SOCK_STREAM | 0x400000, 0, (long)pair);
    failures += expect_result("socketpair_bad_flag", result, -EINVAL);
    result = raw_syscall4(SYS_socketpair, AF_UNIX, 0, 0, (long)pair);
    failures += expect_result("socketpair_bad_type", result,
                              -ESOCKTNOSUPPORT);
    result = raw_syscall4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 1,
                          (long)pair);
    failures += expect_result("socketpair_unix_protocol", result, 0);
    if (result == 0) {
        failures += close_if_open(pair[0]);
        failures += close_if_open(pair[1]);
        pair[0] = -1;
        pair[1] = -1;
    }
    result = raw_syscall4(SYS_socketpair, AF_UNIX,
                          SOCK_RAW | SOCK_NONBLOCK, 0, (long)pair);
    failures += expect_result("socketpair_unix_raw", result, 0);
    if (result == 0) {
        socket_option = -1;
        socket_option_length = sizeof(socket_option);
        result = raw_syscall5(SYS_getsockopt, pair[0], SOL_SOCKET, SO_TYPE,
                              (long)&socket_option,
                              (long)&socket_option_length);
        failures += expect_result("socketpair_raw_get_type", result, 0);
        failures += expect_result("socketpair_raw_type", socket_option,
                                  SOCK_DGRAM);
        byte = 'R';
        result = raw_syscall3(SYS_write, pair[0], (long)&byte, 1);
        failures += expect_result("socketpair_raw_write", result, 1);
        byte = 0;
        result = raw_syscall3(SYS_read, pair[1], (long)&byte, 1);
        failures += expect_result("socketpair_raw_read", result, 1);
        failures += expect_result("socketpair_raw_payload", byte, 'R');
        failures += close_if_open(pair[0]);
        failures += close_if_open(pair[1]);
        pair[0] = -1;
        pair[1] = -1;
    }

    result = raw_syscall4(SYS_socketpair, AF_UNIX,
                          SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                          0, (long)pair);
    failures += expect_result("socketpair_create", result, 0);
    if (result == 0) {
        byte = 'S';
        result = raw_syscall3(SYS_fcntl, pair[0], F_GETFD, 0);
        failures += expect_mask("socketpair_cloexec", result, FD_CLOEXEC);
        result = raw_syscall3(SYS_fcntl, pair[1], F_GETFL, 0);
        failures += expect_mask("socketpair_nonblock", result, O_NONBLOCK);
        result = raw_syscall3(SYS_write, pair[0], (long)&byte, 1);
        failures += expect_result("socketpair_write", result, 1);
        byte = 0;
        result = raw_syscall3(SYS_read, pair[1], (long)&byte, 1);
        failures += expect_result("socketpair_read", result, 1);
        failures += expect_result("socketpair_payload", byte, 'S');
        result = raw_syscall2(SYS_shutdown, pair[0], SHUT_WR);
        failures += expect_result("shutdown_write", result, 0);
        result = raw_syscall6(SYS_sendto, pair[0], (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("shutdown_write_send", result, -EPIPE);
        failures += expect_poll("shutdown_write_local_poll", pair[0],
                                POLLOUT);
        failures += expect_poll("shutdown_write_peer_poll", pair[1],
                                POLLIN | POLLOUT | POLLRDHUP);
        result = raw_syscall3(SYS_read, pair[1], (long)&byte, 1);
        failures += expect_result("shutdown_peer_eof", result, 0);
        byte = 'P';
        result = raw_syscall6(SYS_sendto, pair[1], (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("shutdown_write_peer_send", result, 1);
        byte = 0;
        result = raw_syscall3(SYS_read, pair[0], (long)&byte, 1);
        failures += expect_result("shutdown_write_local_read", result, 1);
        failures += expect_result("shutdown_write_local_payload", byte, 'P');
        result = raw_syscall2(SYS_shutdown, pair[0], 3);
        failures += expect_result("shutdown_bad_how", result, -EINVAL);
        failures += close_if_open(pair[0]);
        failures += close_if_open(pair[1]);
        pair[0] = -1;
        pair[1] = -1;
    }

    result = raw_syscall4(SYS_socketpair, AF_UNIX,
                          SOCK_DGRAM | SOCK_NONBLOCK, 0, (long)pair);
    failures += expect_result("socketpair_dgram_full_shutdown_read_create",
                              result, 0);
    if (result == 0) {
        byte = 'F';
        for (fill_count = 0; fill_count < 1024; ++fill_count) {
            result = raw_syscall6(SYS_sendto, pair[1], (long)&byte, 1,
                                  MSG_NOSIGNAL, 0, 0);
            if (result != 1) break;
        }
        failures += expect_result("dgram_full_shutdown_read_fill", result,
                                  -EAGAIN);
        result = raw_syscall2(SYS_shutdown, pair[0], SHUT_RD);
        failures += expect_result("dgram_full_shutdown_read", result, 0);
        failures += expect_poll("dgram_full_shutdown_read_peer_poll",
                                pair[1], 0);
        result = raw_syscall6(SYS_sendto, pair[1], (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("dgram_full_shutdown_read_peer_send",
                                  result, -EAGAIN);
        failures += close_if_open(pair[0]);
        failures += close_if_open(pair[1]);
        pair[0] = -1;
        pair[1] = -1;
    }

    result = raw_syscall4(SYS_socketpair, AF_UNIX,
                          SOCK_DGRAM | SOCK_NONBLOCK, 0, (long)pair);
    failures += expect_result("socketpair_dgram_shutdown_write_create",
                              result, 0);
    if (result == 0) {
        result = raw_syscall2(SYS_shutdown, pair[0], SHUT_WR);
        failures += expect_result("dgram_shutdown_write", result, 0);
        byte = 'W';
        result = raw_syscall6(SYS_sendto, pair[0], (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("dgram_shutdown_write_send", result,
                                  -EPIPE);
        result = raw_syscall3(SYS_read, pair[1], (long)&byte, 1);
        failures += expect_result("dgram_shutdown_write_peer_read", result,
                                  -EAGAIN);
        failures += expect_poll("dgram_shutdown_write_local_poll", pair[0],
                                POLLOUT);
        failures += expect_poll("dgram_shutdown_write_peer_poll", pair[1],
                                POLLOUT);
        byte = 'R';
        result = raw_syscall6(SYS_sendto, pair[1], (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("dgram_shutdown_write_peer_send", result,
                                  1);
        byte = 0;
        result = raw_syscall3(SYS_read, pair[0], (long)&byte, 1);
        failures += expect_result("dgram_shutdown_write_local_read", result,
                                  1);
        failures += expect_result("dgram_shutdown_write_local_payload", byte,
                                  'R');
        failures += close_if_open(pair[0]);
        failures += close_if_open(pair[1]);
        pair[0] = -1;
        pair[1] = -1;
    }

    result = raw_syscall4(SYS_socketpair, AF_UNIX,
                          SOCK_DGRAM | SOCK_NONBLOCK, 0, (long)pair);
    failures += expect_result("socketpair_dgram_shutdown_read_create",
                              result, 0);
    if (result == 0) {
        result = raw_syscall2(SYS_shutdown, pair[0], SHUT_RD);
        failures += expect_result("dgram_shutdown_read", result, 0);
        byte = 'X';
        result = raw_syscall6(SYS_sendto, pair[1], (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("dgram_shutdown_read_peer_send", result,
                                  -EPIPE);
        result = raw_syscall3(SYS_read, pair[0], (long)&byte, 1);
        failures += expect_result("dgram_shutdown_read_local_read", result,
                                  -EAGAIN);
        failures += expect_poll("dgram_shutdown_read_local_poll", pair[0],
                                POLLIN | POLLOUT | POLLRDHUP);
        failures += expect_poll("dgram_shutdown_read_peer_poll", pair[1],
                                POLLOUT);
        byte = 'Y';
        result = raw_syscall6(SYS_sendto, pair[0], (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("dgram_shutdown_read_local_send", result,
                                  1);
        byte = 0;
        result = raw_syscall3(SYS_read, pair[1], (long)&byte, 1);
        failures += expect_result("dgram_shutdown_read_peer_read", result, 1);
        failures += expect_result("dgram_shutdown_read_peer_payload", byte,
                                  'Y');
        failures += close_if_open(pair[0]);
        failures += close_if_open(pair[1]);
        pair[0] = -1;
        pair[1] = -1;
    }

    result = raw_syscall4(SYS_socketpair, AF_UNIX,
                          SOCK_DGRAM | SOCK_NONBLOCK, 0, (long)pair);
    failures += expect_result("socketpair_dgram_peer_close_create", result, 0);
    if (result == 0) {
        failures += close_if_open(pair[1]);
        pair[1] = -1;
        byte = 'C';
        result = raw_syscall6(SYS_sendto, pair[0], (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("dgram_peer_close_send", result,
                                  -ECONNREFUSED);
        result = raw_syscall3(SYS_read, pair[0], (long)&byte, 1);
        failures += expect_result("dgram_peer_close_read", result, -EAGAIN);
        failures += expect_poll("dgram_peer_close_poll", pair[0], POLLOUT);
        failures += close_if_open(pair[0]);
        pair[0] = -1;
    }

    result = raw_syscall4(SYS_socketpair, AF_UNIX,
                          SOCK_SEQPACKET | SOCK_NONBLOCK, 0, (long)pair);
    failures += expect_result("socketpair_seqpacket_peer_close_create",
                              result, 0);
    if (result == 0) {
        failures += close_if_open(pair[1]);
        pair[1] = -1;
        byte = 'Q';
        result = raw_syscall6(SYS_sendto, pair[0], (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("seqpacket_peer_close_send", result,
                                  -EPIPE);
        result = raw_syscall3(SYS_read, pair[0], (long)&byte, 1);
        failures += expect_result("seqpacket_peer_close_read", result, 0);
        failures += expect_poll("seqpacket_peer_close_poll", pair[0],
                                POLLIN | POLLOUT | POLLHUP | POLLRDHUP);
        failures += close_if_open(pair[0]);
        pair[0] = -1;
    }

    result = raw_syscall2(SYS_shutdown, -1, 3);
    failures += expect_result("shutdown_bad_fd_and_how", result, -EBADF);

    descriptor = raw_syscall3(SYS_socket, AF_UNIX,
                              SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (descriptor < 0) {
        failures += expect_result("shutdown_unconnected_create", descriptor,
                                  0);
    } else {
        result = raw_syscall2(SYS_shutdown, descriptor, SHUT_WR);
        failures += expect_result("shutdown_unconnected", result, 0);
        result = raw_syscall6(SYS_sendto, descriptor, (long)&byte, 1,
                              MSG_NOSIGNAL, 0, 0);
        failures += expect_result("shutdown_unconnected_send", result,
                                  -ENOTCONN);
        failures += close_if_open(descriptor);
    }
    result = raw_syscall2(SYS_listen, -1, 0);
    failures += expect_result("listen_bad_fd", result, -EBADF);

    result = raw_syscall2(SYS_pipe2, (long)pipe_descriptors, 0);
    failures += expect_result("pipe2", result, 0);
    if (result == 0) {
        result = raw_syscall2(SYS_listen, pipe_descriptors[0], 0);
        failures += expect_result("listen_non_socket", result, -ENOTSOCK);
        result = raw_syscall2(SYS_shutdown, pipe_descriptors[0], SHUT_RDWR);
        failures += expect_result("shutdown_non_socket", result, -ENOTSOCK);
        failures += close_if_open(pipe_descriptors[0]);
        failures += close_if_open(pipe_descriptors[1]);
    }

    descriptor = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) {
        failures += expect_result("listen_unbound_create", descriptor, 0);
    } else {
        result = raw_syscall2(SYS_listen, descriptor, 0);
        failures += expect_result("listen_unbound_unix", result, -EINVAL);
        failures += close_if_open(descriptor);
    }

    descriptor = raw_syscall3(SYS_socket, AF_UNIX, SOCK_DGRAM, 0);
    if (descriptor < 0) {
        failures += expect_result("listen_dgram_create", descriptor, 0);
    } else {
        result = raw_syscall2(SYS_listen, descriptor, 0);
        failures += expect_result("listen_dgram", result, -EOPNOTSUPP);
        failures += close_if_open(descriptor);
    }

    putstr("SOCKET_CORE_ABI_PROBE_");
    putstr(failures ? "FAIL failures:" : "PASS failures:");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    int result = run_probe();
#if defined(__x86_64__)
    (void)raw_syscall1(60, result);
#else
    (void)raw_syscall1(93, result);
#endif
    for (;;) {}
}

#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ __volatile__(
        "andq $-16, %rsp\n"
        "call probe_entry\n");
}
#else
void _start(void) {
    probe_entry();
}
#endif
