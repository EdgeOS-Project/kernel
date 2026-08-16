/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux getsockopt/setsockopt ABI probe.  It validates common
 * socket state, short-output semantics, pointer and descriptor error ordering,
 * protocol applicability, timeout layouts, peer identity, device binding, and
 * classic BPF filter lifecycle on both supported 64-bit architectures.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_pipe2 293
#define SYS_socket 41
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_bind 49
#define SYS_socketpair 53
#define SYS_setsockopt 54
#define SYS_getsockopt 55
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_write 64
#define SYS_exit 93
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_sendto 206
#define SYS_recvfrom 207
#define SYS_setsockopt 208
#define SYS_getsockopt 209
#else
#error "socket_option_abi_probe requires a Linux 64-bit architecture"
#endif

#define ENOENT 2
#define EBADF 9
#define EAGAIN 11
#define EFAULT 14
#define ENODEV 19
#define EINVAL 22
#define EDOM 33
#define ERANGE 34
#define ENOTSOCK 88
#define ENOPROTOOPT 92
#define EOPNOTSUPP 95
#define EADDRINUSE 98

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define MSG_DONTWAIT 0x40
#define SOL_IP 0
#define SOL_SOCKET 1
#define SOL_TCP 6
#define SOL_IPV6 41
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_LINGER 13
#define SO_PASSCRED 16
#define SO_PEERCRED 17
#define SO_RCVLOWAT 18
#define SO_SNDLOWAT 19
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define SO_BINDTODEVICE 25
#define SO_ATTACH_FILTER 26
#define SO_DETACH_FILTER 27
#define SO_PEERSEC 31
#define SO_SNDBUFFORCE 32
#define SO_RCVBUFFORCE 33
#define SO_MARK 36
#define SO_PROTOCOL 38
#define SO_DOMAIN 39
#define SO_PEERGROUPS 59
#define SO_RCVTIMEO_NEW 66
#define SO_SNDTIMEO_NEW 67
#define SO_PEERPIDFD 77
#define IP_TTL 2
#define IP_MULTICAST_TTL 33
#define IP_MULTICAST_LOOP 34
#define IP_ADD_MEMBERSHIP 35
#define IP_DROP_MEMBERSHIP 36
#define IPV6_MULTICAST_HOPS 18
#define IPV6_MULTICAST_LOOP 19
#define IPV6_ADD_MEMBERSHIP 20
#define IPV6_DROP_MEMBERSHIP 21
#define IPV6_V6ONLY 26
#define TCP_NODELAY 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define BPF_RET 0x06
#define BPF_K 0x00

struct linux_timeval {
    int64_t seconds;
    int64_t microseconds;
};

struct linux_linger {
    int32_t enabled;
    int32_t seconds;
};

struct linux_ucred {
    int32_t process_id;
    uint32_t user_id;
    uint32_t group_id;
};

struct linux_sockaddr_in {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t zero[8];
};

struct linux_ip_mreqn {
    uint32_t multiaddr;
    uint32_t address;
    int32_t ifindex;
};

struct linux_ipv6_mreq {
    uint8_t multiaddr[16];
    int32_t ifindex;
};

struct linux_sock_filter {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t value;
};

struct linux_sock_fprog {
    uint16_t length;
    uint64_t filter;
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
    (void)raw_syscall3(SYS_write, 1, (long)text, (long)text_length(text));
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

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    putstr(name);
    putstr(": condition failed\n");
    return 1;
}

static long set_option(long descriptor, long level, long name,
                       const void *value, uint32_t length) {
    return raw_syscall5(SYS_setsockopt, descriptor, level, name,
                        (long)value, length);
}

static long get_option(long descriptor, long level, long name,
                       void *value, uint32_t *length) {
    return raw_syscall5(SYS_getsockopt, descriptor, level, name,
                        (long)value, (long)length);
}

static int close_checked(long descriptor) {
    if (descriptor < 0) return 0;
    return expect_result("close", raw_syscall1(SYS_close, descriptor), 0);
}

static uint16_t network_u16(uint16_t value) {
    return (uint16_t)((value << 8) | (value >> 8));
}

static int run_probe(void) {
    int pipe_descriptors[2] = {-1, -1};
    int pair[2] = {-1, -1};
    uint8_t bytes[16];
    uint32_t length;
    int32_t value;
    int32_t output;
    long unix_socket = -1;
    long tcp_socket = -1;
    long udp_socket = -1;
    long filter_sender = -1;
    long ipv6_socket = -1;
    int failures = 0;

    length = 4;
    failures += expect_result("get_badfd",
        get_option(-1, SOL_SOCKET, SO_TYPE, 0, &length), -EBADF);
    failures += expect_result("set_badfd",
        set_option(-1, SOL_SOCKET, SO_REUSEADDR, 0, 0), -EBADF);
    failures += expect_result("pipe2",
        raw_syscall2(SYS_pipe2, (long)pipe_descriptors, 0), 0);
    if (pipe_descriptors[0] >= 0) {
        length = 4;
        failures += expect_result("get_pipe",
            get_option(pipe_descriptors[0], SOL_SOCKET, SO_TYPE,
                       &output, &length), -ENOTSOCK);
        failures += expect_result("set_pipe",
            set_option(pipe_descriptors[0], SOL_SOCKET, SO_REUSEADDR,
                       &value, sizeof(value)), -ENOTSOCK);
    }
    failures += close_checked(pipe_descriptors[0]);
    failures += close_checked(pipe_descriptors[1]);

    unix_socket = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    failures += expect_true("unix_socket", unix_socket >= 0);
    if (unix_socket < 0) goto out;

    for (uint32_t capacity = 0; capacity <= 4; ++capacity) {
        for (uint32_t index = 0; index < sizeof(bytes); ++index)
            bytes[index] = 0xcc;
        length = capacity;
        failures += expect_result("type_short_result",
            get_option(unix_socket, SOL_SOCKET, SO_TYPE, bytes, &length), 0);
        failures += expect_result("type_short_length", length, capacity);
        if (capacity > 0) failures += expect_result(
            "type_short_byte0", bytes[0], SOCK_STREAM);
        if (capacity < sizeof(bytes)) failures += expect_result(
            "type_short_no_overwrite", bytes[capacity], 0xcc);
    }
    length = 4;
    failures += expect_result("get_null_value",
        get_option(unix_socket, SOL_SOCKET, SO_TYPE, 0, &length), -EFAULT);
    failures += expect_result("get_null_length",
        get_option(unix_socket, SOL_SOCKET, SO_TYPE, &output, 0), -EFAULT);
    length = UINT32_MAX;
    failures += expect_result("get_negative_length",
        get_option(unix_socket, SOL_SOCKET, SO_TYPE, &output, &length),
        -EINVAL);
    length = 4;
    failures += expect_result("get_unknown",
        get_option(unix_socket, SOL_SOCKET, 999, &output, &length),
        -ENOPROTOOPT);
    failures += expect_result("set_unknown",
        set_option(unix_socket, SOL_SOCKET, 999, &value, sizeof(value)),
        -ENOPROTOOPT);

    value = 1;
    failures += expect_result("reuse_short",
        set_option(unix_socket, SOL_SOCKET, SO_REUSEADDR, &value, 3),
        -EINVAL);
    failures += expect_result("reuse_null",
        set_option(unix_socket, SOL_SOCKET, SO_REUSEADDR, 0, 4), -EFAULT);
    failures += expect_result("reuse_set",
        set_option(unix_socket, SOL_SOCKET, SO_REUSEADDR,
                   &value, sizeof(value)), 0);
    output = 0;
    length = sizeof(output);
    failures += expect_result("reuse_get",
        get_option(unix_socket, SOL_SOCKET, SO_REUSEADDR,
                   &output, &length), 0);
    failures += expect_result("reuse_value", output, 1);

    failures += expect_result("passcred_set",
        set_option(unix_socket, SOL_SOCKET, SO_PASSCRED,
                   &value, sizeof(value)), 0);
    output = 0;
    length = sizeof(output);
    failures += expect_result("passcred_get",
        get_option(unix_socket, SOL_SOCKET, SO_PASSCRED,
                   &output, &length), 0);
    failures += expect_result("passcred_value", output, 1);

    {
        struct linux_linger linger = {1, 7};
        struct linux_linger returned = {0, 0};
        failures += expect_result("linger_null",
            set_option(unix_socket, SOL_SOCKET, SO_LINGER,
                       0, sizeof(linger)), -EFAULT);
        failures += expect_result("linger_set",
            set_option(unix_socket, SOL_SOCKET, SO_LINGER,
                       &linger, sizeof(linger)), 0);
        length = sizeof(returned);
        failures += expect_result("linger_get",
            get_option(unix_socket, SOL_SOCKET, SO_LINGER,
                       &returned, &length), 0);
        failures += expect_result("linger_enabled", returned.enabled, 1);
        failures += expect_result("linger_seconds", returned.seconds, 7);
    }

    {
        struct linux_timeval timeout = {0, 250000};
        struct linux_timeval returned;
        failures += expect_result("timeout_null",
            set_option(unix_socket, SOL_SOCKET, SO_RCVTIMEO,
                       0, sizeof(timeout)), -EFAULT);
        failures += expect_result("recv_timeout_set",
            set_option(unix_socket, SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout)), 0);
        timeout.microseconds = 500000;
        failures += expect_result("send_timeout_set",
            set_option(unix_socket, SOL_SOCKET, SO_SNDTIMEO_NEW,
                       &timeout, sizeof(timeout)), 0);
        length = sizeof(returned);
        failures += expect_result("recv_timeout_get",
            get_option(unix_socket, SOL_SOCKET, SO_RCVTIMEO,
                       &returned, &length), 0);
        failures += expect_true("recv_timeout_nonzero",
            returned.seconds > 0 || returned.microseconds > 0);
        length = sizeof(returned);
        failures += expect_result("send_timeout_get",
            get_option(unix_socket, SOL_SOCKET, SO_SNDTIMEO,
                       &returned, &length), 0);
        failures += expect_true("send_timeout_nonzero",
            returned.seconds > 0 || returned.microseconds > 0);
        timeout.microseconds = 1000000;
        failures += expect_result("timeout_invalid_usec",
            set_option(unix_socket, SOL_SOCKET, SO_RCVTIMEO_NEW,
                       &timeout, sizeof(timeout)), -EDOM);
    }

    value = -1;
    failures += expect_result("receive_buffer_negative",
        set_option(unix_socket, SOL_SOCKET, SO_RCVBUF,
                   &value, sizeof(value)), 0);
    length = sizeof(output);
    failures += expect_result("receive_buffer_get",
        get_option(unix_socket, SOL_SOCKET, SO_RCVBUF,
                   &output, &length), 0);
    failures += expect_true("receive_buffer_positive", output > 0);
    value = 1024 * 1024;
    failures += expect_result("send_buffer_force_set",
        set_option(unix_socket, SOL_SOCKET, SO_SNDBUFFORCE,
                   &value, sizeof(value)), 0);
    failures += expect_result("receive_buffer_force_set",
        set_option(unix_socket, SOL_SOCKET, SO_RCVBUFFORCE,
                   &value, sizeof(value)), 0);
    length = sizeof(output);
    failures += expect_result("send_buffer_after_force_get",
        get_option(unix_socket, SOL_SOCKET, SO_SNDBUF,
                   &output, &length), 0);
    failures += expect_true("send_buffer_after_force_positive", output > 0);
    length = sizeof(output);
    failures += expect_result("receive_buffer_after_force_get",
        get_option(unix_socket, SOL_SOCKET, SO_RCVBUF,
                   &output, &length), 0);
    failures += expect_true("receive_buffer_after_force_positive", output > 0);
    failures += expect_result("send_low_water_read_only",
        set_option(unix_socket, SOL_SOCKET, SO_SNDLOWAT,
                   &value, sizeof(value)), -ENOPROTOOPT);
    failures += expect_result("receive_low_water_set",
        set_option(unix_socket, SOL_SOCKET, SO_RCVLOWAT,
                   &value, sizeof(value)), 0);
    length = sizeof(output);
    failures += expect_result("receive_low_water_get",
        get_option(unix_socket, SOL_SOCKET, SO_RCVLOWAT,
                   &output, &length), 0);
    failures += expect_result("receive_low_water_value", output, 2147483647);

    value = 1;
    failures += expect_result("tcp_option_on_unix",
        set_option(unix_socket, SOL_TCP, TCP_NODELAY,
                   &value, sizeof(value)), -EOPNOTSUPP);
    length = sizeof(output);
    failures += expect_result("peersec_unsupported",
        get_option(unix_socket, SOL_SOCKET, SO_PEERSEC,
                   &output, &length), -ENOPROTOOPT);

    value = 0x12345678;
    failures += expect_result("socket_mark_set",
        set_option(unix_socket, SOL_SOCKET, SO_MARK,
                   &value, sizeof(value)), 0);
    output = 0;
    length = sizeof(output);
    failures += expect_result("socket_mark_get",
        get_option(unix_socket, SOL_SOCKET, SO_MARK,
                   &output, &length), 0);
    failures += expect_result("socket_mark_value", output, value);

    {
        const char loopback[] = "lo";
        char returned[16];
        failures += expect_result("bind_device_set",
            set_option(unix_socket, SOL_SOCKET, SO_BINDTODEVICE,
                       loopback, sizeof(loopback)), 0);
        length = sizeof(returned);
        failures += expect_result("bind_device_get",
            get_option(unix_socket, SOL_SOCKET, SO_BINDTODEVICE,
                       returned, &length), 0);
        failures += expect_result("bind_device_length", length, 3);
        failures += expect_true("bind_device_value",
            returned[0] == 'l' && returned[1] == 'o' && returned[2] == 0);
        failures += expect_result("bind_device_bad",
            set_option(unix_socket, SOL_SOCKET, SO_BINDTODEVICE,
                       "bad0", 5), -ENODEV);
    }

    {
        struct linux_sock_filter instruction = {
            BPF_RET | BPF_K, 0, 0, UINT32_MAX
        };
        struct linux_sock_fprog program = {1, (uint64_t)&instruction};
        struct linux_sock_filter invalid_instruction = {
            0xffffu, 0, 0, 0
        };
        struct linux_sock_fprog invalid_program = {
            1, (uint64_t)&invalid_instruction
        };
        value = 0;
        failures += expect_result("filter_null",
            set_option(unix_socket, SOL_SOCKET, SO_ATTACH_FILTER,
                       0, sizeof(program)), -EFAULT);
        failures += expect_result("filter_invalid",
            set_option(unix_socket, SOL_SOCKET, SO_ATTACH_FILTER,
                       &invalid_program, sizeof(invalid_program)), -EINVAL);
        failures += expect_result("filter_attach",
            set_option(unix_socket, SOL_SOCKET, SO_ATTACH_FILTER,
                       &program, sizeof(program)), 0);
        failures += expect_result("filter_detach",
            set_option(unix_socket, SOL_SOCKET, SO_DETACH_FILTER,
                       &value, sizeof(value)), 0);
        failures += expect_result("filter_detach_empty",
            set_option(unix_socket, SOL_SOCKET, SO_DETACH_FILTER,
                       &value, sizeof(value)), -ENOENT);
    }

    failures += expect_result("socketpair",
        raw_syscall6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0,
                     (long)pair, 0, 0), 0);
    if (pair[0] >= 0) {
        struct linux_ucred credentials;
        uint32_t groups[16];
        int peer_pidfd = -1;
        length = sizeof(credentials);
        failures += expect_result("peercred",
            get_option(pair[0], SOL_SOCKET, SO_PEERCRED,
                       &credentials, &length), 0);
        failures += expect_result("peercred_length", length,
                                  sizeof(credentials));
        failures += expect_true("peercred_pid", credentials.process_id > 0);
        length = 0;
        failures += expect_result("peergroups_size",
            get_option(pair[0], SOL_SOCKET, SO_PEERGROUPS, 0, &length),
            -ERANGE);
        failures += expect_true("peergroups_required",
                                length >= sizeof(uint32_t));
        if (length <= sizeof(groups)) {
            failures += expect_result("peergroups",
                get_option(pair[0], SOL_SOCKET, SO_PEERGROUPS,
                           groups, &length), 0);
        }
        length = sizeof(peer_pidfd);
        failures += expect_result("peerpidfd",
            get_option(pair[0], SOL_SOCKET, SO_PEERPIDFD,
                       &peer_pidfd, &length), 0);
        failures += expect_true("peerpidfd_value", peer_pidfd >= 0);
        failures += close_checked(peer_pidfd);
    }

    tcp_socket = raw_syscall3(SYS_socket, AF_INET, SOCK_STREAM, 0);
    failures += expect_true("tcp_socket", tcp_socket >= 0);
    if (tcp_socket >= 0) {
        output = 0;
        length = sizeof(output);
        failures += expect_result("tcp_protocol_get",
            get_option(tcp_socket, SOL_SOCKET, SO_PROTOCOL,
                       &output, &length), 0);
        failures += expect_result("tcp_protocol_value", output, IPPROTO_TCP);
        value = 1;
        failures += expect_result("tcp_nodelay_set",
            set_option(tcp_socket, SOL_TCP, TCP_NODELAY,
                       &value, sizeof(value)), 0);
        output = 0;
        length = sizeof(output);
        failures += expect_result("tcp_nodelay_get",
            get_option(tcp_socket, SOL_TCP, TCP_NODELAY,
                       &output, &length), 0);
        failures += expect_result("tcp_nodelay_value", output, 1);
        value = 42;
        failures += expect_result("ip_ttl_set",
            set_option(tcp_socket, SOL_IP, IP_TTL,
                       &value, sizeof(value)), 0);
        output = 0;
        length = sizeof(output);
        failures += expect_result("ip_ttl_get",
            get_option(tcp_socket, SOL_IP, IP_TTL,
                       &output, &length), 0);
        failures += expect_result("ip_ttl_value", output, 42);
    }

    udp_socket = raw_syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    failures += expect_true("udp_socket", udp_socket >= 0);
    if (udp_socket >= 0) {
        struct linux_sockaddr_in loopback = {
            AF_INET, network_u16(46073), 0x0100007fu, {0}
        };
        struct linux_sock_filter reject_instruction = {
            BPF_RET | BPF_K, 0, 0, 0
        };
        struct linux_sock_filter accept_instruction = {
            BPF_RET | BPF_K, 0, 0, UINT32_MAX
        };
        struct linux_sock_fprog reject_program = {
            1, (uint64_t)&reject_instruction
        };
        struct linux_sock_fprog accept_program = {
            1, (uint64_t)&accept_instruction
        };
        char sent = 'x';
        char received = 0;
        uint8_t multicast_ttl = 7;
        struct linux_ip_mreqn membership = {
            0xfb0000e0u, 0u, 0
        };
        output = 0;
        length = sizeof(output);
        failures += expect_result("udp_protocol_get",
            get_option(udp_socket, SOL_SOCKET, SO_PROTOCOL,
                       &output, &length), 0);
        failures += expect_result("udp_protocol_value", output, IPPROTO_UDP);
        failures += expect_result("ip_multicast_ttl_byte_set",
            set_option(udp_socket, SOL_IP, IP_MULTICAST_TTL,
                       &multicast_ttl, sizeof(multicast_ttl)), 0);
        output = 0;
        length = sizeof(output);
        failures += expect_result("ip_multicast_ttl_get",
            get_option(udp_socket, SOL_IP, IP_MULTICAST_TTL,
                       &output, &length), 0);
        failures += expect_result("ip_multicast_ttl_value", output, 7);
        value = 1;
        failures += expect_result("ip_multicast_loop_set",
            set_option(udp_socket, SOL_IP, IP_MULTICAST_LOOP,
                       &value, sizeof(value)), 0);
        failures += expect_result("ip_membership_add",
            set_option(udp_socket, SOL_IP, IP_ADD_MEMBERSHIP,
                       &membership, sizeof(membership)), 0);
        failures += expect_result("ip_membership_duplicate",
            set_option(udp_socket, SOL_IP, IP_ADD_MEMBERSHIP,
                       &membership, sizeof(membership)), -EADDRINUSE);
        failures += expect_result("ip_membership_drop",
            set_option(udp_socket, SOL_IP, IP_DROP_MEMBERSHIP,
                       &membership, sizeof(membership)), 0);
        filter_sender = raw_syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
        failures += expect_true("filter_sender", filter_sender >= 0);
        failures += expect_result("filter_bind",
            raw_syscall3(SYS_bind, udp_socket, (long)&loopback,
                         sizeof(loopback)), 0);
        failures += expect_result("filter_reject_attach",
            set_option(udp_socket, SOL_SOCKET, SO_ATTACH_FILTER,
                       &reject_program, sizeof(reject_program)), 0);
        failures += expect_result("filter_reject_send",
            raw_syscall6(SYS_sendto, filter_sender, (long)&sent, 1, 0,
                         (long)&loopback, sizeof(loopback)), 1);
        failures += expect_result("filter_reject_recv",
            raw_syscall6(SYS_recvfrom, udp_socket, (long)&received, 1,
                         MSG_DONTWAIT, 0, 0), -EAGAIN);
        failures += expect_result("filter_accept_attach",
            set_option(udp_socket, SOL_SOCKET, SO_ATTACH_FILTER,
                       &accept_program, sizeof(accept_program)), 0);
        sent = 'y';
        failures += expect_result("filter_accept_send",
            raw_syscall6(SYS_sendto, filter_sender, (long)&sent, 1, 0,
                         (long)&loopback, sizeof(loopback)), 1);
        failures += expect_result("filter_accept_recv",
            raw_syscall6(SYS_recvfrom, udp_socket, (long)&received, 1,
                         MSG_DONTWAIT, 0, 0), 1);
        failures += expect_result("filter_accept_value", received, 'y');
        value = 0;
        failures += expect_result("filter_udp_detach",
            set_option(udp_socket, SOL_SOCKET, SO_DETACH_FILTER,
                       &value, sizeof(value)), 0);
        value = 1;
        failures += expect_result("tcp_set_on_udp",
            set_option(udp_socket, SOL_TCP, TCP_NODELAY,
                       &value, sizeof(value)), -ENOPROTOOPT);
        length = sizeof(output);
        failures += expect_result("tcp_get_on_udp",
            get_option(udp_socket, SOL_TCP, TCP_NODELAY,
                       &output, &length), -EOPNOTSUPP);
    }

    ipv6_socket = raw_syscall3(SYS_socket, AF_INET6, SOCK_DGRAM, 0);
    if (ipv6_socket >= 0) {
        struct linux_ipv6_mreq membership = {
            {0xff, 0x02, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0xfb},
            0
        };
        value = 1;
        failures += expect_result("ipv6_only_set",
            set_option(ipv6_socket, SOL_IPV6, IPV6_V6ONLY,
                       &value, sizeof(value)), 0);
        output = 0;
        length = sizeof(output);
        failures += expect_result("ipv6_only_get",
            get_option(ipv6_socket, SOL_IPV6, IPV6_V6ONLY,
                       &output, &length), 0);
        failures += expect_result("ipv6_only_value", output, 1);
        value = 9;
        failures += expect_result("ipv6_multicast_hops_set",
            set_option(ipv6_socket, SOL_IPV6, IPV6_MULTICAST_HOPS,
                       &value, sizeof(value)), 0);
        output = 0;
        length = sizeof(output);
        failures += expect_result("ipv6_multicast_hops_get",
            get_option(ipv6_socket, SOL_IPV6, IPV6_MULTICAST_HOPS,
                       &output, &length), 0);
        failures += expect_result("ipv6_multicast_hops_value", output, 9);
        value = 1;
        failures += expect_result("ipv6_multicast_loop_set",
            set_option(ipv6_socket, SOL_IPV6, IPV6_MULTICAST_LOOP,
                       &value, sizeof(value)), 0);
        failures += expect_result("ipv6_membership_add",
            set_option(ipv6_socket, SOL_IPV6, IPV6_ADD_MEMBERSHIP,
                       &membership, sizeof(membership)), 0);
        failures += expect_result("ipv6_membership_drop",
            set_option(ipv6_socket, SOL_IPV6, IPV6_DROP_MEMBERSHIP,
                       &membership, sizeof(membership)), 0);
    }

out:
    failures += close_checked(pair[0]);
    failures += close_checked(pair[1]);
    failures += close_checked(ipv6_socket);
    failures += close_checked(filter_sender);
    failures += close_checked(udp_socket);
    failures += close_checked(tcp_socket);
    failures += close_checked(unix_socket);
    putstr(failures ? "SOCKET_OPTION_ABI_PROBE_FAIL failures: " :
                      "SOCKET_OPTION_ABI_PROBE_PASS failures: ");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

void _start(void) {
    (void)raw_syscall1(SYS_exit, run_probe());
    for (;;) {}
}
