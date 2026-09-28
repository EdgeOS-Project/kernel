/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux socket first-observation ABI oracle. It records the
 * descriptor, pointer, and flag validation order shared socket handlers must
 * preserve. It also verifies AF_UNIX datagram record boundaries across vector
 * I/O, recvmsg input-pointer preservation, and SO_ERROR copyout side effects.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_poll 7
#define SYS_write 1
#define SYS_close 3
#define SYS_getpid 39
#define SYS_socket 41
#define SYS_connect 42
#define SYS_accept4 288
#define SYS_bind 49
#define SYS_listen 50
#define SYS_getsockname 51
#define SYS_getpeername 52
#define SYS_socketpair 53
#define SYS_setsockopt 54
#define SYS_getsockopt 55
#define SYS_exit 60
#define SYS_pipe2 293
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_sendmsg 46
#define SYS_recvmsg 47
#define SYS_shutdown 48
#elif defined(__aarch64__)
#define SYS_pipe2 59
#define SYS_close 57
#define SYS_write 64
#define SYS_ppoll 73
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_listen 201
#define SYS_connect 203
#define SYS_getsockname 204
#define SYS_getpeername 205
#define SYS_sendto 206
#define SYS_recvfrom 207
#define SYS_setsockopt 208
#define SYS_getsockopt 209
#define SYS_shutdown 210
#define SYS_sendmsg 211
#define SYS_recvmsg 212
#define SYS_accept4 242
#else
#error "socket_first_observation_abi_probe requires x86_64 or AArch64 Linux"
#endif

#define EBADF 9
#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22
#define ENOTSOCK 88
#define EOPNOTSUPP 95
#define ECONNREFUSED 111

#define AF_UNIX 1
#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_SEQPACKET 5
#define SOCK_NONBLOCK 0x800
#define SOCK_CLOEXEC 0x80000
#define SOL_SOCKET 1
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define MSG_DONTWAIT 0x40
#define POLLERR 0x0008

struct linux_iovec {
    uint64_t base;
    uint64_t length;
};

struct linux_msghdr {
    uint64_t name;
    uint32_t name_length;
    uint32_t pad0;
    uint64_t iov;
    uint64_t iov_length;
    uint64_t control;
    uint64_t control_length;
    int32_t flags;
    int32_t pad1;
};

struct linux_sockaddr_un {
    uint16_t family;
    uint8_t path[108];
};

struct linux_sockaddr_in {
    uint16_t family;
    uint16_t port;
    uint8_t address[4];
    uint8_t zero[8];
};

struct linux_pollfd {
    int32_t descriptor;
    int16_t events;
    int16_t returned_events;
};

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

static unsigned long check_count;

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

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, 0, 0);
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
    char bytes[24];
    unsigned long magnitude;
    int position = (int)sizeof(bytes);

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
        bytes[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    }
    (void)raw_syscall3(SYS_write, 1, (long)&bytes[position],
                       (long)(sizeof(bytes) - (unsigned)position));
}

static int expect_result(const char *name, long actual, long expected) {
    ++check_count;
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
    ++check_count;
    if (condition) return 0;
    putstr(name);
    putstr(": false\n");
    return 1;
}

static int expect_bytes(const char *name, const uint8_t *actual,
                        const uint8_t *expected, uint64_t length) {
    ++check_count;
    for (uint64_t index = 0; index < length; ++index) {
        if (actual[index] == expected[index]) continue;
        putstr(name);
        putstr(": byte=");
        putdec((long)index);
        putstr(" actual=");
        putdec(actual[index]);
        putstr(" expected=");
        putdec(expected[index]);
        putstr("\n");
        return 1;
    }
    return 0;
}

static void bytes_fill(void *pointer, uint8_t value, uint64_t length) {
    uint8_t *bytes = (uint8_t *)pointer;
    for (uint64_t index = 0; index < length; ++index) bytes[index] = value;
}

static void bytes_zero(void *pointer, uint64_t length) {
    bytes_fill(pointer, 0, length);
}

static int close_checked(long descriptor) {
    if (descriptor < 0) return 0;
    return expect_result("close", raw_syscall1(SYS_close, descriptor), 0);
}

static long socket_pair(int type, int descriptors[2]) {
    return raw_syscall4(SYS_socketpair, AF_UNIX, type, 0,
                        (long)descriptors);
}

static void make_unix_address(struct linux_sockaddr_un *address,
                              uint8_t tag) {
    uint32_t process_id = (uint32_t)raw_syscall1(SYS_getpid, 0);

    bytes_zero(address, sizeof(*address));
    address->family = AF_UNIX;
    address->path[0] = 0;
    address->path[1] = 'e';
    address->path[2] = 'd';
    address->path[3] = 'g';
    address->path[4] = 'e';
    address->path[5] = tag;
    address->path[6] = (uint8_t)process_id;
    address->path[7] = (uint8_t)(process_id >> 8);
    address->path[8] = (uint8_t)(process_id >> 16);
    address->path[9] = (uint8_t)(process_id >> 24);
}

static int test_descriptor_pointer_and_flag_order(void) {
    int pipe_descriptors[2] = {-1, -1};
    int pair[2] = {-1, -1};
    struct linux_msghdr message;
    uint32_t option_length = sizeof(int32_t);
    int32_t option_value = 1;
    long descriptor = -1;
    int failures = 0;

    failures += expect_result("bind_badfd_before_address",
        raw_syscall3(SYS_bind, -1, 1, sizeof(struct linux_sockaddr_un)),
        -EBADF);
    failures += expect_result("connect_badfd_before_address",
        raw_syscall3(SYS_connect, -1, 1, sizeof(struct linux_sockaddr_un)),
        -EBADF);
    failures += expect_result("listen_badfd",
        raw_syscall2(SYS_listen, -1, -1), -EBADF);
    failures += expect_result("shutdown_badfd_before_how",
        raw_syscall2(SYS_shutdown, -1, -1), -EBADF);
    failures += expect_result("getsockname_badfd_before_pointers",
        raw_syscall3(SYS_getsockname, -1, 1, 1), -EBADF);
    failures += expect_result("getpeername_badfd_before_pointers",
        raw_syscall3(SYS_getpeername, -1, 1, 1), -EBADF);
    failures += expect_result("sendto_badfd_before_inputs",
        raw_syscall6(SYS_sendto, -1, 1, 1, -1, 1,
                     sizeof(struct linux_sockaddr_un)), -EBADF);
    failures += expect_result("recvfrom_badfd_before_outputs",
        raw_syscall6(SYS_recvfrom, -1, 1, 1, -1, 1, 1), -EBADF);
    failures += expect_result("sendmsg_badfd_before_header",
        raw_syscall3(SYS_sendmsg, -1, 1, 0), -EBADF);
    failures += expect_result("recvmsg_badfd_before_header",
        raw_syscall3(SYS_recvmsg, -1, 1, MSG_DONTWAIT), -EBADF);
    failures += expect_result("accept4_badfd_before_flags",
        raw_syscall4(SYS_accept4, -1, 1, 1, 1), -EBADF);
    failures += expect_result("setsockopt_badfd_before_value",
        raw_syscall5(SYS_setsockopt, -1, SOL_SOCKET, SO_REUSEADDR, 1,
                     sizeof(option_value)), -EBADF);
    failures += expect_result("getsockopt_badfd_before_outputs",
        raw_syscall5(SYS_getsockopt, -1, SOL_SOCKET, SO_TYPE, 1, 1),
        -EBADF);

    failures += expect_result("pipe2",
        raw_syscall2(SYS_pipe2, (long)pipe_descriptors, 0), 0);
    if (pipe_descriptors[0] >= 0) {
        failures += expect_result("bind_nonsocket_before_address",
            raw_syscall3(SYS_bind, pipe_descriptors[0], 1,
                         sizeof(struct linux_sockaddr_un)), -ENOTSOCK);
        failures += expect_result("connect_address_before_nonsocket",
            raw_syscall3(SYS_connect, pipe_descriptors[0], 1,
                         sizeof(struct linux_sockaddr_un)), -EFAULT);
        failures += expect_result("listen_nonsocket",
            raw_syscall2(SYS_listen, pipe_descriptors[0], -1), -ENOTSOCK);
        failures += expect_result("shutdown_nonsocket_before_how",
            raw_syscall2(SYS_shutdown, pipe_descriptors[0], -1),
            -ENOTSOCK);
        failures += expect_result("getsockname_nonsocket_before_pointers",
            raw_syscall3(SYS_getsockname, pipe_descriptors[0], 1, 1),
            -ENOTSOCK);
        failures += expect_result("getpeername_nonsocket_before_pointers",
            raw_syscall3(SYS_getpeername, pipe_descriptors[0], 1, 1),
            -ENOTSOCK);
        failures += expect_result("sendto_nonsocket_before_inputs",
            raw_syscall6(SYS_sendto, pipe_descriptors[1], 1, 1, -1, 1,
                         sizeof(struct linux_sockaddr_un)), -ENOTSOCK);
        failures += expect_result("recvfrom_nonsocket_before_outputs",
            raw_syscall6(SYS_recvfrom, pipe_descriptors[0], 1, 1, -1, 1,
                         1), -ENOTSOCK);
        failures += expect_result("sendmsg_nonsocket_before_header",
            raw_syscall3(SYS_sendmsg, pipe_descriptors[1], 1, 0),
            -ENOTSOCK);
        failures += expect_result("recvmsg_nonsocket_before_header",
            raw_syscall3(SYS_recvmsg, pipe_descriptors[0], 1,
                         MSG_DONTWAIT),
            -ENOTSOCK);
        failures += expect_result("accept4_badflags_before_socket_type",
            raw_syscall4(SYS_accept4, pipe_descriptors[0], 1, 1, 1),
            -EINVAL);
        failures += expect_result("setsockopt_nonsocket_before_value",
            raw_syscall5(SYS_setsockopt, pipe_descriptors[0], SOL_SOCKET,
                         SO_REUSEADDR, 1, sizeof(option_value)), -ENOTSOCK);
        failures += expect_result("getsockopt_nonsocket_before_outputs",
            raw_syscall5(SYS_getsockopt, pipe_descriptors[0], SOL_SOCKET,
                         SO_TYPE, 1, 1), -ENOTSOCK);
    }
    failures += close_checked(pipe_descriptors[0]);
    failures += close_checked(pipe_descriptors[1]);

    descriptor = raw_syscall3(SYS_socket, AF_UNIX,
                              SOCK_DGRAM | SOCK_NONBLOCK, 0);
    failures += expect_true("ordering_socket", descriptor >= 0);
    if (descriptor >= 0) {
        uint8_t payload = 's';

        failures += expect_result("bind_valid_socket_bad_address",
            raw_syscall3(SYS_bind, descriptor, 1,
                         sizeof(struct linux_sockaddr_un)), -EFAULT);
        failures += expect_result("connect_valid_socket_bad_address",
            raw_syscall3(SYS_connect, descriptor, 1,
                         sizeof(struct linux_sockaddr_un)), -EFAULT);
        failures += expect_result("sendto_valid_socket_bad_address",
            raw_syscall6(SYS_sendto, descriptor, (long)&payload, 1, 0, 1,
                         sizeof(struct linux_sockaddr_un)), -EFAULT);
        failures += expect_result("sendmsg_valid_socket_bad_header",
            raw_syscall3(SYS_sendmsg, descriptor, 1, 0), -EFAULT);
        failures += expect_result("recvmsg_header_before_empty_queue",
            raw_syscall3(SYS_recvmsg, descriptor, 1, MSG_DONTWAIT),
            -EFAULT);
        failures += expect_result("recvfrom_empty_before_output_faults",
            raw_syscall6(SYS_recvfrom, descriptor, 1, 1, MSG_DONTWAIT, 1,
                         1), -EAGAIN);

        option_length = sizeof(option_value);
        failures += expect_result("getsockopt_bad_value_pointer",
            raw_syscall5(SYS_getsockopt, descriptor, SOL_SOCKET, SO_TYPE,
                         1, (long)&option_length), -EFAULT);
        failures += expect_result("getsockopt_bad_length_pointer",
            raw_syscall5(SYS_getsockopt, descriptor, SOL_SOCKET, SO_TYPE,
                         (long)&option_value, 1), -EFAULT);
        failures += expect_result("setsockopt_bad_value_pointer",
            raw_syscall5(SYS_setsockopt, descriptor, SOL_SOCKET,
                         SO_REUSEADDR, 1, sizeof(option_value)), -EFAULT);
        failures += expect_result("listen_datagram",
            raw_syscall2(SYS_listen, descriptor, 1), -EOPNOTSUPP);
        failures += expect_result("shutdown_bad_how",
            raw_syscall2(SYS_shutdown, descriptor, -1), -EINVAL);
    }
    failures += close_checked(descriptor);

    failures += expect_result("ordering_pair",
        socket_pair(SOCK_DGRAM | SOCK_NONBLOCK, pair), 0);
    if (pair[0] >= 0) {
        bytes_zero(&message, sizeof(message));
        failures += expect_result("sendmsg_zero_length",
            raw_syscall3(SYS_sendmsg, pair[0], (long)&message, 0), 0);
        failures += expect_result("recvmsg_zero_length_record",
            raw_syscall3(SYS_recvmsg, pair[1], (long)&message,
                         MSG_DONTWAIT), 0);
    }
    failures += close_checked(pair[0]);
    failures += close_checked(pair[1]);
    return failures;
}

static int test_accept_and_name_copy_order(void) {
    struct linux_sockaddr_un server_address;
    uint8_t returned_address[sizeof(server_address)];
    uint32_t returned_length;
    long server = -1;
    long client = -1;
    long accepted = -1;
    int failures = 0;

    make_unix_address(&server_address, 'l');
    server = raw_syscall3(SYS_socket, AF_UNIX,
                          SOCK_STREAM | SOCK_NONBLOCK, 0);
    failures += expect_true("listener_socket", server >= 0);
    if (server < 0) goto out;
    failures += expect_result("listener_bind",
        raw_syscall3(SYS_bind, server, (long)&server_address, 12), 0);
    failures += expect_result("listener_listen",
        raw_syscall2(SYS_listen, server, 4), 0);
    failures += expect_result("accept4_flags_before_output_pointers",
        raw_syscall4(SYS_accept4, server, 1, 1, 1), -EINVAL);
    failures += expect_result("accept4_empty_before_output_pointers",
        raw_syscall4(SYS_accept4, server, 1, 1, 0), -EAGAIN);

    returned_length = 0;
    failures += expect_result("getsockname_zero_capacity_ignores_address",
        raw_syscall3(SYS_getsockname, server, 1, (long)&returned_length), 0);
    failures += expect_result("getsockname_reports_full_length",
        returned_length, 12);
    returned_length = sizeof(returned_address);
    failures += expect_result("getsockname_bad_address_copy",
        raw_syscall3(SYS_getsockname, server, 1, (long)&returned_length),
        -EFAULT);
    failures += expect_result("getsockname_bad_length_pointer",
        raw_syscall3(SYS_getsockname, server, (long)returned_address, 1),
        -EFAULT);

    client = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    failures += expect_true("accept_client_socket", client >= 0);
    if (client < 0) goto out;
    failures += expect_result("accept_client_connect",
        raw_syscall3(SYS_connect, client, (long)&server_address, 12), 0);
    accepted = raw_syscall4(SYS_accept4, server, 0, 1, SOCK_CLOEXEC);
    failures += expect_true("accept_null_address_ignores_length",
                            accepted >= 0);

    returned_length = 0;
    failures += expect_result("getpeername_zero_capacity_ignores_address",
        raw_syscall3(SYS_getpeername, client, 1, (long)&returned_length), 0);
    failures += expect_result("getpeername_reports_full_length",
        returned_length, 12);
    returned_length = sizeof(returned_address);
    failures += expect_result("getpeername_bad_address_copy",
        raw_syscall3(SYS_getpeername, client, 1, (long)&returned_length),
        -EFAULT);
    failures += expect_result("getpeername_bad_length_pointer",
        raw_syscall3(SYS_getpeername, client, (long)returned_address, 1),
        -EFAULT);

out:
    failures += close_checked(accepted);
    failures += close_checked(client);
    failures += close_checked(server);
    return failures;
}

static int test_datagram_record_and_header_preservation(void) {
    static const uint8_t expected_first[2] = {'a', 'b'};
    static const uint8_t expected_second[3] = {'c', 'D', 'E'};
    static const uint8_t expected_third[4] = {'F', 'G', 'h', 'i'};
    int pair[2] = {-1, -1};
    struct linux_iovec send_vectors[3];
    struct linux_iovec receive_vectors[3];
    struct linux_msghdr send_header;
    struct linux_msghdr receive_header;
    uint8_t first[3];
    uint8_t second[4];
    uint8_t third[6];
    uint8_t name_bytes[32];
    uint8_t control_bytes[32];
    uint8_t trailing_record = 'Z';
    uint8_t trailing_output[16];
    uint64_t saved_name;
    uint64_t saved_vectors;
    uint64_t saved_control;
    int failures = 0;

    failures += expect_result("record_pair",
        socket_pair(SOCK_DGRAM | SOCK_NONBLOCK, pair), 0);
    if (pair[0] < 0) return failures;

    send_vectors[0].base = (uint64_t)(uintptr_t)"abc";
    send_vectors[0].length = 3;
    send_vectors[1].base = (uint64_t)(uintptr_t)"DEFG";
    send_vectors[1].length = 4;
    send_vectors[2].base = (uint64_t)(uintptr_t)"hi";
    send_vectors[2].length = 2;
    bytes_zero(&send_header, sizeof(send_header));
    send_header.iov = (uint64_t)(uintptr_t)send_vectors;
    send_header.iov_length = 3;
    failures += expect_result("three_vector_datagram_send",
        raw_syscall3(SYS_sendmsg, pair[0], (long)&send_header, 0), 9);
    failures += expect_result("trailing_datagram_send",
        raw_syscall6(SYS_sendto, pair[0], (long)&trailing_record, 1, 0,
                     0, 0), 1);

    bytes_fill(first, 0xcc, sizeof(first));
    bytes_fill(second, 0xcc, sizeof(second));
    bytes_fill(third, 0xcc, sizeof(third));
    bytes_fill(name_bytes, 0xcc, sizeof(name_bytes));
    bytes_fill(control_bytes, 0xcc, sizeof(control_bytes));
    receive_vectors[0].base = (uint64_t)(uintptr_t)first;
    receive_vectors[0].length = 2;
    receive_vectors[1].base = (uint64_t)(uintptr_t)second;
    receive_vectors[1].length = 3;
    receive_vectors[2].base = (uint64_t)(uintptr_t)third;
    receive_vectors[2].length = 5;
    bytes_zero(&receive_header, sizeof(receive_header));
    receive_header.name = (uint64_t)(uintptr_t)name_bytes;
    receive_header.name_length = sizeof(name_bytes);
    receive_header.iov = (uint64_t)(uintptr_t)receive_vectors;
    receive_header.iov_length = 3;
    receive_header.control = (uint64_t)(uintptr_t)control_bytes;
    receive_header.control_length = sizeof(control_bytes);
    receive_header.flags = 0x12345678;
    saved_name = receive_header.name;
    saved_vectors = receive_header.iov;
    saved_control = receive_header.control;

    failures += expect_result("three_vector_datagram_receive",
        raw_syscall3(SYS_recvmsg, pair[1], (long)&receive_header,
                     MSG_DONTWAIT), 9);
    failures += expect_bytes("receive_scatter_first", first,
                             expected_first, sizeof(expected_first));
    failures += expect_bytes("receive_scatter_second", second,
                             expected_second, sizeof(expected_second));
    failures += expect_bytes("receive_scatter_third", third,
                             expected_third, sizeof(expected_third));
    failures += expect_result("receive_first_canary", first[2], 0xcc);
    failures += expect_result("receive_second_canary", second[3], 0xcc);
    failures += expect_result("receive_third_canary0", third[4], 0xcc);
    failures += expect_result("receive_third_canary1", third[5], 0xcc);
    failures += expect_true("recvmsg_name_pointer_preserved",
                            receive_header.name == saved_name);
    failures += expect_true("recvmsg_iov_pointer_preserved",
                            receive_header.iov == saved_vectors);
    failures += expect_true("recvmsg_control_pointer_preserved",
                            receive_header.control == saved_control);
    failures += expect_result("recvmsg_iov_count_preserved",
        (long)receive_header.iov_length, 3);
    failures += expect_result("recvmsg_unnamed_peer_length",
        receive_header.name_length, 0);
    failures += expect_result("recvmsg_no_control_length",
        (long)receive_header.control_length, 0);
    failures += expect_result("recvmsg_output_flags",
        receive_header.flags, 0);

    bytes_fill(trailing_output, 0xcc, sizeof(trailing_output));
    failures += expect_result("record_boundary_preserves_next_datagram",
        raw_syscall6(SYS_recvfrom, pair[1], (long)trailing_output,
                     sizeof(trailing_output), MSG_DONTWAIT, 0, 0), 1);
    failures += expect_result("trailing_datagram_payload",
        trailing_output[0], 'Z');
    failures += expect_result("trailing_datagram_canary",
        trailing_output[1], 0xcc);
    failures += expect_result("record_queue_empty",
        raw_syscall6(SYS_recvfrom, pair[1], 1, 1, MSG_DONTWAIT, 1, 1),
        -EAGAIN);

    failures += close_checked(pair[0]);
    failures += close_checked(pair[1]);
    return failures;
}

static int test_record_late_iovec_fault_type(int type) {
    static const uint8_t payload[4] = {'L', 'A', 'T', 'E'};
    const char *pair_case = type == SOCK_DGRAM ?
        "dgram_late_fault_pair" : "seqpacket_late_fault_pair";
    const char *send_case = type == SOCK_DGRAM ?
        "dgram_late_fault_send" : "seqpacket_late_fault_send";
    const char *fault_case = type == SOCK_DGRAM ?
        "dgram_late_iovec_fault" : "seqpacket_late_iovec_fault";
    const char *consume_case = type == SOCK_DGRAM ?
        "dgram_late_fault_consumes_record" :
        "seqpacket_late_fault_consumes_record";
    int pair[2] = {-1, -1};
    struct linux_iovec vectors[2];
    struct linux_msghdr header;
    uint8_t first[2] = {0, 0};
    uint8_t received[5];
    int failures = 0;

    failures += expect_result(pair_case,
        socket_pair(type | SOCK_NONBLOCK, pair), 0);
    if (pair[0] < 0) return failures;
    failures += expect_result(send_case,
        raw_syscall6(SYS_sendto, pair[0], (long)payload,
                     sizeof(payload), 0, 0, 0),
        sizeof(payload));

    vectors[0].base = (uint64_t)(uintptr_t)first;
    vectors[0].length = sizeof(first);
    vectors[1].base = 1;
    vectors[1].length = sizeof(payload) - sizeof(first);
    bytes_zero(&header, sizeof(header));
    header.iov = (uint64_t)(uintptr_t)vectors;
    header.iov_length = 2;
    failures += expect_result(fault_case,
        raw_syscall3(SYS_recvmsg, pair[1], (long)&header,
                     MSG_DONTWAIT),
        -EFAULT);

    bytes_fill(received, 0xcc, sizeof(received));
    failures += expect_result(consume_case,
        raw_syscall6(SYS_recvfrom, pair[1], (long)received,
                     sizeof(received), MSG_DONTWAIT, 0, 0),
        -EAGAIN);

    failures += close_checked(pair[0]);
    failures += close_checked(pair[1]);
    return failures;
}

static int test_record_late_iovec_fault(void) {
    int failures = 0;

    failures += test_record_late_iovec_fault_type(SOCK_DGRAM);
    failures += test_record_late_iovec_fault_type(SOCK_SEQPACKET);
    return failures;
}

static long wait_for_socket_error(long descriptor) {
    struct linux_pollfd poll_descriptor;
    long result;

    poll_descriptor.descriptor = (int32_t)descriptor;
    poll_descriptor.events = POLLERR;
    poll_descriptor.returned_events = 0;
#if defined(__x86_64__)
    result = raw_syscall3(SYS_poll, (long)&poll_descriptor, 1, 1000);
#else
    {
        struct linux_timespec timeout = {1, 0};
        result = raw_syscall5(SYS_ppoll, (long)&poll_descriptor, 1,
                              (long)&timeout, 0, 0);
    }
#endif
    if (result != 1) return result;
    return (poll_descriptor.returned_events & POLLERR) ? 1 : 0;
}

static int generate_local_udp_error(long *descriptor_out) {
    struct linux_sockaddr_in address;
    uint32_t address_length = sizeof(address);
    uint8_t payload = 'E';
    long receiver = -1;
    long sender = -1;
    long result;

    *descriptor_out = -1;
    receiver = raw_syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    if (receiver < 0) return 1;
    bytes_zero(&address, sizeof(address));
    address.family = AF_INET;
    address.address[0] = 127;
    address.address[1] = 0;
    address.address[2] = 0;
    address.address[3] = 1;
    result = raw_syscall3(SYS_bind, receiver, (long)&address,
                          sizeof(address));
    if (result < 0) goto fail;
    result = raw_syscall3(SYS_getsockname, receiver, (long)&address,
                          (long)&address_length);
    if (result < 0) goto fail;
    sender = raw_syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    if (sender < 0) goto fail;
    if (raw_syscall1(SYS_close, receiver) < 0) goto fail;
    receiver = -1;
    result = raw_syscall3(SYS_connect, sender, (long)&address,
                          sizeof(address));
    if (result < 0) goto fail;
    result = raw_syscall6(SYS_sendto, sender, (long)&payload, 1, 0, 0, 0);
    if (result != 1) goto fail;
    result = wait_for_socket_error(sender);
    if (result != 1) goto fail;
    *descriptor_out = sender;
    return 0;

fail:
    if (receiver >= 0) (void)raw_syscall1(SYS_close, receiver);
    if (sender >= 0) (void)raw_syscall1(SYS_close, sender);
    return 1;
}

static int test_so_error_copyout(void) {
    uint32_t option_length;
    int32_t option_value;
    uint8_t short_value;
    uint8_t payload = 'R';
    long descriptor = -1;
    int failures = 0;

    failures += expect_result("udp_error_setup",
        generate_local_udp_error(&descriptor), 0);
    if (descriptor < 0) return failures;

    option_length = sizeof(option_value);
    failures += expect_result("so_error_bad_copyout",
        raw_syscall5(SYS_getsockopt, descriptor, SOL_SOCKET, SO_ERROR, 1,
                     (long)&option_length), -EFAULT);
    option_value = -1;
    option_length = sizeof(option_value);
    failures += expect_result("so_error_after_failed_copy_result",
        raw_syscall5(SYS_getsockopt, descriptor, SOL_SOCKET, SO_ERROR,
                     (long)&option_value, (long)&option_length), 0);
    failures += expect_result("so_error_failed_copy_consumes_error",
        option_value, 0);

    failures += expect_result("udp_error_regenerate_send",
        raw_syscall6(SYS_sendto, descriptor, (long)&payload, 1, 0, 0, 0),
        1);
    failures += expect_result("udp_error_regenerate_wait",
        wait_for_socket_error(descriptor), 1);
    short_value = 0xcc;
    option_length = 1;
    failures += expect_result("so_error_short_copy_result",
        raw_syscall5(SYS_getsockopt, descriptor, SOL_SOCKET, SO_ERROR,
                     (long)&short_value, (long)&option_length), 0);
    failures += expect_result("so_error_short_copy_length",
        option_length, 1);
    failures += expect_result("so_error_short_copy_value",
        short_value, ECONNREFUSED);
    option_value = -1;
    option_length = sizeof(option_value);
    failures += expect_result("so_error_success_consumes_result",
        raw_syscall5(SYS_getsockopt, descriptor, SOL_SOCKET, SO_ERROR,
                     (long)&option_value, (long)&option_length), 0);
    failures += expect_result("so_error_success_consumes_value",
        option_value, 0);

    failures += close_checked(descriptor);
    return failures;
}

static int run_probe(void) {
    int failures = 0;

    failures += test_descriptor_pointer_and_flag_order();
    failures += test_accept_and_name_copy_order();
    failures += test_datagram_record_and_header_preservation();
    failures += test_record_late_iovec_fault();
    failures += test_so_error_copyout();
    putstr(failures ? "SOCKET_FIRST_OBSERVATION_ABI_PROBE_FAIL failures: " :
                      "SOCKET_FIRST_OBSERVATION_ABI_PROBE_PASS failures: ");
    putdec(failures);
    putstr(" checks: ");
    putdec((long)check_count);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    (void)raw_syscall1(SYS_exit, run_probe());
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
