/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux socket message-I/O ABI probe.  It validates shared
 * msghdr/iovec limits, multi-vector transfer, datagram truncation, batched
 * messages, SCM_RIGHTS delivery, and MSG_CMSG_CLOEXEC on both supported
 * 64-bit architectures.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_writev 20
#define SYS_socket 41
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_bind 49
#define SYS_fcntl 72
#define SYS_getpid 39
#define SYS_socketpair 53
#define SYS_setsockopt 54
#define SYS_getsockopt 55
#define SYS_sendmsg 46
#define SYS_recvmsg 47
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_pipe2 293
#define SYS_recvmmsg 299
#define SYS_sendmmsg 307
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_write 64
#define SYS_writev 66
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_sendto 206
#define SYS_recvfrom 207
#define SYS_setsockopt 208
#define SYS_getsockopt 209
#define SYS_sendmsg 211
#define SYS_recvmsg 212
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_recvmmsg 243
#define SYS_sendmmsg 269
#else
#error "socket_message_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22
#define ENOTSOCK 88
#define EMSGSIZE 90
#define ENOPROTOOPT 92

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_NONBLOCK 0x800
#define SOL_SOCKET 1
#define SO_PASSCRED 16
#define SO_TIMESTAMP 29
#define SCM_RIGHTS 1
#define SCM_CREDENTIALS 2
#define SCM_TIMESTAMP SO_TIMESTAMP
#define MSG_CTRUNC 0x08
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40
#define MSG_CMSG_CLOEXEC 0x40000000
#define F_GETFD 1
#define FD_CLOEXEC 1
#define SIGCHLD 17

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

struct linux_mmsghdr {
    struct linux_msghdr message;
    uint32_t length;
    uint32_t pad;
};

struct linux_cmsghdr {
    uint64_t length;
    int32_t level;
    int32_t type;
};

struct linux_ucred {
    int32_t process_id;
    uint32_t user_id;
    uint32_t group_id;
};

struct linux_sockaddr_un {
    uint16_t family;
    char path[108];
};

struct linux_timeval64 {
    int64_t seconds;
    int64_t microseconds;
};

struct linux_timespec64 {
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
    putstr(": false\n");
    return 1;
}

static void bytes_zero(void *pointer, uint64_t length) {
    uint8_t *bytes = (uint8_t *)pointer;
    for (uint64_t index = 0; index < length; ++index) bytes[index] = 0;
}

static int bytes_equal(const void *left_pointer, const void *right_pointer,
                       uint64_t length) {
    const uint8_t *left = (const uint8_t *)left_pointer;
    const uint8_t *right = (const uint8_t *)right_pointer;
    for (uint64_t index = 0; index < length; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static uint64_t cmsg_align(uint64_t length) {
    return (length + sizeof(uint64_t) - 1u) & ~(sizeof(uint64_t) - 1u);
}

static int close_if_open(long descriptor) {
    return descriptor >= 0 ? (int)raw_syscall1(SYS_close, descriptor) : 0;
}

static long socket_pair(int type, int descriptors[2]) {
    return raw_syscall4(SYS_socketpair, AF_UNIX, type, 0,
                        (long)descriptors);
}

static long unix_socket(int type) {
    return raw_syscall3(SYS_socket, AF_UNIX, type, 0);
}

static uint32_t make_abstract_address(struct linux_sockaddr_un *address,
                                      char discriminator) {
    uint32_t pid = (uint32_t)raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    bytes_zero(address, sizeof(*address));
    address->family = AF_UNIX;
    address->path[0] = 0;
    address->path[1] = 'e';
    address->path[2] = 'd';
    address->path[3] = 'g';
    address->path[4] = 'e';
    address->path[5] = discriminator;
    address->path[6] = (char)pid;
    address->path[7] = (char)(pid >> 8);
    address->path[8] = (char)(pid >> 16);
    address->path[9] = (char)(pid >> 24);
    return (uint32_t)sizeof(address->family) + 10u;
}

static long send_message(int descriptor, struct linux_msghdr *message,
                         uint32_t flags) {
    return raw_syscall3(SYS_sendmsg, descriptor, (long)message, flags);
}

static long receive_message(int descriptor, struct linux_msghdr *message,
                            uint32_t flags) {
    return raw_syscall3(SYS_recvmsg, descriptor, (long)message, flags);
}

static int test_named_datagram_sendmsg(void) {
    static const char payload[] = "notify";
    struct linux_sockaddr_un receiver_address;
    struct linux_sockaddr_un sender_address;
    struct linux_sockaddr_un observed_source;
    struct linux_iovec send_iov;
    struct linux_iovec receive_iov;
    struct linux_msghdr send_header;
    struct linux_msghdr receive_header;
    struct {
        struct linux_cmsghdr header;
        struct linux_ucred credentials;
        uint32_t padding;
    } control;
    uint32_t receiver_length;
    uint32_t sender_length;
    char received[sizeof(payload) - 1u];
    long receiver = -1;
    long sender = -1;
    int failures = 0;

    receiver_length = make_abstract_address(&receiver_address, 'r');
    sender_length = make_abstract_address(&sender_address, 's');
    receiver = unix_socket(SOCK_DGRAM | SOCK_NONBLOCK);
    sender = unix_socket(SOCK_DGRAM | SOCK_NONBLOCK);
    failures += expect_true("named_dgram_receiver", receiver >= 0);
    failures += expect_true("named_dgram_sender", sender >= 0);
    if (receiver < 0 || sender < 0) goto out;
    failures += expect_result(
        "named_dgram_bind_receiver",
        raw_syscall3(SYS_bind, receiver, (long)&receiver_address,
                     receiver_length), 0);
    failures += expect_result(
        "named_dgram_bind_sender",
        raw_syscall3(SYS_bind, sender, (long)&sender_address,
                     sender_length), 0);
    {
        int enabled = 1;
        failures += expect_result(
            "named_dgram_passcred",
            raw_syscall5(SYS_setsockopt, receiver, SOL_SOCKET, SO_PASSCRED,
                         (long)&enabled, sizeof(enabled)), 0);
    }

    send_iov.base = (uint64_t)(uintptr_t)payload;
    send_iov.length = sizeof(payload) - 1u;
    bytes_zero(&send_header, sizeof(send_header));
    send_header.name = (uint64_t)(uintptr_t)&receiver_address;
    send_header.name_length = receiver_length;
    send_header.iov = (uint64_t)(uintptr_t)&send_iov;
    send_header.iov_length = 1;
    failures += expect_result("named_dgram_sendmsg",
        send_message((int)sender, &send_header, 0), sizeof(payload) - 1u);

    bytes_zero(received, sizeof(received));
    bytes_zero(&observed_source, sizeof(observed_source));
    receive_iov.base = (uint64_t)(uintptr_t)received;
    receive_iov.length = sizeof(received);
    bytes_zero(&receive_header, sizeof(receive_header));
    bytes_zero(&control, sizeof(control));
    receive_header.name = (uint64_t)(uintptr_t)&observed_source;
    receive_header.name_length = sizeof(observed_source);
    receive_header.iov = (uint64_t)(uintptr_t)&receive_iov;
    receive_header.iov_length = 1;
    receive_header.control = (uint64_t)(uintptr_t)&control;
    receive_header.control_length = sizeof(control);
    failures += expect_result("named_dgram_recvmsg",
        receive_message((int)receiver, &receive_header, MSG_DONTWAIT),
        sizeof(payload) - 1u);
    failures += expect_true("named_dgram_payload",
        bytes_equal(received, payload, sizeof(received)));
    failures += expect_result("named_dgram_source_length",
                              receive_header.name_length, sender_length);
    failures += expect_true("named_dgram_source_address",
        bytes_equal(&observed_source, &sender_address, sender_length));
    failures += expect_result("named_dgram_control_length",
                              receive_header.control_length,
                              cmsg_align(sizeof(struct linux_cmsghdr) +
                                         sizeof(struct linux_ucred)));
    failures += expect_result("named_dgram_cred_level",
                              control.header.level, SOL_SOCKET);
    failures += expect_result("named_dgram_cred_type",
                              control.header.type, SCM_CREDENTIALS);
    failures += expect_result("named_dgram_cred_pid",
                              control.credentials.process_id,
                              raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0));

out:
    failures += close_if_open(receiver);
    failures += close_if_open(sender);
    return failures;
}

static int test_header_and_iovec_rules(void) {
    int failures = 0;
    int pair[2] = {-1, -1};
    int pipe_descriptors[2] = {-1, -1};
    struct linux_msghdr message;
    struct linux_iovec iov;
    char byte = 'x';

    failures += expect_result("send_bad_descriptor_before_header",
        raw_syscall3(SYS_sendmsg, -1, 0, 0), -EBADF);
    failures += expect_result("recv_bad_descriptor_before_header",
        raw_syscall3(SYS_recvmsg, -1, 0, MSG_DONTWAIT), -EBADF);
    failures += expect_result("message_pipe",
        raw_syscall2(SYS_pipe2, (long)pipe_descriptors, 0), 0);
    if (pipe_descriptors[0] >= 0) {
        failures += expect_result("send_non_socket_before_header",
            raw_syscall3(SYS_sendmsg, pipe_descriptors[1], 0, 0),
            -ENOTSOCK);
        failures += expect_result("recv_non_socket_before_header",
            raw_syscall3(SYS_recvmsg, pipe_descriptors[0], 0,
                         MSG_DONTWAIT), -ENOTSOCK);
    }
    failures += close_if_open(pipe_descriptors[0]);
    failures += close_if_open(pipe_descriptors[1]);

    failures += expect_result("stream_pair",
        socket_pair(SOCK_STREAM | SOCK_NONBLOCK, pair), 0);
    if (pair[0] < 0) return failures;
    failures += expect_result("send_null_header",
        raw_syscall3(SYS_sendmsg, pair[0], 0, 0), -EFAULT);
    failures += expect_result("recv_null_header",
        raw_syscall3(SYS_recvmsg, pair[0], 0, MSG_DONTWAIT), -EFAULT);

    bytes_zero(&message, sizeof(message));
    failures += expect_result("send_zero_iovec",
        send_message(pair[0], &message, 0), 0);
    failures += expect_result("recv_zero_iovec",
        receive_message(pair[1], &message, MSG_DONTWAIT), -EAGAIN);

    bytes_zero(&message, sizeof(message));
    message.iov = 1;
    message.iov_length = 1025;
    failures += expect_result("send_too_many_iovecs",
        send_message(pair[0], &message, 0), -EMSGSIZE);
    failures += expect_result("recv_too_many_iovecs",
        receive_message(pair[1], &message, MSG_DONTWAIT), -EMSGSIZE);

    bytes_zero(&iov, sizeof(iov));
    iov.length = 1;
    bytes_zero(&message, sizeof(message));
    message.iov = (uint64_t)(uintptr_t)&iov;
    message.iov_length = 1;
    failures += expect_result("send_null_iovec_base",
        send_message(pair[0], &message, 0), -EFAULT);
    failures += expect_result("recv_null_iovec_base",
        receive_message(pair[1], &message, MSG_DONTWAIT), -EAGAIN);

    iov.base = (uint64_t)(uintptr_t)&byte;
    iov.length = UINT64_MAX;
    failures += expect_result("send_iovec_overflow",
        send_message(pair[0], &message, 0), -EINVAL);
    failures += expect_result("recv_iovec_overflow",
        receive_message(pair[1], &message, MSG_DONTWAIT), -EINVAL);

    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int test_buffer_routing_and_transfer(void) {
    static const char payload[] = "buffer";
    int failures = 0;
    int pair[2] = {-1, -1};
    int pipe_descriptors[2] = {-1, -1};
    char received[sizeof(payload) - 1u];

    failures += expect_result("sendto_bad_descriptor_first",
        raw_syscall6(SYS_sendto, -1, 1, 1, 0, 1, 16), -EBADF);
    failures += expect_result("recvfrom_bad_descriptor_first",
        raw_syscall6(SYS_recvfrom, -1, 1, 1, MSG_DONTWAIT, 1, 1),
        -EBADF);
    failures += expect_result("buffer_pipe",
        raw_syscall2(SYS_pipe2, (long)pipe_descriptors, 0), 0);
    if (pipe_descriptors[0] >= 0) {
        failures += expect_result("sendto_non_socket_first",
            raw_syscall6(SYS_sendto, pipe_descriptors[1], 1, 1, 0, 1,
                         16), -ENOTSOCK);
        failures += expect_result("recvfrom_non_socket_first",
            raw_syscall6(SYS_recvfrom, pipe_descriptors[0], 1, 1,
                         MSG_DONTWAIT, 1, 1), -ENOTSOCK);
    }
    failures += close_if_open(pipe_descriptors[0]);
    failures += close_if_open(pipe_descriptors[1]);

    failures += expect_result("buffer_pair",
        socket_pair(SOCK_DGRAM | SOCK_NONBLOCK, pair), 0);
    if (pair[0] < 0) return failures;
    failures += expect_result("recvfrom_empty_defers_buffer_fault",
        raw_syscall6(SYS_recvfrom, pair[1], 1, 1, MSG_DONTWAIT, 0, 0),
        -EAGAIN);
    failures += expect_result("sendto_null_address_ignores_length",
        raw_syscall6(SYS_sendto, pair[0], (long)payload,
                     sizeof(payload) - 1u, 0, 0, 1),
        sizeof(payload) - 1u);
    bytes_zero(received, sizeof(received));
    failures += expect_result("recvfrom_payload",
        raw_syscall6(SYS_recvfrom, pair[1], (long)received,
                     sizeof(received), MSG_DONTWAIT, 0, 0),
        sizeof(received));
    failures += expect_true("recvfrom_payload_bytes",
        bytes_equal(received, payload, sizeof(received)));
    failures += expect_result("sendto_bad_address",
        raw_syscall6(SYS_sendto, pair[0], (long)payload,
                     sizeof(payload) - 1u, 0, 1, 16), -EFAULT);

    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int test_stream_vectors(void) {
    static const char expected[] = "edge-message";
    int failures = 0;
    int pair[2] = {-1, -1};
    struct linux_iovec send_iov[3];
    struct linux_iovec receive_iov[3];
    struct linux_msghdr send_header;
    struct linux_msghdr receive_header;
    char first[5];
    char second[4];
    char third[4];
    char joined[sizeof(expected) - 1u];

    failures += expect_result("vector_pair", socket_pair(SOCK_STREAM, pair), 0);
    if (pair[0] < 0) return failures;
    send_iov[0].base = (uint64_t)(uintptr_t)"edge-";
    send_iov[0].length = 5;
    send_iov[1].base = (uint64_t)(uintptr_t)"mess";
    send_iov[1].length = 4;
    send_iov[2].base = (uint64_t)(uintptr_t)"age";
    send_iov[2].length = 3;
    bytes_zero(&send_header, sizeof(send_header));
    send_header.iov = (uint64_t)(uintptr_t)send_iov;
    send_header.iov_length = 3;
    failures += expect_result("vector_send",
        send_message(pair[0], &send_header, 0), 12);

    bytes_zero(first, sizeof(first));
    bytes_zero(second, sizeof(second));
    bytes_zero(third, sizeof(third));
    receive_iov[0].base = (uint64_t)(uintptr_t)first;
    receive_iov[0].length = sizeof(first);
    receive_iov[1].base = (uint64_t)(uintptr_t)second;
    receive_iov[1].length = sizeof(second);
    receive_iov[2].base = (uint64_t)(uintptr_t)third;
    receive_iov[2].length = sizeof(third);
    bytes_zero(&receive_header, sizeof(receive_header));
    receive_header.iov = (uint64_t)(uintptr_t)receive_iov;
    receive_header.iov_length = 3;
    receive_header.flags = 0x12345678;
    failures += expect_result("vector_receive",
        receive_message(pair[1], &receive_header, 0), 12);
    for (uint32_t index = 0; index < sizeof(first); ++index)
        joined[index] = first[index];
    for (uint32_t index = 0; index < sizeof(second); ++index)
        joined[sizeof(first) + index] = second[index];
    for (uint32_t index = 0; index < 3; ++index)
        joined[sizeof(first) + sizeof(second) + index] = third[index];
    failures += expect_true("vector_payload",
        bytes_equal(joined, expected, sizeof(joined)));
    failures += expect_result("vector_name_length", receive_header.name_length, 0);
    failures += expect_result("vector_control_length",
                              (long)receive_header.control_length, 0);
    failures += expect_result("vector_output_flags", receive_header.flags, 0);

    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int test_datagram_truncation_and_batch(void) {
    static const char first_payload[] = "abcdefgh";
    static const char second_payload[] = "ijk";
    int failures = 0;
    int pair[2] = {-1, -1};
    struct linux_iovec send_iov[2];
    struct linux_iovec receive_iov[2];
    struct linux_mmsghdr send_batch[2];
    struct linux_mmsghdr receive_batch[2];
    struct linux_timespec64 timeout;
    char first_buffer[4];
    char second_buffer[8];

    failures += expect_result("batch_pair",
        socket_pair(SOCK_DGRAM | SOCK_NONBLOCK, pair), 0);
    if (pair[0] < 0) return failures;
    bytes_zero(send_batch, sizeof(send_batch));
    send_iov[0].base = (uint64_t)(uintptr_t)first_payload;
    send_iov[0].length = sizeof(first_payload) - 1u;
    send_iov[1].base = (uint64_t)(uintptr_t)second_payload;
    send_iov[1].length = sizeof(second_payload) - 1u;
    for (uint32_t index = 0; index < 2; ++index) {
        send_batch[index].message.iov =
            (uint64_t)(uintptr_t)&send_iov[index];
        send_batch[index].message.iov_length = 1;
    }
    failures += expect_result("send_batch",
        raw_syscall4(SYS_sendmmsg, pair[0], (long)send_batch, 2, 0), 2);
    failures += expect_result("send_batch_length0", send_batch[0].length, 8);
    failures += expect_result("send_batch_length1", send_batch[1].length, 3);

    bytes_zero(receive_batch, sizeof(receive_batch));
    bytes_zero(first_buffer, sizeof(first_buffer));
    bytes_zero(second_buffer, sizeof(second_buffer));
    receive_iov[0].base = (uint64_t)(uintptr_t)first_buffer;
    receive_iov[0].length = sizeof(first_buffer);
    receive_iov[1].base = (uint64_t)(uintptr_t)second_buffer;
    receive_iov[1].length = sizeof(second_buffer);
    for (uint32_t index = 0; index < 2; ++index) {
        receive_batch[index].message.iov =
            (uint64_t)(uintptr_t)&receive_iov[index];
        receive_batch[index].message.iov_length = 1;
    }
    failures += expect_result("receive_batch",
        raw_syscall5(SYS_recvmmsg, pair[1], (long)receive_batch, 2,
                     MSG_DONTWAIT | MSG_TRUNC, 0), 2);
    failures += expect_result("receive_batch_length0",
                              receive_batch[0].length, 8);
    failures += expect_result("receive_batch_length1",
                              receive_batch[1].length, 3);
    failures += expect_true("receive_batch_trunc_flag",
        (receive_batch[0].message.flags & MSG_TRUNC) != 0);
    failures += expect_true("receive_batch_first_payload",
        bytes_equal(first_buffer, first_payload, sizeof(first_buffer)));
    failures += expect_true("receive_batch_second_payload",
        bytes_equal(second_buffer, second_payload,
                    sizeof(second_payload) - 1u));

    failures += expect_result("sendmmsg_zero_vlen",
        raw_syscall4(SYS_sendmmsg, pair[0], 0, 0, 0), 0);
    failures += expect_result("recvmmsg_zero_vlen",
        raw_syscall5(SYS_recvmmsg, pair[1], 0, 0, MSG_DONTWAIT, 0), 0);
    timeout.seconds = 0;
    timeout.nanoseconds = 1000000000LL;
    failures += expect_result("recvmmsg_invalid_timeout",
        raw_syscall5(SYS_recvmmsg, pair[1], (long)receive_batch, 1,
                     MSG_DONTWAIT, (long)&timeout), -EINVAL);
    timeout.seconds = 0;
    timeout.nanoseconds = 0;
    failures += expect_result("recvmmsg_zero_timeout_nonblocking",
        raw_syscall5(SYS_recvmmsg, pair[1], (long)receive_batch, 1,
                     MSG_DONTWAIT, (long)&timeout), -EAGAIN);
    failures += expect_result("recvmmsg_zero_timeout_seconds",
                              timeout.seconds, 0);
    failures += expect_result("recvmmsg_zero_timeout_nanoseconds",
                              timeout.nanoseconds, 0);
    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int test_datagram_writev_atomicity(void) {
    static const uint32_t uid = 1000u;
    static const uint32_t gid = 1001u;
    static const char unit[] = "edge.service";
    int failures = 0;
    int pair[2] = {-1, -1};
    struct linux_iovec vectors[3];
    struct linux_iovec receive_iov;
    struct linux_msghdr receive_header;
    uint8_t expected[sizeof(uid) + sizeof(gid) + sizeof(unit) - 1u];
    uint8_t received[sizeof(expected)];
    uint32_t offset = 0;

    failures += expect_result("writev_dgram_pair",
        socket_pair(SOCK_DGRAM | SOCK_NONBLOCK, pair), 0);
    if (pair[0] < 0) return failures;
    bytes_zero(expected, sizeof(expected));
    bytes_zero(received, sizeof(received));
    for (uint32_t index = 0; index < sizeof(uid); ++index)
        expected[offset++] = ((const uint8_t *)&uid)[index];
    for (uint32_t index = 0; index < sizeof(gid); ++index)
        expected[offset++] = ((const uint8_t *)&gid)[index];
    for (uint32_t index = 0; index < sizeof(unit) - 1u; ++index)
        expected[offset++] = (uint8_t)unit[index];
    vectors[0].base = (uint64_t)(uintptr_t)&uid;
    vectors[0].length = sizeof(uid);
    vectors[1].base = (uint64_t)(uintptr_t)&gid;
    vectors[1].length = sizeof(gid);
    vectors[2].base = (uint64_t)(uintptr_t)unit;
    vectors[2].length = sizeof(unit) - 1u;
    failures += expect_result("writev_dgram_single_record",
        raw_syscall3(SYS_writev, pair[0], (long)vectors, 3),
        (long)sizeof(expected));

    receive_iov.base = (uint64_t)(uintptr_t)received;
    receive_iov.length = sizeof(received);
    bytes_zero(&receive_header, sizeof(receive_header));
    receive_header.iov = (uint64_t)(uintptr_t)&receive_iov;
    receive_header.iov_length = 1;
    failures += expect_result("writev_dgram_receive",
        receive_message(pair[1], &receive_header, MSG_DONTWAIT),
        (long)sizeof(received));
    failures += expect_true("writev_dgram_payload",
        bytes_equal(received, expected, sizeof(expected)));
    failures += expect_result("writev_dgram_no_fragments",
        receive_message(pair[1], &receive_header, MSG_DONTWAIT), -EAGAIN);

    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int test_batch_count_above_legacy_limit(void) {
    int failures = 0;
    int pair[2] = {-1, -1};
    struct linux_mmsghdr messages[65];

    failures += expect_result("large_batch_pair",
        socket_pair(SOCK_STREAM | SOCK_NONBLOCK, pair), 0);
    if (pair[0] < 0) return failures;
    bytes_zero(messages, sizeof(messages));
    failures += expect_result("sendmmsg_65_zero_messages",
        raw_syscall4(SYS_sendmmsg, pair[0], (long)messages, 65, 0), 65);
    for (uint32_t index = 0; index < 65; ++index)
        failures += expect_result("sendmmsg_zero_length",
                                  messages[index].length, 0);
    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int test_rights_and_credentials(void) {
    int failures = 0;
    int pair[2] = {-1, -1};
    int pipe_descriptors[2] = {-1, -1};
    uint8_t send_control[64];
    uint8_t receive_control[128];
    struct linux_cmsghdr *control;
    struct linux_iovec send_iov;
    struct linux_iovec receive_iov;
    struct linux_msghdr send_header;
    struct linux_msghdr receive_header;
    char send_byte = 'R';
    char receive_byte = 0;
    int32_t received_descriptor = -1;
    int one = 1;

    failures += expect_result("rights_pair", socket_pair(SOCK_DGRAM, pair), 0);
    failures += expect_result("rights_pipe",
        raw_syscall2(SYS_pipe2, (long)pipe_descriptors, 0), 0);
    if (pair[0] < 0 || pipe_descriptors[0] < 0) return failures;
    failures += expect_result("passcred_enable",
        raw_syscall5(SYS_setsockopt, pair[1], SOL_SOCKET, SO_PASSCRED,
                     (long)&one, sizeof(one)), 0);

    bytes_zero(send_control, sizeof(send_control));
    control = (struct linux_cmsghdr *)send_control;
    control->length = sizeof(*control) + sizeof(int32_t);
    control->level = SOL_SOCKET;
    control->type = SCM_RIGHTS;
    *(int32_t *)(send_control + cmsg_align(sizeof(*control))) =
        pipe_descriptors[0];
    send_iov.base = (uint64_t)(uintptr_t)&send_byte;
    send_iov.length = 1;
    bytes_zero(&send_header, sizeof(send_header));
    send_header.iov = (uint64_t)(uintptr_t)&send_iov;
    send_header.iov_length = 1;
    send_header.control = (uint64_t)(uintptr_t)send_control;
    send_header.control_length = cmsg_align(control->length);
    failures += expect_result("rights_send",
        send_message(pair[0], &send_header, 0), 1);

    bytes_zero(receive_control, sizeof(receive_control));
    receive_iov.base = (uint64_t)(uintptr_t)&receive_byte;
    receive_iov.length = 1;
    bytes_zero(&receive_header, sizeof(receive_header));
    receive_header.iov = (uint64_t)(uintptr_t)&receive_iov;
    receive_header.iov_length = 1;
    receive_header.control = (uint64_t)(uintptr_t)receive_control;
    receive_header.control_length = sizeof(receive_control);
    failures += expect_result("rights_receive",
        receive_message(pair[1], &receive_header, MSG_CMSG_CLOEXEC), 1);
    failures += expect_result("rights_payload", receive_byte, send_byte);
    failures += expect_true("rights_control_not_truncated",
        (receive_header.flags & MSG_CTRUNC) == 0);
    {
        uint64_t offset = 0;
        int found_credentials = 0;
        int found_rights = 0;
        while (offset + sizeof(struct linux_cmsghdr) <=
               receive_header.control_length) {
            control = (struct linux_cmsghdr *)(receive_control + offset);
            if (control->length < sizeof(*control) ||
                control->length > receive_header.control_length - offset)
                break;
            if (control->level == SOL_SOCKET &&
                control->type == SCM_RIGHTS &&
                control->length >= sizeof(*control) + sizeof(int32_t)) {
                received_descriptor = *(int32_t *)(
                    receive_control + offset + cmsg_align(sizeof(*control)));
                failures += expect_result("rights_cloexec",
                    raw_syscall3(SYS_fcntl, received_descriptor, F_GETFD, 0),
                    FD_CLOEXEC);
                found_rights = 1;
            }
            if (control->level == SOL_SOCKET &&
                control->type == SCM_CREDENTIALS &&
                control->length >=
                    sizeof(*control) + sizeof(struct linux_ucred)) {
                struct linux_ucred *credentials = (struct linux_ucred *)(
                    receive_control + offset + cmsg_align(sizeof(*control)));
                failures += expect_result("credentials_pid",
                    credentials->process_id, raw_syscall1(SYS_getpid, 0));
                found_credentials = 1;
            }
            offset += cmsg_align(control->length);
        }
        failures += expect_true("rights_present", found_rights);
        failures += expect_true("credentials_present", found_credentials);
    }

    failures += close_if_open(received_descriptor);
    failures += close_if_open(pipe_descriptors[0]);
    failures += close_if_open(pipe_descriptors[1]);
    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int test_sender_credentials(void) {
    int failures = 0;
    int pair[2] = {-1, -1};
    struct linux_ucred credentials;
    struct linux_cmsghdr *control;
    struct linux_iovec receive_iov;
    struct linux_msghdr receive_header;
    uint8_t control_bytes[64];
    char received = 0;
    int enabled = 1;
    int status = 0;
    long child;

    failures += expect_result("sender_credentials_pair",
        socket_pair(SOCK_DGRAM, pair), 0);
    if (pair[0] < 0) return failures;
    failures += expect_result("sender_credentials_enable",
        raw_syscall5(SYS_setsockopt, pair[1], SOL_SOCKET, SO_PASSCRED,
                     (long)&enabled, sizeof(enabled)), 0);

    child = raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    failures += expect_true("sender_credentials_clone", child >= 0);
    if (child == 0) {
        char byte = 'P';
        long result = raw_syscall3(SYS_sendto, pair[0], (long)&byte, 1);
        (void)raw_syscall1(SYS_exit, result == 1 ? 0 : 1);
        for (;;) {}
    }
    if (child < 0) goto out;

    bytes_zero(control_bytes, sizeof(control_bytes));
    receive_iov.base = (uint64_t)(uintptr_t)&received;
    receive_iov.length = 1;
    bytes_zero(&receive_header, sizeof(receive_header));
    receive_header.iov = (uint64_t)(uintptr_t)&receive_iov;
    receive_header.iov_length = 1;
    receive_header.control = (uint64_t)(uintptr_t)control_bytes;
    receive_header.control_length = sizeof(control_bytes);
    failures += expect_result("sender_credentials_receive",
        receive_message(pair[1], &receive_header, 0), 1);
    control = (struct linux_cmsghdr *)control_bytes;
    bytes_zero(&credentials, sizeof(credentials));
    if (receive_header.control_length >=
        sizeof(*control) + sizeof(credentials)) {
        const uint8_t *data = control_bytes + sizeof(*control);
        for (uint32_t index = 0; index < sizeof(credentials); ++index)
            ((uint8_t *)&credentials)[index] = data[index];
    }
    failures += expect_result("sender_credentials_level",
                              control->level, SOL_SOCKET);
    failures += expect_result("sender_credentials_type",
                              control->type, SCM_CREDENTIALS);
    failures += expect_result("sender_credentials_pid",
                              credentials.process_id, child);
    failures += expect_result("sender_credentials_wait",
        raw_syscall4(SYS_wait4, child, (long)&status, 0, 0), child);
    failures += expect_result("sender_credentials_child_status", status, 0);

out:
    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int test_receive_timestamp(void) {
    int failures = 0;
    int pair[2] = {-1, -1};
    int enabled = 1;
    uint32_t enabled_length = sizeof(enabled);
    uint8_t control_bytes[64];
    struct linux_cmsghdr *control;
    struct linux_timeval64 *timestamp;
    struct linux_iovec send_iov;
    struct linux_iovec receive_iov;
    struct linux_msghdr send_header;
    struct linux_msghdr receive_header;
    char sent = 'T';
    char received = 0;

    failures += expect_result("timestamp_pair", socket_pair(SOCK_DGRAM, pair), 0);
    if (pair[0] < 0) return failures;
    failures += expect_result("timestamp_enable",
        raw_syscall5(SYS_setsockopt, pair[1], SOL_SOCKET, SO_TIMESTAMP,
                     (long)&enabled, sizeof(enabled)), 0);
    enabled = 0;
    failures += expect_result("timestamp_get",
        raw_syscall5(SYS_getsockopt, pair[1], SOL_SOCKET, SO_TIMESTAMP,
                     (long)&enabled, (long)&enabled_length), 0);
    failures += expect_result("timestamp_get_value", enabled, 1);
    failures += expect_result("timestamp_get_length", enabled_length,
                              sizeof(enabled));

    send_iov.base = (uint64_t)(uintptr_t)&sent;
    send_iov.length = 1;
    bytes_zero(&send_header, sizeof(send_header));
    send_header.iov = (uint64_t)(uintptr_t)&send_iov;
    send_header.iov_length = 1;
    failures += expect_result("timestamp_send",
                              send_message(pair[0], &send_header, 0), 1);

    bytes_zero(control_bytes, sizeof(control_bytes));
    receive_iov.base = (uint64_t)(uintptr_t)&received;
    receive_iov.length = 1;
    bytes_zero(&receive_header, sizeof(receive_header));
    receive_header.iov = (uint64_t)(uintptr_t)&receive_iov;
    receive_header.iov_length = 1;
    receive_header.control = (uint64_t)(uintptr_t)control_bytes;
    receive_header.control_length = sizeof(control_bytes);
    failures += expect_result("timestamp_receive",
                              receive_message(pair[1], &receive_header, 0), 1);
    control = (struct linux_cmsghdr *)control_bytes;
    timestamp = (struct linux_timeval64 *)(control_bytes + sizeof(*control));
    failures += expect_true("timestamp_control_length",
        receive_header.control_length >=
            sizeof(*control) + sizeof(*timestamp));
    failures += expect_result("timestamp_control_level", control->level,
                              SOL_SOCKET);
    failures += expect_result("timestamp_control_type", control->type,
                              SCM_TIMESTAMP);
    failures += expect_true("timestamp_seconds", timestamp->seconds > 0);
    failures += expect_true("timestamp_microseconds",
        timestamp->microseconds >= 0 && timestamp->microseconds < 1000000);

    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int test_control_validation(void) {
    int failures = 0;
    int pair[2] = {-1, -1};
    uint8_t control_bytes[64];
    struct linux_cmsghdr *control =
        (struct linux_cmsghdr *)control_bytes;
    struct linux_iovec iov;
    struct linux_msghdr message;
    char byte = 'C';

    failures += expect_result("control_pair",
        socket_pair(SOCK_DGRAM | SOCK_NONBLOCK, pair), 0);
    if (pair[0] < 0) return failures;
    iov.base = (uint64_t)(uintptr_t)&byte;
    iov.length = 1;
    bytes_zero(&message, sizeof(message));
    message.iov = (uint64_t)(uintptr_t)&iov;
    message.iov_length = 1;

    message.control = 0;
    message.control_length = sizeof(*control);
    failures += expect_result("control_null_pointer",
        send_message(pair[0], &message, 0), -EFAULT);

    message.control = 1;
    failures += expect_result("control_bad_pointer",
        send_message(pair[0], &message, 0), -EFAULT);

    bytes_zero(control_bytes, sizeof(control_bytes));
    message.control = (uint64_t)(uintptr_t)control_bytes;
    message.control_length = sizeof(*control);
    control->length = sizeof(*control) - 1u;
    control->level = SOL_SOCKET;
    control->type = SCM_RIGHTS;
    failures += expect_result("control_short_header_length",
        send_message(pair[0], &message, 0), -EINVAL);

    bytes_zero(control_bytes, sizeof(control_bytes));
    message.control_length = sizeof(*control) + 1u;
    control->length = sizeof(*control) + 1u;
    control->level = SOL_SOCKET;
    control->type = SCM_RIGHTS;
    failures += expect_result("control_partial_descriptor",
        send_message(pair[0], &message, 0), 1);

    bytes_zero(control_bytes, sizeof(control_bytes));
    message.control_length = sizeof(*control);
    control->length = sizeof(*control);
    control->level = SOL_SOCKET;
    control->type = 0x7fffffff;
    failures += expect_result("control_unknown_socket_type",
        send_message(pair[0], &message, 0), -EINVAL);

    bytes_zero(control_bytes, sizeof(control_bytes));
    message.control_length = sizeof(*control);
    control->length = sizeof(*control);
    control->level = 0x7fffffff;
    control->type = 1;
    failures += expect_result("control_unknown_level",
        send_message(pair[0], &message, 0), 1);

    bytes_zero(control_bytes, sizeof(control_bytes));
    message.control_length = cmsg_align(sizeof(*control)) + 1u;
    control->length = sizeof(*control);
    control->level = SOL_SOCKET;
    control->type = SCM_RIGHTS;
    failures += expect_result("control_trailing_padding",
        send_message(pair[0], &message, 0), 1);

    failures += close_if_open(pair[0]);
    failures += close_if_open(pair[1]);
    return failures;
}

static int run_probe(void) {
    int failures = 0;
    failures += test_header_and_iovec_rules();
    failures += test_buffer_routing_and_transfer();
    failures += test_stream_vectors();
    failures += test_datagram_truncation_and_batch();
    failures += test_named_datagram_sendmsg();
    failures += test_datagram_writev_atomicity();
    failures += test_batch_count_above_legacy_limit();
    failures += test_rights_and_credentials();
    failures += test_sender_credentials();
    failures += test_receive_timestamp();
    failures += test_control_validation();
    putstr(failures ? "SOCKET_MESSAGE_ABI_PROBE_FAIL failures: " :
                      "SOCKET_MESSAGE_ABI_PROBE_PASS failures: ");
    putdec(failures);
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
