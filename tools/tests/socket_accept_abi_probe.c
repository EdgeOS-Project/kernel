/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux accept/accept4 ABI probe.  It validates descriptor and
 * flag error ordering, address-pointer rules, full-length truncation reports,
 * exact binary AF_UNIX peer names, and accepted descriptor flags.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_fcntl 72
#define SYS_socket 41
#define SYS_connect 42
#define SYS_accept 43
#define SYS_bind 49
#define SYS_listen 50
#define SYS_accept4 288
#define SYS_pipe2 293
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_write 64
#define SYS_exit 93
#define SYS_socket 198
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept 202
#define SYS_connect 203
#define SYS_accept4 242
#else
#error "socket_accept_abi_probe requires a Linux 64-bit architecture"
#endif

#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22
#define EBADF 9
#define ENOTSOCK 88

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_NONBLOCK 0x800
#define SOCK_CLOEXEC 0x80000
#define O_NONBLOCK 0x800
#define F_GETFD 1
#define F_GETFL 3
#define F_SETFL 4
#define FD_CLOEXEC 1

static const uint8_t server_address[] = {
    AF_UNIX, 0, 0, 'e', 'd', 'g', 'e', '-', 'a', 'c', 'c', 'e', 'p', 't'
};
static const uint8_t client_address[] = {
    AF_UNIX, 0, 0, 'e', 'd', 'g', 'e', '-', 'p', 'e', 'e', 'r', 0, 'x'
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

static int expect_bytes(const char *name, const uint8_t *actual,
                        const uint8_t *expected, uint32_t length) {
    for (uint32_t index = 0; index < length; ++index) {
        if (actual[index] == expected[index]) continue;
        putstr(name);
        putstr(": byte=");
        putdec(index);
        putstr(" actual=");
        putdec(actual[index]);
        putstr(" expected=");
        putdec(expected[index]);
        putstr("\n");
        return 1;
    }
    return 0;
}

static void bytes_fill(uint8_t *bytes, uint8_t value, uint32_t length) {
    for (uint32_t index = 0; index < length; ++index) bytes[index] = value;
}

static int close_checked(long descriptor) {
    if (descriptor < 0) return 0;
    return expect_result("close", raw_syscall1(SYS_close, descriptor), 0);
}

static long create_client(int bind_peer) {
    long descriptor = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) return descriptor;
    if (bind_peer && raw_syscall3(SYS_bind, descriptor, (long)client_address,
                                  sizeof(client_address)) < 0) {
        (void)raw_syscall1(SYS_close, descriptor);
        return -1;
    }
    if (raw_syscall3(SYS_connect, descriptor, (long)server_address,
                     sizeof(server_address)) < 0) {
        (void)raw_syscall1(SYS_close, descriptor);
        return -1;
    }
    return descriptor;
}

static int run_probe(void) {
    uint8_t returned[32];
    uint32_t returned_length;
    int pipe_descriptors[2] = {-1, -1};
    long server = -1;
    long plain_socket = -1;
    long client = -1;
    long accepted = -1;
    int failures = 0;
    long status;

    failures += expect_result("accept4_badfd_badflags",
        raw_syscall4(SYS_accept4, -1, 0, 0, 1), -EBADF);
    failures += expect_result("pipe2",
        raw_syscall2(SYS_pipe2, (long)pipe_descriptors, 0), 0);
    if (pipe_descriptors[0] >= 0) {
        failures += expect_result("accept_pipe",
            raw_syscall3(SYS_accept, pipe_descriptors[0], 0, 0), -ENOTSOCK);
        failures += expect_result("accept4_pipe_badflags",
            raw_syscall4(SYS_accept4, pipe_descriptors[0], 0, 0, 1),
            -EINVAL);
    }
    failures += close_checked(pipe_descriptors[0]);
    failures += close_checked(pipe_descriptors[1]);

    plain_socket = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (plain_socket >= 0)
        failures += expect_result("accept_not_listening",
            raw_syscall3(SYS_accept, plain_socket, 0, 0), -EINVAL);
    else
        failures += expect_result("plain_socket", plain_socket, 0);
    failures += close_checked(plain_socket);

    server = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) {
        failures += expect_result("server_socket", server, 0);
        goto out;
    }
    failures += expect_result("server_bind",
        raw_syscall3(SYS_bind, server, (long)server_address,
                     sizeof(server_address)), 0);
    failures += expect_result("server_listen",
        raw_syscall2(SYS_listen, server, 8), 0);
    failures += expect_result("accept4_badflags",
        raw_syscall4(SYS_accept4, server, 0, 0, 1), -EINVAL);

    status = raw_syscall3(SYS_fcntl, server, F_GETFL, 0);
    failures += expect_result("listener_getfl", status < 0 ? status : 0, 0);
    if (status >= 0) {
        failures += expect_result("listener_set_nonblock",
            raw_syscall3(SYS_fcntl, server, F_SETFL,
                         status | O_NONBLOCK), 0);
        failures += expect_result("accept_empty_nonblock",
            raw_syscall3(SYS_accept, server, 0, 0), -EAGAIN);
        failures += expect_result("listener_restore_flags",
            raw_syscall3(SYS_fcntl, server, F_SETFL,
                         status & ~O_NONBLOCK), 0);
    }

    client = create_client(0);
    failures += expect_result("fault_client", client < 0 ? client : 0, 0);
    if (client >= 0) {
        returned_length = sizeof(returned);
        failures += expect_result("accept_null_length",
            raw_syscall3(SYS_accept, server, (long)returned, 0), -EFAULT);
    }
    failures += close_checked(client);
    client = -1;

    client = create_client(0);
    failures += expect_result("ignored_length_client", client < 0 ? client : 0, 0);
    if (client >= 0) {
        accepted = raw_syscall3(SYS_accept, server, 0, 1);
        failures += expect_result("accept_null_address_bad_length",
                                  accepted < 0 ? accepted : 0, 0);
        failures += close_checked(accepted);
        accepted = -1;
    }
    failures += close_checked(client);
    client = -1;

    client = create_client(1);
    failures += expect_result("named_client", client < 0 ? client : 0, 0);
    if (client >= 0) {
        bytes_fill(returned, 0xcc, sizeof(returned));
        returned_length = 1;
        accepted = raw_syscall3(SYS_accept, server, (long)returned,
                                (long)&returned_length);
        failures += expect_result("accept_truncated",
                                  accepted < 0 ? accepted : 0, 0);
        failures += expect_result("accept_actual_length", returned_length,
                                  sizeof(client_address));
        failures += expect_result("accept_family_byte", returned[0], AF_UNIX);
        failures += expect_result("accept_no_overwrite", returned[1], 0xcc);
        failures += close_checked(accepted);
        accepted = -1;
    }
    failures += close_checked(client);
    client = -1;

    client = create_client(0);
    failures += expect_result("accept4_client", client < 0 ? client : 0, 0);
    if (client >= 0) {
        bytes_fill(returned, 0xcc, sizeof(returned));
        returned_length = sizeof(returned);
        accepted = raw_syscall4(SYS_accept4, server, (long)returned,
                                (long)&returned_length,
                                SOCK_NONBLOCK | SOCK_CLOEXEC);
        failures += expect_result("accept4", accepted < 0 ? accepted : 0, 0);
        if (accepted >= 0) {
            status = raw_syscall3(SYS_fcntl, accepted, F_GETFL, 0);
            failures += expect_result("accept4_nonblock",
                                      status < 0 ? status :
                                      ((status & O_NONBLOCK) != 0), 1);
            status = raw_syscall3(SYS_fcntl, accepted, F_GETFD, 0);
            failures += expect_result("accept4_cloexec",
                                      status < 0 ? status :
                                      ((status & FD_CLOEXEC) != 0), 1);
            failures += expect_result("accept4_peer_length", returned_length, 2);
            failures += expect_result("accept4_peer_family", returned[0], AF_UNIX);
        }
        failures += close_checked(accepted);
        accepted = -1;
    }
    failures += close_checked(client);
    client = -1;

    client = create_client(0);
    failures += expect_result("inheritance_client", client < 0 ? client : 0, 0);
    if (client >= 0) {
        status = raw_syscall3(SYS_fcntl, server, F_GETFL, 0);
        if (status >= 0)
            failures += expect_result("inheritance_listener_nonblock",
                raw_syscall3(SYS_fcntl, server, F_SETFL,
                             status | O_NONBLOCK), 0);
        accepted = raw_syscall3(SYS_accept, server, 0, 0);
        failures += expect_result("accept_pending_nonblock_listener",
                                  accepted < 0 ? accepted : 0, 0);
        if (accepted >= 0) {
            long accepted_flags = raw_syscall3(SYS_fcntl, accepted, F_GETFL, 0);
            failures += expect_result("accept_does_not_inherit_nonblock",
                accepted_flags < 0 ? accepted_flags :
                ((accepted_flags & O_NONBLOCK) != 0), 0);
        }
        if (status >= 0)
            failures += expect_result("inheritance_listener_restore",
                raw_syscall3(SYS_fcntl, server, F_SETFL,
                             status & ~O_NONBLOCK), 0);
        failures += close_checked(accepted);
        accepted = -1;
    }

out:
    failures += close_checked(accepted);
    failures += close_checked(client);
    failures += close_checked(server);
    putstr(failures ? "SOCKET_ACCEPT_ABI_PROBE_FAIL failures: " :
                      "SOCKET_ACCEPT_ABI_PROBE_PASS failures: ");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

void _start(void) {
    (void)raw_syscall1(SYS_exit, run_probe());
    for (;;) {}
}
