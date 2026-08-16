/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding raw Linux socket-address ABI probe.  It checks descriptor and
 * pointer error ordering, name truncation, exact AF_UNIX abstract names,
 * connection peer names, IPv4 ephemeral binding, and AF_UNSPEC disconnect.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_socket 41
#define SYS_connect 42
#define SYS_accept 43
#define SYS_bind 49
#define SYS_listen 50
#define SYS_getsockname 51
#define SYS_getpeername 52
#define SYS_socketpair 53
#define SYS_exit 60
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_write 64
#define SYS_exit 93
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept 202
#define SYS_connect 203
#define SYS_getsockname 204
#define SYS_getpeername 205
#else
#error "socket_address_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22
#define EADDRINUSE 98
#define ENOTSOCK 88
#define ENOTCONN 107

#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_INET 2

#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_NONBLOCK 0x800

struct linux_sockaddr_in {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t zero[8];
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

static int close_if_open(long descriptor) {
    if (descriptor < 0) return 0;
    return expect_result("close", raw_syscall1(SYS_close, descriptor), 0);
}

static int run_error_order_probe(void) {
    uint8_t address[128];
    uint16_t family = AF_UNIX;
    uint32_t length = sizeof(address);
    int pipe_descriptors[2] = {-1, -1};
    int failures = 0;
    long result;

    failures += expect_result("getsockname_badfd_null",
        raw_syscall3(SYS_getsockname, -1, 0, 0), -EBADF);
    failures += expect_result("getpeername_badfd_null",
        raw_syscall3(SYS_getpeername, -1, 0, 0), -EBADF);
    failures += expect_result("connect_badfd_null",
        raw_syscall3(SYS_connect, -1, 0, 16), -EBADF);
    failures += expect_result("connect_badfd_oversize",
        raw_syscall3(SYS_connect, -1, 0, sizeof(address) + 1u), -EBADF);
    result = raw_syscall2(SYS_pipe2, (long)pipe_descriptors, 0);
    failures += expect_result("pipe2", result, 0);
    if (result == 0) {
        failures += expect_result("bind_nonsocket",
            raw_syscall3(SYS_bind, pipe_descriptors[0], 0, 16), -ENOTSOCK);
        failures += expect_result("connect_nonsocket_fault",
            raw_syscall3(SYS_connect, pipe_descriptors[0], 0, 16), -EFAULT);
        failures += expect_result("connect_nonsocket_valid",
            raw_syscall3(SYS_connect, pipe_descriptors[0],
                         (long)&family, sizeof(family)), -ENOTSOCK);
        failures += expect_result("getsockname_nonsocket",
            raw_syscall3(SYS_getsockname, pipe_descriptors[0],
                         (long)address, (long)&length), -ENOTSOCK);
    }
    failures += close_if_open(pipe_descriptors[0]);
    failures += close_if_open(pipe_descriptors[1]);
    return failures;
}

static int run_name_copy_probe(void) {
    uint8_t address[128];
    uint32_t length;
    long descriptor;
    int failures = 0;

    descriptor = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0)
        return expect_result("name_socket", descriptor, 0);

    bytes_fill(address, 0xcc, sizeof(address));
    length = 0;
    failures += expect_result("getsockname_zero",
        raw_syscall3(SYS_getsockname, descriptor, 0, (long)&length), 0);
    failures += expect_result("getsockname_zero_length", length, 2);

    bytes_fill(address, 0xcc, sizeof(address));
    length = 1;
    failures += expect_result("getsockname_truncated",
        raw_syscall3(SYS_getsockname, descriptor, (long)address,
                     (long)&length), 0);
    failures += expect_result("getsockname_actual_length", length, 2);
    failures += expect_result("getsockname_family_byte", address[0], AF_UNIX);
    failures += expect_result("getsockname_no_overwrite", address[1], 0xcc);

    length = sizeof(address);
    failures += expect_result("getpeername_unconnected",
        raw_syscall3(SYS_getpeername, descriptor, (long)address,
                     (long)&length), -ENOTCONN);
    failures += close_if_open(descriptor);
    return failures;
}

static int run_unix_autobind_probe(void) {
    uint16_t family = AF_UNIX;
    uint8_t returned[16];
    uint32_t length = sizeof(returned);
    long descriptor;
    int failures = 0;

    descriptor = raw_syscall3(SYS_socket, AF_UNIX, SOCK_DGRAM, 0);
    if (descriptor < 0)
        return expect_result("autobind_socket", descriptor, 0);
    failures += expect_result("autobind_bind",
        raw_syscall3(SYS_bind, descriptor, (long)&family, sizeof(family)), 0);
    bytes_fill(returned, 0xcc, sizeof(returned));
    failures += expect_result("autobind_getsockname",
        raw_syscall3(SYS_getsockname, descriptor, (long)returned,
                     (long)&length), 0);
    failures += expect_result("autobind_name_length", length, 8);
    failures += expect_result("autobind_name_family", returned[0], AF_UNIX);
    failures += expect_result("autobind_name_abstract", returned[2], 0);
    for (uint32_t index = 3; index < 8; ++index) {
        uint8_t byte = returned[index];
        if ((byte >= '0' && byte <= '9') ||
            (byte >= 'a' && byte <= 'f'))
            continue;
        putstr("autobind_name_hex: byte=");
        putdec(index);
        putstr(" value=");
        putdec(byte);
        putstr("\n");
        ++failures;
    }
    failures += close_if_open(descriptor);
    return failures;
}

static int run_unix_relisten_probe(void) {
    static const uint8_t abstract_address[] = {
        AF_UNIX, 0, 0, 'e', 'd', 'g', 'e', 0,
        'r', 'e', 'l', 'i', 's', 't', 'e', 'n'
    };
    long clients[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
    long listener = -1;
    uint32_t client_count = 0;
    uint32_t initial_count = 0;
    uint32_t additional_count = 0;
    int initial_stopped = 0;
    int additional_stopped = 0;
    int failures = 0;

    listener = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0)
        return expect_result("relisten_socket", listener, 0);
    failures += expect_result("relisten_bind",
        raw_syscall3(SYS_bind, listener, (long)abstract_address,
                     sizeof(abstract_address)), 0);
    failures += expect_result("relisten_initial",
        raw_syscall2(SYS_listen, listener, 1), 0);

    while (client_count < 8u) {
        long client = raw_syscall3(
            SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        long result;

        if (client < 0) {
            failures += expect_result(
                "relisten_initial_client", client, 0);
            break;
        }
        result = raw_syscall3(
            SYS_connect, client, (long)abstract_address,
            sizeof(abstract_address));
        if (result == 0) {
            clients[client_count++] = client;
            ++initial_count;
            continue;
        }
        failures += expect_result(
            "relisten_initial_stop", result, -EAGAIN);
        failures += close_if_open(client);
        initial_stopped = 1;
        break;
    }
    failures += expect_result(
        "relisten_initial_capacity", initial_count, 2);
    failures += expect_result(
        "relisten_initial_stopped", initial_stopped, 1);
    failures += expect_result("relisten_expand",
        raw_syscall2(SYS_listen, listener, 4), 0);

    while (client_count < 8u) {
        long client = raw_syscall3(
            SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        long result;

        if (client < 0) {
            failures += expect_result(
                "relisten_additional_client", client, 0);
            break;
        }
        result = raw_syscall3(
            SYS_connect, client, (long)abstract_address,
            sizeof(abstract_address));
        if (result == 0) {
            clients[client_count++] = client;
            ++additional_count;
            continue;
        }
        failures += expect_result(
            "relisten_additional_stop", result, -EAGAIN);
        failures += close_if_open(client);
        additional_stopped = 1;
        break;
    }
    failures += expect_result(
        "relisten_additional_capacity", additional_count, 3);
    failures += expect_result(
        "relisten_total_capacity", client_count, 5);
    failures += expect_result(
        "relisten_additional_stopped", additional_stopped, 1);

    failures += close_if_open(listener);
    for (uint32_t index = 0; index < client_count; ++index)
        failures += close_if_open(clients[index]);
    return failures;
}

static int run_unix_address_probe(void) {
    static const uint8_t abstract_address[] = {
        AF_UNIX, 0, 0, 'e', 'd', 'g', 'e', 0, 'a', 'b', 'i'
    };
    uint8_t returned[128];
    uint32_t length;
    long server = -1;
    long duplicate = -1;
    long client = -1;
    long accepted = -1;
    int failures = 0;

    server = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    duplicate = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    client = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (server < 0 || duplicate < 0 || client < 0) {
        failures += expect_result("unix_server_socket", server < 0 ? server : 0, 0);
        failures += expect_result("unix_duplicate_socket", duplicate < 0 ? duplicate : 0, 0);
        failures += expect_result("unix_client_socket", client < 0 ? client : 0, 0);
        goto out;
    }
    failures += expect_result("unix_bind",
        raw_syscall3(SYS_bind, server, (long)abstract_address,
                     sizeof(abstract_address)), 0);
    failures += expect_result("unix_duplicate_bind",
        raw_syscall3(SYS_bind, duplicate, (long)abstract_address,
                     sizeof(abstract_address)), -EADDRINUSE);
    failures += expect_result("unix_listen",
        raw_syscall2(SYS_listen, server, 4), 0);
    failures += expect_result("unix_connect",
        raw_syscall3(SYS_connect, client, (long)abstract_address,
                     sizeof(abstract_address)), 0);
    accepted = raw_syscall3(SYS_accept, server, 0, 0);
    if (accepted < 0) {
        failures += expect_result("unix_accept", accepted, 0);
        goto out;
    }

    bytes_fill(returned, 0xcc, sizeof(returned));
    length = sizeof(returned);
    failures += expect_result("unix_server_getsockname",
        raw_syscall3(SYS_getsockname, server, (long)returned,
                     (long)&length), 0);
    failures += expect_result("unix_server_name_length", length,
                              sizeof(abstract_address));
    failures += expect_bytes("unix_server_name", returned, abstract_address,
                             sizeof(abstract_address));

    bytes_fill(returned, 0xcc, sizeof(returned));
    length = sizeof(returned);
    failures += expect_result("unix_client_getpeername",
        raw_syscall3(SYS_getpeername, client, (long)returned,
                     (long)&length), 0);
    failures += expect_result("unix_client_peer_length", length,
                              sizeof(abstract_address));
    failures += expect_bytes("unix_client_peer", returned, abstract_address,
                             sizeof(abstract_address));

    bytes_fill(returned, 0xcc, sizeof(returned));
    length = sizeof(returned);
    failures += expect_result("unix_accepted_getsockname",
        raw_syscall3(SYS_getsockname, accepted, (long)returned,
                     (long)&length), 0);
    failures += expect_result("unix_accepted_name_length", length,
                              sizeof(abstract_address));
    failures += expect_bytes("unix_accepted_name", returned, abstract_address,
                             sizeof(abstract_address));

    bytes_fill(returned, 0xcc, sizeof(returned));
    length = sizeof(returned);
    failures += expect_result("unix_accepted_getpeername",
        raw_syscall3(SYS_getpeername, accepted, (long)returned,
                     (long)&length), 0);
    failures += expect_result("unix_accepted_peer_length", length, 2);
    failures += expect_result("unix_accepted_peer_family", returned[0], AF_UNIX);

out:
    failures += close_if_open(accepted);
    failures += close_if_open(client);
    failures += close_if_open(duplicate);
    failures += close_if_open(server);
    return failures;
}

static int run_ipv4_probe(void) {
    struct linux_sockaddr_in local = {AF_INET, 0, 0x0100007f, {0}};
    struct linux_sockaddr_in peer = {AF_INET, 0x0900, 0x0100007f, {0}};
    struct linux_sockaddr_in returned;
    struct linux_sockaddr_in unspec = {AF_UNSPEC, 0, 0, {0}};
    uint32_t length;
    long descriptor;
    int failures = 0;

    descriptor = raw_syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    if (descriptor < 0)
        return expect_result("ipv4_socket", descriptor, 0);
    failures += expect_result("ipv4_bind",
        raw_syscall3(SYS_bind, descriptor, (long)&local, sizeof(local)), 0);
    bytes_fill((uint8_t *)&returned, 0xcc, sizeof(returned));
    length = 1;
    failures += expect_result("ipv4_getsockname_truncated",
        raw_syscall3(SYS_getsockname, descriptor, (long)&returned,
                     (long)&length), 0);
    failures += expect_result("ipv4_name_actual_length", length, sizeof(returned));
    failures += expect_result("ipv4_name_family_byte",
                              ((uint8_t *)&returned)[0], AF_INET);

    bytes_fill((uint8_t *)&returned, 0, sizeof(returned));
    length = sizeof(returned);
    failures += expect_result("ipv4_getsockname",
        raw_syscall3(SYS_getsockname, descriptor, (long)&returned,
                     (long)&length), 0);
    failures += expect_result("ipv4_name_length", length, sizeof(returned));
    failures += expect_result("ipv4_name_family", returned.family, AF_INET);
    if (!returned.port) {
        putstr("ipv4_name_port: zero ephemeral port\n");
        ++failures;
    }

    failures += expect_result("ipv4_connect",
        raw_syscall3(SYS_connect, descriptor, (long)&peer, sizeof(peer)), 0);
    length = sizeof(returned);
    failures += expect_result("ipv4_getpeername",
        raw_syscall3(SYS_getpeername, descriptor, (long)&returned,
                     (long)&length), 0);
    failures += expect_result("ipv4_peer_port", returned.port, peer.port);
    failures += expect_result("ipv4_disconnect",
        raw_syscall3(SYS_connect, descriptor, (long)&unspec, sizeof(unspec)), 0);
    length = sizeof(returned);
    failures += expect_result("ipv4_peer_after_disconnect",
        raw_syscall3(SYS_getpeername, descriptor, (long)&returned,
                     (long)&length), -ENOTCONN);
    failures += close_if_open(descriptor);
    return failures;
}

static int run_probe(void) {
    int failures = 0;
    failures += run_error_order_probe();
    failures += run_name_copy_probe();
    failures += run_unix_autobind_probe();
    failures += run_unix_relisten_probe();
    failures += run_unix_address_probe();
    failures += run_ipv4_probe();
    putstr(failures ? "SOCKET_ADDRESS_ABI_PROBE_FAIL failures: " :
                      "SOCKET_ADDRESS_ABI_PROBE_PASS failures: ");
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
