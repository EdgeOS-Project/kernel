/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 sendmsg and recvmsg compatibility ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_socket_message_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))

#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_socketpair 53
#define X32_SYS_sendmsg 518
#define X32_SYS_recvmsg 519

#define EBADF 9
#define EFAULT 14
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_CLOEXEC 02000000

struct x32_iovec {
    uint32_t base;
    uint32_t length;
};

struct x32_msghdr {
    uint32_t name;
    int32_t name_length;
    uint32_t iov;
    uint32_t iov_length;
    uint32_t control;
    uint32_t control_length;
    int32_t flags;
};

static int sockets[2];
static const char send_left[] = "so";
static const char send_right[] = "ck";
static char receive_left[4];
static char receive_right[4];
static struct x32_iovec send_vectors[2];
static struct x32_iovec receive_vectors[2];
static struct x32_msghdr send_header;
static struct x32_msghdr receive_header;

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;

    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static long x32_syscall3(long number, long a0, long a1, long a2) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, 0, 0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;

    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count, 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" expected=");
    print_number(expected);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static int expect_bytes(const char *name, const char *actual,
                        const char *expected, unsigned long length) {
    for (unsigned long index = 0; index < length; ++index) {
        if (actual[index] == expected[index]) continue;
        print_text("FAIL ");
        print_text(name);
        print_text("\n");
        return 1;
    }
    return 0;
}

static uint32_t pointer32(const void *pointer) {
    return (uint32_t)(uintptr_t)pointer;
}

START_ATTRIBUTES void _start(void) {
    int failures = 0;

    failures += expect_result(
        "socketpair", raw_syscall6(
            SYS_socketpair, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
            (long)sockets, 0, 0), 0);
    if (failures) goto finish;

    send_vectors[0].base = pointer32(send_left);
    send_vectors[0].length = 2;
    send_vectors[1].base = pointer32(send_right);
    send_vectors[1].length = 2;
    send_header.iov = pointer32(send_vectors);
    send_header.iov_length = 2;
    failures += expect_result(
        "sendmsg", x32_syscall3(
            X32_SYS_sendmsg, sockets[0], (long)&send_header, 0), 4);

    receive_vectors[0].base = pointer32(receive_left);
    receive_vectors[0].length = 2;
    receive_vectors[1].base = pointer32(receive_right);
    receive_vectors[1].length = 2;
    receive_header.name_length = 123;
    receive_header.iov = pointer32(receive_vectors);
    receive_header.iov_length = 2;
    receive_header.flags = -1;
    failures += expect_result(
        "recvmsg", x32_syscall3(
            X32_SYS_recvmsg, sockets[1], (long)&receive_header, 0), 4);
    failures += expect_bytes("recvmsg-left", receive_left, "so", 2);
    failures += expect_bytes("recvmsg-right", receive_right, "ck", 2);
    failures += expect_result(
        "recvmsg-name-length", receive_header.name_length, 123);
    failures += expect_result(
        "recvmsg-control-length", receive_header.control_length, 0);
    failures += expect_result("recvmsg-flags", receive_header.flags, 0);

    failures += expect_result(
        "bad-fd-first", x32_syscall3(
            X32_SYS_sendmsg, -1, -1, 0), -EBADF);
    failures += expect_result(
        "invalid-header", x32_syscall3(
            X32_SYS_sendmsg, sockets[0], -1, 0), -EFAULT);

    (void)raw_syscall6(SYS_close, sockets[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
finish:
    if (failures) {
        print_text("X32_SOCKET_MESSAGE_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_SOCKET_MESSAGE_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
