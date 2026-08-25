/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 socket-option compatibility ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_socket_option_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_socketpair 53
#define X32_SYS_setsockopt 541
#define X32_SYS_getsockopt 542
#define EINVAL 22
#define EDOM 33
#define AF_UNIX 1
#define SOCK_DGRAM 2
#define SOCK_CLOEXEC 02000000
#define SOL_SOCKET 1
#define SO_PASSCRED 16
#define SO_RCVTIMEO_OLD 20
#define SO_ATTACH_FILTER 26
#define SO_RCVTIMEO_NEW 66
#define BPF_RET 0x06
#define BPF_K 0x00

struct timeval32 {
    int32_t seconds;
    int32_t microseconds;
};

struct timeval64 {
    int64_t seconds;
    int64_t microseconds;
};

struct sock_filter {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t value;
};

struct compat_sock_fprog {
    uint16_t length;
    uint16_t reserved;
    uint32_t filter;
};

static int sockets[2];
static int integer_value;
static uint32_t option_length;
static struct timeval32 short_timeout;
static struct timeval64 old_timeout;
static struct timeval64 new_timeout;
static struct sock_filter filter[] = {
    { BPF_RET | BPF_K, 0, 0, UINT32_MAX },
};
static struct compat_sock_fprog filter_program;

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

static long x32_syscall5(
    long number, long a0, long a1, long a2, long a3, long a4) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, a3, a4, 0);
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

static uint32_t pointer32(const void *pointer) {
    return (uint32_t)(uintptr_t)pointer;
}

START_ATTRIBUTES void _start(void) {
    int failures = 0;

    failures += expect_result(
        "socketpair", raw_syscall6(
            SYS_socketpair, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0,
            (long)sockets, 0, 0), 0);
    if (failures) goto finish;

    short_timeout.seconds = 1;
    short_timeout.microseconds = 252000;
    failures += expect_result(
        "short-old-timeout-rejected", x32_syscall5(
            X32_SYS_setsockopt, sockets[0], SOL_SOCKET,
            SO_RCVTIMEO_OLD, (long)&short_timeout, sizeof(short_timeout)),
        -EINVAL);

    old_timeout.seconds = 1;
    old_timeout.microseconds = 252000;
    failures += expect_result(
        "set-old-timeout", x32_syscall5(
            X32_SYS_setsockopt, sockets[0], SOL_SOCKET,
            SO_RCVTIMEO_OLD, (long)&old_timeout, sizeof(old_timeout)), 0);
    old_timeout.seconds = -1;
    old_timeout.microseconds = -1;
    option_length = sizeof(old_timeout);
    failures += expect_result(
        "get-old-timeout", x32_syscall5(
            X32_SYS_getsockopt, sockets[0], SOL_SOCKET,
            SO_RCVTIMEO_OLD, (long)&old_timeout, (long)&option_length), 0);
    failures += expect_result("old-timeout-length", option_length,
                              sizeof(old_timeout));
    failures += expect_result("old-timeout-seconds", old_timeout.seconds, 1);
    failures += expect_result("old-timeout-microseconds",
                              old_timeout.microseconds, 252000);

    new_timeout.seconds = 2;
    new_timeout.microseconds = 500000;
    failures += expect_result(
        "set-new-timeout", x32_syscall5(
            X32_SYS_setsockopt, sockets[0], SOL_SOCKET,
            SO_RCVTIMEO_NEW, (long)&new_timeout, sizeof(new_timeout)), 0);
    new_timeout.seconds = -1;
    new_timeout.microseconds = -1;
    option_length = sizeof(new_timeout);
    failures += expect_result(
        "get-new-timeout", x32_syscall5(
            X32_SYS_getsockopt, sockets[0], SOL_SOCKET,
            SO_RCVTIMEO_NEW, (long)&new_timeout, (long)&option_length), 0);
    failures += expect_result("new-timeout-length", option_length,
                              sizeof(new_timeout));
    failures += expect_result("new-timeout-seconds", new_timeout.seconds, 2);
    failures += expect_result("new-timeout-microseconds",
                              new_timeout.microseconds, 500000);

    old_timeout.seconds = 0;
    old_timeout.microseconds = 1000000;
    failures += expect_result(
        "invalid-old-timeout", x32_syscall5(
            X32_SYS_setsockopt, sockets[0], SOL_SOCKET,
            SO_RCVTIMEO_OLD, (long)&old_timeout, sizeof(old_timeout)),
        -EDOM);

    old_timeout.seconds = -1;
    old_timeout.microseconds = 0;
    failures += expect_result(
        "negative-old-timeout", x32_syscall5(
            X32_SYS_setsockopt, sockets[0], SOL_SOCKET,
            SO_RCVTIMEO_OLD, (long)&old_timeout, sizeof(old_timeout)), 0);
    option_length = sizeof(old_timeout);
    failures += expect_result(
        "get-cleared-timeout", x32_syscall5(
            X32_SYS_getsockopt, sockets[0], SOL_SOCKET,
            SO_RCVTIMEO_OLD, (long)&old_timeout, (long)&option_length), 0);
    failures += expect_result("cleared-timeout-seconds", old_timeout.seconds, 0);
    failures += expect_result("cleared-timeout-microseconds",
                              old_timeout.microseconds, 0);

    integer_value = 1;
    failures += expect_result(
        "set-integer", x32_syscall5(
            X32_SYS_setsockopt, sockets[0], SOL_SOCKET, SO_PASSCRED,
            (long)&integer_value, sizeof(integer_value)), 0);
    integer_value = 0;
    option_length = sizeof(integer_value);
    failures += expect_result(
        "get-integer", x32_syscall5(
            X32_SYS_getsockopt, sockets[0], SOL_SOCKET, SO_PASSCRED,
            (long)&integer_value, (long)&option_length), 0);
    failures += expect_result("integer-value", integer_value, 1);
    failures += expect_result("integer-length", option_length,
                              sizeof(integer_value));

    filter_program.length = 1;
    filter_program.reserved = 0;
    filter_program.filter = pointer32(filter);
    failures += expect_result(
        "attach-filter", x32_syscall5(
            X32_SYS_setsockopt, sockets[0], SOL_SOCKET, SO_ATTACH_FILTER,
            (long)&filter_program, sizeof(filter_program)), 0);
    failures += expect_result(
        "filter-native-length-rejected", x32_syscall5(
            X32_SYS_setsockopt, sockets[1], SOL_SOCKET, SO_ATTACH_FILTER,
            (long)&filter_program, 16), -EINVAL);

    (void)raw_syscall6(SYS_close, sockets[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
finish:
    if (failures) {
        print_text("X32_SOCKET_OPTION_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_SOCKET_OPTION_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
