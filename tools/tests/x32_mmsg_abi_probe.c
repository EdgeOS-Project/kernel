/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 sendmmsg and recvmmsg compatibility ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_mmsg_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_socketpair 53
#define X32_SYS_recvmmsg 537
#define X32_SYS_sendmmsg 538
#define EINVAL 22
#define EBADF 9
#define AF_UNIX 1
#define SOCK_DGRAM 2
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

struct x32_mmsghdr {
    struct x32_msghdr header;
    uint32_t message_length;
};

struct kernel_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

static int sockets[2];
static const char send_one[] = "ab";
static const char send_two[] = "cde";
static char receive_one[4];
static char receive_two[4];
static struct x32_iovec send_vectors[2];
static struct x32_iovec receive_vectors[2];
static struct x32_mmsghdr send_messages[2];
static struct x32_mmsghdr receive_messages[2];

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

static int expect_bytes(const char *name, const char *actual,
                        const char *expected, uint32_t length) {
    for (uint32_t index = 0; index < length; ++index) {
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

static void prepare_entry(struct x32_mmsghdr *entry,
                          struct x32_iovec *vector,
                          void *buffer, uint32_t length) {
    uint8_t *bytes = (uint8_t *)entry;
    for (uint32_t index = 0; index < sizeof(*entry); ++index)
        bytes[index] = 0;
    vector->base = pointer32(buffer);
    vector->length = length;
    entry->header.iov = pointer32(vector);
    entry->header.iov_length = 1;
}

START_ATTRIBUTES void _start(void) {
    struct kernel_timespec timeout;
    int failures = 0;

    failures += expect_result(
        "socketpair", raw_syscall6(
            SYS_socketpair, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0,
            (long)sockets, 0, 0), 0);
    if (failures) goto finish;

    prepare_entry(&send_messages[0], &send_vectors[0],
                  (void *)send_one, 2);
    prepare_entry(&send_messages[1], &send_vectors[1],
                  (void *)send_two, 3);
    failures += expect_result(
        "sendmmsg", x32_syscall5(
            X32_SYS_sendmmsg, sockets[0], (long)send_messages,
            2, 0, 0), 2);
    failures += expect_result(
        "sendmmsg-length-0", send_messages[0].message_length, 2);
    failures += expect_result(
        "sendmmsg-length-1", send_messages[1].message_length, 3);

    prepare_entry(&receive_messages[0], &receive_vectors[0],
                  receive_one, sizeof(receive_one));
    prepare_entry(&receive_messages[1], &receive_vectors[1],
                  receive_two, sizeof(receive_two));
    timeout.seconds = 1;
    timeout.nanoseconds = 0;
    failures += expect_result(
        "recvmmsg", x32_syscall5(
            X32_SYS_recvmmsg, sockets[1], (long)receive_messages,
            2, 0, (long)&timeout), 2);
    failures += expect_result(
        "recvmmsg-length-0", receive_messages[0].message_length, 2);
    failures += expect_result(
        "recvmmsg-length-1", receive_messages[1].message_length, 3);
    failures += expect_bytes("recvmmsg-payload-0", receive_one, "ab", 2);
    failures += expect_bytes("recvmmsg-payload-1", receive_two, "cde", 3);
    if (timeout.seconds < 0 || timeout.seconds > 1 ||
        timeout.nanoseconds < 0 || timeout.nanoseconds >= 1000000000LL) {
        print_text("FAIL recvmmsg-timeout-writeback\n");
        ++failures;
    }

    timeout.seconds = 0;
    timeout.nanoseconds = 1000000000LL;
    failures += expect_result(
        "invalid-timeout", x32_syscall5(
            X32_SYS_recvmmsg, sockets[1], (long)receive_messages,
            1, 0, (long)&timeout), -EINVAL);
    failures += expect_result(
        "zero-vector", x32_syscall5(
            X32_SYS_sendmmsg, -1, 0, 0, 0, 0), -EBADF);

    (void)raw_syscall6(SYS_close, sockets[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
finish:
    if (failures) {
        print_text("X32_MMSG_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_MMSG_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
