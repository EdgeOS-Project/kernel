/* SPDX-License-Identifier: MPL-2.0 */
/* Linux POSIX message queue ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_getpid 39
#define SYS_exit 60
#define SYS_mq_open 240
#define SYS_mq_unlink 241
#define SYS_mq_timedsend 242
#define SYS_mq_timedreceive 243
#define SYS_mq_notify 244
#define SYS_mq_getsetattr 245
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_close 57
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_mq_open 180
#define SYS_mq_unlink 181
#define SYS_mq_timedsend 182
#define SYS_mq_timedreceive 183
#define SYS_mq_notify 184
#define SYS_mq_getsetattr 185
#else
#error "posix_mq_abi_probe requires a Linux 64-bit architecture"
#endif

#define EAGAIN 11
#define EBADF 9
#define EMSGSIZE 90
#define O_CREAT 00000100
#define O_EXCL 00000200
#define O_RDWR 2
#define O_NONBLOCK 00004000

struct linux_mq_attr {
    int64_t mq_flags;
    int64_t mq_maxmsg;
    int64_t mq_msgsize;
    int64_t mq_curmsgs;
};

struct linux_sigevent64 {
    uint64_t value;
    int32_t signal;
    int32_t notify;
    uint8_t padding[48];
};

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
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
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#endif
}

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = (unsigned char)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned long length) {
    unsigned char *output = destination;
    const unsigned char *input = source;
    for (unsigned long index = 0; index < length; ++index)
        output[index] = input[index];
    return destination;
}

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char digits[24];
    unsigned long magnitude;
    int position = (int)sizeof(digits);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&digits[position],
                       (long)(sizeof(digits) - (unsigned long)position),
                       0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static void append_number(char *destination, unsigned long value) {
    char reversed[24];
    unsigned int count = 0;
    unsigned int offset = 0;
    while (destination[offset]) ++offset;
    do {
        reversed[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    while (count) destination[offset++] = reversed[--count];
    destination[offset] = 0;
}

static int run_tests(void) {
    struct linux_mq_attr create = {
        .mq_maxmsg = 3,
        .mq_msgsize = 16,
    };
    struct linux_mq_attr current;
    struct linux_mq_attr replacement = {.mq_flags = O_NONBLOCK};
    struct linux_sigevent64 event = {.notify = 1};
    char name[48] = "edge-posix-mq-";
    char receive[16] = {0};
    uint32_t priority = 0;
    long descriptor;
    int failures = 0;

    append_number(name, (unsigned long)raw_syscall6(
        SYS_getpid, 0, 0, 0, 0, 0, 0));
    descriptor = raw_syscall6(
        SYS_mq_open, (long)name, O_CREAT | O_EXCL | O_RDWR,
        0600, (long)&create, 0, 0);
    failures += expect_true("create queue", descriptor >= 0);
    if (descriptor < 0) return failures;
    failures += expect_result("notify none",
        raw_syscall6(SYS_mq_notify, descriptor, (long)&event,
                     0, 0, 0, 0), 0);
    failures += expect_result("send low",
        raw_syscall6(SYS_mq_timedsend, descriptor, (long)"low",
                     3, 1, 0, 0), 0);
    failures += expect_result("send high",
        raw_syscall6(SYS_mq_timedsend, descriptor, (long)"high",
                     4, 7, 0, 0), 0);
    memset(&current, 0, sizeof(current));
    failures += expect_result("get attributes",
        raw_syscall6(SYS_mq_getsetattr, descriptor, 0,
                     (long)&current, 0, 0, 0), 0);
    failures += expect_true("attribute contents",
        current.mq_maxmsg == 3 && current.mq_msgsize == 16 &&
        current.mq_curmsgs == 2);
    failures += expect_result("receive high",
        raw_syscall6(SYS_mq_timedreceive, descriptor, (long)receive,
                     sizeof(receive), (long)&priority, 0, 0), 4);
    failures += expect_true("priority ordering",
        priority == 7 && receive[0] == 'h' && receive[3] == 'h');
    failures += expect_result("set nonblock",
        raw_syscall6(SYS_mq_getsetattr, descriptor, (long)&replacement,
                     0, 0, 0, 0), 0);
    failures += expect_result("receive low",
        raw_syscall6(SYS_mq_timedreceive, descriptor, (long)receive,
                     sizeof(receive), (long)&priority, 0, 0), 3);
    failures += expect_result("empty nonblock",
        raw_syscall6(SYS_mq_timedreceive, descriptor, (long)receive,
                     sizeof(receive), (long)&priority, 0, 0), -EAGAIN);
    failures += expect_result("small buffer",
        raw_syscall6(SYS_mq_timedreceive, descriptor, (long)receive,
                     8, 0, 0, 0), -EMSGSIZE);
    failures += expect_result("unlink",
        raw_syscall6(SYS_mq_unlink, (long)name, 0, 0, 0, 0, 0), 0);
    failures += expect_result("close",
        raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    failures += expect_result("closed descriptor",
        raw_syscall6(SYS_mq_getsetattr, descriptor, 0,
                     (long)&current, 0, 0, 0), -EBADF);
    return failures;
}

void _start(void) {
    int failures = run_tests();
    if (failures) {
        print_text("posix-mq-abi: FAIL failures=");
        print_number(failures);
        print_text("\n");
    } else {
        print_text("posix-mq-abi: PASS\n");
    }
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
