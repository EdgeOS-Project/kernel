/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux BSD process accounting ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_acct 163
#define SYS_openat 257
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_exit 93
#define SYS_acct 89
#define SYS_openat 56
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "process_accounting_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define O_RDONLY 0u
#define O_WRONLY 1u
#define O_CREAT 0100u
#define O_TRUNC 01000u
#define SIGCHLD 17u
#define EFAULT 14
#define EISDIR 21

typedef uint16_t comp_t;

struct acct_v3 {
    uint8_t flag;
    uint8_t version;
    uint16_t tty;
    uint32_t exit_code;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t ppid;
    uint32_t begin_time;
    float elapsed_time;
    comp_t user_time;
    comp_t system_time;
    comp_t memory;
    comp_t input_output;
    comp_t read_write;
    comp_t minor_faults;
    comp_t major_faults;
    comp_t swaps;
    char command[16];
};

_Static_assert(sizeof(struct acct_v3) == 64u,
               "acct_v3 probe layout mismatch");

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

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_long(long value) {
    char digits[32];
    unsigned long magnitude;
    unsigned long count = 0;
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    while (count) {
        char digit = digits[--count];
        (void)raw_syscall6(SYS_write, 1, (long)&digit, 1, 0, 0, 0);
    }
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_long(actual);
    print_text(" expected=");
    print_long(expected);
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

static long spawn_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static int run_tests(void) {
    static const char accounting_path[] = "/tmp/edgeos-acct-probe.data";
    static const char directory_path[] = "/tmp";
    struct acct_v3 record;
    int status = 0;
    long descriptor;
    long child;
    long count;
    int failures = 0;

    failures += expect(
        "invalid pointer", raw_syscall6(SYS_acct, 1, 0, 0, 0, 0, 0),
        -EFAULT);
    failures += expect(
        "directory", raw_syscall6(
            SYS_acct, (long)directory_path, 0, 0, 0, 0, 0),
        -EISDIR);
    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)accounting_path,
        O_WRONLY | O_CREAT | O_TRUNC, 0600, 0, 0);
    failures += expect_true("create accounting file", descriptor >= 0);
    if (descriptor < 0) return failures + 1;
    failures += expect(
        "close accounting file",
        raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    failures += expect(
        "enable", raw_syscall6(
            SYS_acct, (long)accounting_path, 0, 0, 0, 0, 0), 0);
    child = spawn_child();
    failures += expect_true("spawn child", child >= 0);
    if (child == 0)
        (void)raw_syscall6(SYS_exit, 37, 0, 0, 0, 0, 0);
    if (child > 0) {
        failures += expect(
            "wait child",
            raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0),
            child);
        failures += expect("child wait status", status, 37 << 8);
    }
    failures += expect(
        "disable", raw_syscall6(SYS_acct, 0, 0, 0, 0, 0, 0), 0);
    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)accounting_path,
        O_RDONLY, 0, 0, 0);
    failures += expect_true("open accounting record", descriptor >= 0);
    if (descriptor < 0) return failures + 1;
    count = raw_syscall6(
        SYS_read, descriptor, (long)&record, sizeof(record), 0, 0, 0);
    failures += expect("record size", count, sizeof(record));
    failures += expect("record version", record.version & 0x7fu, 3);
    failures += expect("record exit status", record.exit_code, 37 << 8);
    failures += expect("record pid", record.pid, child);
    failures += expect_true("record command", record.command[0] != 0);
    failures += expect(
        "close record", raw_syscall6(
            SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    return failures;
}

__attribute__((noreturn)) void _start(void) {
    int failures = run_tests();
    print_text(failures ? "PROCESS_ACCOUNTING_ABI_PROBE_FAIL\n" :
                          "PROCESS_ACCOUNTING_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
