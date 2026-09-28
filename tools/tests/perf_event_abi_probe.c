/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux perf software-counter ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define ENTRY_ALIGNMENT __attribute__((force_align_arg_pointer))
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_clone 56
#define SYS_ioctl 16
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_perf_event_open 298
#elif defined(__aarch64__)
#define ENTRY_ALIGNMENT
#define SYS_close 57
#define SYS_clone 220
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_ioctl 29
#define SYS_perf_event_open 241
#define SYS_wait4 260
#else
#error "perf_event_abi_probe requires a Linux 64-bit architecture"
#endif

#define PERF_TYPE_SOFTWARE 1u
#define PERF_COUNT_SW_TASK_CLOCK 1u
#define PERF_COUNT_SW_DUMMY 9u
#define PERF_FORMAT_TOTAL_TIME_ENABLED (1u << 0)
#define PERF_FORMAT_TOTAL_TIME_RUNNING (1u << 1)
#define PERF_FORMAT_ID (1u << 2)
#define PERF_FORMAT_GROUP (1u << 3)
#define PERF_ATTR_DISABLED (1ull << 0)
#define PERF_ATTR_INHERIT (1ull << 1)
#define PERF_ATTR_EXCLUDE_KERNEL (1ull << 5)
#define PERF_FLAG_FD_CLOEXEC (1u << 3)
#define PERF_IOC_ENABLE 0x2400u
#define PERF_IOC_DISABLE 0x2401u
#define PERF_IOC_RESET 0x2403u
#define PERF_IOC_ID 0x80082407u
#define PERF_IOC_FLAG_GROUP 1u
#define E2BIG 7
#define EACCES 13
#define EINVAL 22
#define ENOSPC 28
#define EPERM 1
#define SIGCHLD 17

struct perf_event_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    uint32_t wakeup_events;
    uint32_t breakpoint_type;
    uint64_t config1;
    uint64_t config2;
    uint64_t branch_sample_type;
    uint64_t sample_registers_user;
    uint32_t sample_stack_user;
    int32_t clock_id;
    uint64_t sample_registers_interrupt;
    uint32_t auxiliary_watermark;
    uint16_t sample_max_stack;
    uint16_t reserved2;
    uint32_t auxiliary_sample_size;
    uint32_t auxiliary_action;
    uint64_t signal_data;
    uint64_t config3;
    uint64_t config4;
};

_Static_assert(sizeof(struct perf_event_attr) == 144,
               "perf_event_attr probe layout mismatch");

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

static void clear_bytes(void *destination, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = 0;
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
    char buffer[32];
    unsigned long magnitude;
    unsigned long length = 0;

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[length++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude && length < sizeof(buffer));
    while (length) {
        char digit = buffer[--length];
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

static long perf_open(struct perf_event_attr *attr, int group, long flags) {
    return raw_syscall6(
        SYS_perf_event_open, (long)attr, 0, -1, group, flags, 0);
}

static void burn_cpu(void) {
    volatile uint64_t value = 1;
    for (uint64_t index = 0; index < 4000000u; ++index)
        value = value * 6364136223846793005ull + index + 1u;
    __asm__ volatile("" : : "r"(value) : "memory");
}

static int run_tests(void) {
    struct perf_event_attr attr;
    uint64_t values[16];
    uint64_t event_id = 0;
    long leader;
    long sibling;
    int failures = 0;

    clear_bytes(&attr, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = 8;
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    failures += expect("short attr", perf_open(&attr, -1, 0), -E2BIG);
    failures += expect_true("reported attr size", attr.size == sizeof(attr));

    clear_bytes(&attr, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
                       PERF_FORMAT_TOTAL_TIME_RUNNING |
                       PERF_FORMAT_ID;
    attr.flags = PERF_ATTR_DISABLED | PERF_ATTR_EXCLUDE_KERNEL;
    leader = perf_open(&attr, -1, PERF_FLAG_FD_CLOEXEC);
    if (leader == -EPERM || leader == -EACCES) {
        print_text("PERF_EVENT_ABI_PROBE_SKIP permission\n");
        return 77;
    }
    failures += expect_true("open task clock", leader >= 0);
    if (leader < 0) return failures + 1;
    clear_bytes(values, sizeof(values));
    failures += expect("disabled read", raw_syscall6(
        SYS_read, leader, (long)values, 32, 0, 0, 0), 32);
    failures += expect_true("disabled values",
                            values[0] == 0 && values[3] != 0);
    failures += expect("enable", raw_syscall6(
        SYS_ioctl, leader, PERF_IOC_ENABLE, 0, 0, 0, 0), 0);
    burn_cpu();
    failures += expect("disable", raw_syscall6(
        SYS_ioctl, leader, PERF_IOC_DISABLE, 0, 0, 0, 0), 0);
    clear_bytes(values, sizeof(values));
    failures += expect("enabled read", raw_syscall6(
        SYS_read, leader, (long)values, 32, 0, 0, 0), 32);
    failures += expect_true("task clock advanced",
                            values[0] > 0 && values[1] > 0 &&
                            values[2] > 0 && values[3] != 0);
    failures += expect("id", raw_syscall6(
        SYS_ioctl, leader, PERF_IOC_ID, (long)&event_id, 0, 0, 0), 0);
    failures += expect_true("id value", event_id == values[3]);
    failures += expect("short read", raw_syscall6(
        SYS_read, leader, (long)values, 8, 0, 0, 0), -ENOSPC);
    failures += expect("reset", raw_syscall6(
        SYS_ioctl, leader, PERF_IOC_RESET, 0, 0, 0, 0), 0);
    failures += expect("reset read", raw_syscall6(
        SYS_read, leader, (long)values, 32, 0, 0, 0), 32);
    failures += expect_true("reset value", values[0] == 0);
    (void)raw_syscall6(SYS_close, leader, 0, 0, 0, 0, 0);

    clear_bytes(&attr, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    attr.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
    attr.flags = PERF_ATTR_DISABLED | PERF_ATTR_EXCLUDE_KERNEL;
    leader = perf_open(&attr, -1, 0);
    failures += expect_true("group leader", leader >= 0);
    attr.config = PERF_COUNT_SW_DUMMY;
    attr.read_format = 0;
    sibling = leader >= 0 ? perf_open(&attr, (int)leader, 0) : -1;
    failures += expect_true("group sibling", sibling >= 0);
    if (leader >= 0 && sibling >= 0) {
        failures += expect("group enable", raw_syscall6(
            SYS_ioctl, leader, PERF_IOC_ENABLE,
            PERF_IOC_FLAG_GROUP, 0, 0, 0), 0);
        burn_cpu();
        failures += expect("group disable", raw_syscall6(
            SYS_ioctl, leader, PERF_IOC_DISABLE,
            PERF_IOC_FLAG_GROUP, 0, 0, 0), 0);
        clear_bytes(values, sizeof(values));
        failures += expect("group read", raw_syscall6(
            SYS_read, leader, (long)values, 40, 0, 0, 0), 40);
        failures += expect_true("group values",
            values[0] == 2 && values[1] > 0 && values[2] != 0 &&
            values[3] == 0 && values[4] != 0);
    }
    if (sibling >= 0)
        (void)raw_syscall6(SYS_close, sibling, 0, 0, 0, 0, 0);
    if (leader >= 0)
        (void)raw_syscall6(SYS_close, leader, 0, 0, 0, 0, 0);

    clear_bytes(&attr, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    attr.flags = PERF_ATTR_INHERIT | PERF_ATTR_EXCLUDE_KERNEL;
    leader = perf_open(&attr, -1, 0);
    failures += expect_true("inherited event", leader >= 0);
    if (leader >= 0) {
        uint64_t before = 0;
        uint64_t after = 0;
        int child_status = -1;
        long child;

        failures += expect("inherited read before", raw_syscall6(
            SYS_read, leader, (long)&before, sizeof(before),
            0, 0, 0), sizeof(before));
        child = raw_syscall6(
            SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (child == 0) {
            burn_cpu();
            burn_cpu();
            raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
            for (;;) { }
        }
        failures += expect_true("inherited fork", child > 0);
        if (child > 0) {
            failures += expect("inherited wait", raw_syscall6(
                SYS_wait4, child, (long)&child_status,
                0, 0, 0, 0), child);
            failures += expect("inherited child status", child_status, 0);
            failures += expect("inherited disable", raw_syscall6(
                SYS_ioctl, leader, PERF_IOC_DISABLE, 0, 0, 0, 0), 0);
            failures += expect("inherited read after", raw_syscall6(
                SYS_read, leader, (long)&after, sizeof(after),
                0, 0, 0), sizeof(after));
            failures += expect_true(
                "inherited child contribution", after > before);
        }
        (void)raw_syscall6(SYS_close, leader, 0, 0, 0, 0, 0);
    }

    clear_bytes(&attr, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    attr.flags = PERF_ATTR_EXCLUDE_KERNEL;
    failures += expect("invalid open flags",
        perf_open(&attr, -1, 0x10), -EINVAL);
    return failures;
}

ENTRY_ALIGNMENT void _start(void) {
    int result = run_tests();
    if (result == 77)
        raw_syscall6(SYS_exit, 77, 0, 0, 0, 0, 0);
    if (!result) print_text("PERF_EVENT_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
