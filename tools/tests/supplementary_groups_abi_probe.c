/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code, licensed under MPL-2.0.
 *
 * This freestanding probe validates Linux getgroups/setgroups semantics at
 * the full NGROUPS_MAX boundary on x86_64 and AArch64.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_getgroups 115
#define SYS_setgroups 116
#define SYS_capget 125
#define SYS_capset 126
#define SYS_openat 257
#elif defined(__aarch64__)
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_getgroups 158
#define SYS_setgroups 159
#define SYS_capget 90
#define SYS_capset 91
#else
#error "supplementary_groups_abi_probe requires a Linux 64-bit architecture"
#endif

#define EPERM 1
#define EFAULT 14
#define EINVAL 22
#define LINUX_CAP_VERSION_3 0x20080522u
#define CAP_SETGID 6u
#define NGROUPS_MAX 65536u
#define AT_FDCWD -100

struct cap_header {
    uint32_t version;
    int32_t pid;
};

struct cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

static uint32_t group_input[NGROUPS_MAX];
static uint32_t group_output[NGROUPS_MAX];
static char proc_status[400000];

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    long result;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = argument3;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2),
          "r"(r10)
        : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    register long x3 __asm__("x3") = argument3;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall4(number, argument0, argument1, argument2, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) length++;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
}

static void putdec(long value) {
    char buffer[32];
    unsigned long magnitude;
    int index = 31;
    buffer[index] = 0;
    if (value < 0) magnitude = (unsigned long)(-(value + 1)) + 1u;
    else magnitude = (unsigned long)value;
    do {
        buffer[--index] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    if (value < 0) buffer[--index] = '-';
    putstr(&buffer[index]);
}

static void memzero(void *destination, unsigned long size) {
    unsigned char *bytes = destination;
    unsigned long index;
    for (index = 0; index < size; ++index) bytes[index] = 0;
}

static int expect_ret(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": got=");
    putdec(actual);
    putstr(" expected=");
    putdec(expected);
    putstr("\n");
    return 1;
}

static int expect_groups(const char *name, uint32_t count,
                         const uint32_t *expected) {
    uint32_t index;
    long result;
    memzero(group_output, (unsigned long)count * sizeof(group_output[0]));
    result = raw_syscall3(SYS_getgroups, count, (long)group_output, 0);
    if (expect_ret(name, result, count)) return 1;
    for (index = 0; index < count; ++index) {
        if (group_output[index] == expected[index]) continue;
        putstr(name);
        putstr(": mismatch index=");
        putdec(index);
        putstr(" got=");
        putdec(group_output[index]);
        putstr(" expected=");
        putdec(expected[index]);
        putstr("\n");
        return 1;
    }
    return 0;
}

static int proc_groups_failure(const char *detail, long value) {
    putstr("proc_status_groups: ");
    putstr(detail);
    putstr("=");
    putdec(value);
    putstr("\n");
    return 1;
}

static int expect_proc_status_groups(uint32_t count) {
    static const char path[] = "/proc/self/status";
    static const char prefix[] = "Groups:\t";
    unsigned long length = 0;
    unsigned long offset;
    unsigned long prefix_index;
    uint32_t expected = 1;
    long descriptor;

    descriptor = raw_syscall4(SYS_openat, AT_FDCWD, (long)path, 0, 0);
    if (descriptor < 0) return proc_groups_failure("open", descriptor);
    while (length < sizeof(proc_status)) {
        long result = raw_syscall3(SYS_read, descriptor,
                                   (long)&proc_status[length],
                                   sizeof(proc_status) - length);
        if (result < 0) {
            (void)raw_syscall3(SYS_close, descriptor, 0, 0);
            return proc_groups_failure("read", result);
        }
        if (!result) break;
        length += (unsigned long)result;
    }
    (void)raw_syscall3(SYS_close, descriptor, 0, 0);
    if (length == sizeof(proc_status))
        return proc_groups_failure("truncated", length);

    for (offset = 0; offset < length; ++offset) {
        if (offset && proc_status[offset - 1] != '\n') continue;
        for (prefix_index = 0; prefix[prefix_index]; ++prefix_index) {
            if (offset + prefix_index >= length ||
                proc_status[offset + prefix_index] != prefix[prefix_index])
                break;
        }
        if (!prefix[prefix_index]) break;
    }
    if (offset == length) return proc_groups_failure("missing", -1);
    offset += prefix_index;
    while (offset < length && proc_status[offset] != '\n') {
        uint32_t value = 0;
        int have_digit = 0;
        while (offset < length && proc_status[offset] == ' ') ++offset;
        while (offset < length && proc_status[offset] >= '0' &&
               proc_status[offset] <= '9') {
            have_digit = 1;
            value = value * 10u + (uint32_t)(proc_status[offset] - '0');
            ++offset;
        }
        if (!have_digit) break;
        if (expected > count || value != expected)
            return proc_groups_failure("value", value);
        ++expected;
    }
    if (offset >= length || proc_status[offset] != '\n')
        return proc_groups_failure("unterminated", offset);
    if (expected != count + 1u)
        return proc_groups_failure("count", expected - 1u);
    return 0;
}

static int drop_setgid_capability(void) {
    struct cap_header header;
    struct cap_data data[2];
    long result;
    header.version = LINUX_CAP_VERSION_3;
    header.pid = 0;
    memzero(data, sizeof(data));
    result = raw_syscall3(SYS_capget, (long)&header, (long)data, 0);
    if (result < 0) return (int)result;
    data[0].effective &= ~(1u << CAP_SETGID);
    data[0].permitted &= ~(1u << CAP_SETGID);
    return (int)raw_syscall3(SYS_capset, (long)&header, (long)data, 0);
}

static int run_probe(void) {
    static const uint32_t sorted_small[] = {100, 100, 200, 300};
    uint32_t index;
    int failures = 0;

    failures += expect_ret("getgroups_negative",
                           raw_syscall3(SYS_getgroups, -1, 0, 0), -EINVAL);
    failures += expect_ret("setgroups_too_large",
                           raw_syscall3(SYS_setgroups, NGROUPS_MAX + 1u,
                                        (long)group_input, 0), -EINVAL);
    failures += expect_ret("setgroups_null",
                           raw_syscall3(SYS_setgroups, 1, 0, 0), -EFAULT);
    group_input[0] = UINT32_MAX;
    failures += expect_ret("setgroups_invalid_gid",
                           raw_syscall3(SYS_setgroups, 1,
                                        (long)group_input, 0), -EINVAL);

    group_input[0] = 300;
    group_input[1] = 100;
    group_input[2] = 200;
    group_input[3] = 100;
    failures += expect_ret("setgroups_small",
                           raw_syscall3(SYS_setgroups, 4,
                                        (long)group_input, 0), 0);
    failures += expect_ret("getgroups_count",
                           raw_syscall3(SYS_getgroups, 0, 0, 0), 4);
    failures += expect_ret("getgroups_short",
                           raw_syscall3(SYS_getgroups, 3,
                                        (long)group_output, 0), -EINVAL);
    failures += expect_ret("getgroups_null",
                           raw_syscall3(SYS_getgroups, 4, 0, 0), -EFAULT);
    failures += expect_groups("getgroups_sorted_small", 4, sorted_small);

    for (index = 0; index < 33u; ++index)
        group_input[index] = 33u - index;
    failures += expect_ret("setgroups_over_arm64_old_limit",
                           raw_syscall3(SYS_setgroups, 33,
                                        (long)group_input, 0), 0);
    for (index = 0; index < 33u; ++index)
        group_input[index] = index + 1u;
    failures += expect_groups("getgroups_33", 33, group_input);

    for (index = 0; index < NGROUPS_MAX; ++index)
        group_input[index] = NGROUPS_MAX - index;
    failures += expect_ret("setgroups_max",
                           raw_syscall3(SYS_setgroups, NGROUPS_MAX,
                                        (long)group_input, 0), 0);
    failures += expect_ret("getgroups_max_count",
                           raw_syscall3(SYS_getgroups, 0, 0, 0), NGROUPS_MAX);
    for (index = 0; index < NGROUPS_MAX; ++index)
        group_input[index] = index + 1u;
    failures += expect_groups("getgroups_max", NGROUPS_MAX, group_input);
    failures += expect_proc_status_groups(NGROUPS_MAX);

    failures += expect_ret("setgroups_clear",
                           raw_syscall3(SYS_setgroups, 0, 0, 0), 0);
    failures += expect_ret("getgroups_empty",
                           raw_syscall3(SYS_getgroups, 0, 0, 0), 0);
    failures += expect_ret("capset_drop_setgid", drop_setgid_capability(), 0);
    failures += expect_ret("setgroups_unprivileged",
                           raw_syscall3(SYS_setgroups, 0, 0, 0), -EPERM);
    failures += expect_ret("setgroups_unprivileged_too_large",
                           raw_syscall3(SYS_setgroups, NGROUPS_MAX + 1u,
                                        0, 0), -EPERM);
    failures += expect_ret("getgroups_after_cap_drop",
                           raw_syscall3(SYS_getgroups, 0, 0, 0), 0);

    putstr("supplementary_groups_abi_probe: ");
    putstr(failures ? "FAIL\n" : "OK\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    int result = run_probe();
    (void)raw_syscall3(SYS_exit, result, 0, 0);
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
