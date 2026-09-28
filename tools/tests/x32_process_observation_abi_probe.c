/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 wait and resource-usage ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_process_observation_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_exit 60
#define X32_SYS_fork 57
#define X32_SYS_wait4 61
#define X32_SYS_getrusage 98
#define X32_SYS_waitid 529
#define P_PID 1
#define WEXITED 4
#define RUSAGE_SELF 0
#define SIGCHLD 17
#define CLD_EXITED 1

struct compat_siginfo {
    int32_t signal_number;
    int32_t error;
    int32_t code;
    uint8_t payload[116];
} __attribute__((aligned(8)));

struct guarded_siginfo {
    struct compat_siginfo information;
    uint64_t guard;
};

struct rusage64 {
    int64_t words[18];
};

static struct guarded_siginfo wait_information;
static struct rusage64 wait_usage;
static struct rusage64 self_usage;
static uint32_t wait_status;

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

static long x32_syscall6(long number, long a0, long a1, long a2,
                          long a3, long a4, long a5) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, a3, a4, a5);
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

static uint32_t read_u32(const void *base, uint32_t offset) {
    const uint8_t *bytes = (const uint8_t *)base;
    return (uint32_t)bytes[offset + 0u] |
           ((uint32_t)bytes[offset + 1u] << 8) |
           ((uint32_t)bytes[offset + 2u] << 16) |
           ((uint32_t)bytes[offset + 3u] << 24);
}

START_ATTRIBUTES void _start(void) {
    long child;
    int failures = 0;

    wait_information.guard = UINT64_C(0x1122334455667788);
    child = x32_syscall6(X32_SYS_fork, 0, 0, 0, 0, 0, 0);
    if (child == 0) {
        x32_syscall6(SYS_exit, 37, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (child < 0) {
        failures += expect_result("fork-waitid", child, 0);
    } else {
        failures += expect_result(
            "waitid", x32_syscall6(
                X32_SYS_waitid, P_PID, child,
                (long)&wait_information.information, WEXITED,
                (long)&wait_usage, 0), 0);
        failures += expect_result(
            "waitid-signo", wait_information.information.signal_number,
            SIGCHLD);
        failures += expect_result(
            "waitid-code", wait_information.information.code, CLD_EXITED);
        failures += expect_result(
            "waitid-pid", read_u32(&wait_information.information, 12u),
            child);
        failures += expect_result(
            "waitid-status", read_u32(&wait_information.information, 20u),
            37);
        failures += expect_result(
            "waitid-size", (long)wait_information.guard,
            (long)UINT64_C(0x1122334455667788));
    }

    child = x32_syscall6(X32_SYS_fork, 0, 0, 0, 0, 0, 0);
    if (child == 0) {
        x32_syscall6(SYS_exit, 23, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (child < 0) {
        failures += expect_result("fork-wait4", child, 0);
    } else {
        failures += expect_result(
            "wait4", x32_syscall6(
                X32_SYS_wait4, child, (long)&wait_status, 0,
                (long)&wait_usage, 0, 0), child);
        failures += expect_result("wait4-status", wait_status, 23 << 8);
    }

    failures += expect_result(
        "getrusage", x32_syscall6(
            X32_SYS_getrusage, RUSAGE_SELF, (long)&self_usage,
            0, 0, 0, 0), 0);

    if (failures) {
        print_text("X32_PROCESS_OBSERVATION_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_PROCESS_OBSERVATION_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
