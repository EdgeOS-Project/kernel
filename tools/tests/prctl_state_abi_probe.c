/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code, licensed under MPL-2.0.
 *
 * Libc-independent prctl ABI coverage for identical execution on Alpine
 * x86_64 and AArch64 guests.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_prctl 157
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_prctl 167
#else
#error "prctl_state_abi_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22
#define PR_SET_PDEATHSIG 1
#define PR_GET_PDEATHSIG 2
#define PR_GET_DUMPABLE 3
#define PR_SET_DUMPABLE 4
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define PR_GET_SECCOMP 21
#define PR_CAPBSET_READ 23
#define PR_SET_TIMERSLACK 29
#define PR_GET_TIMERSLACK 30
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define PR_SET_THP_DISABLE 41
#define PR_GET_THP_DISABLE 42
#define PR_THP_DISABLE_EXCEPT_ADVISED (1 << 1)
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0

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
#elif defined(__aarch64__)
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

static long prctl(long option, long argument2, long argument3,
                  long argument4, long argument5) {
    return raw_syscall6(SYS_prctl, option, argument2, argument3, argument4,
                        argument5, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text, (long)text_length(text),
                       0, 0, 0);
}

static void putdec(long value) {
    char buffer[32];
    unsigned long magnitude;
    int index = 31;
    buffer[index] = 0;
    magnitude = value < 0 ? (unsigned long)(-(value + 1)) + 1u :
                            (unsigned long)value;
    do {
        buffer[--index] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    if (value < 0) buffer[--index] = '-';
    putstr(&buffer[index]);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": got=");
    putdec(actual);
    putstr(" expected=");
    putdec(expected);
    putstr("\n");
    return 1;
}

static int bytes_equal(const char *left, const char *right,
                       unsigned long length) {
    unsigned long index;
    for (index = 0; index < length; ++index) {
        if (left[index] != right[index]) return 0;
    }
    return 1;
}

static int run_probe(void) {
    static const char requested_name[] = "edge-prctl-name-is-truncated";
    static const char expected_name[16] = "edge-prctl-name";
    char original_name[16] = {0};
    char observed_name[16] = {0};
    long original_dumpable;
    long original_timer_slack;
    long original_thp;
    long seccomp_mode;
    int32_t parent_death_signal = -1;
    int failures = 0;

    failures += expect_result("get_name_initial",
        prctl(PR_GET_NAME, (long)original_name, 0, 0, 0), 0);
    failures += expect_result("set_name",
        prctl(PR_SET_NAME, (long)requested_name, 0, 0, 0), 0);
    failures += expect_result("get_name",
        prctl(PR_GET_NAME, (long)observed_name, 0, 0, 0), 0);
    if (!bytes_equal(observed_name, expected_name, sizeof(observed_name))) {
        putstr("name_bytes: mismatch\n");
        ++failures;
    }
    failures += expect_result("get_name_null",
        prctl(PR_GET_NAME, 0, 0, 0, 0), -EFAULT);
    failures += expect_result("set_name_bad_pointer",
        prctl(PR_SET_NAME, 1, 0, 0, 0), -EFAULT);
    failures += expect_result("restore_name",
        prctl(PR_SET_NAME, (long)original_name, 0, 0, 0), 0);

    failures += expect_result("pdeath_invalid",
        prctl(PR_SET_PDEATHSIG, 65, 0, 0, 0), -EINVAL);
    failures += expect_result("pdeath_set",
        prctl(PR_SET_PDEATHSIG, 10, 0, 0, 0), 0);
    failures += expect_result("pdeath_get",
        prctl(PR_GET_PDEATHSIG, (long)&parent_death_signal, 0, 0, 0), 0);
    failures += expect_result("pdeath_value", parent_death_signal, 10);
    failures += expect_result("pdeath_clear",
        prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0), 0);

    original_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    failures += expect_result("dumpable_initial_valid",
        original_dumpable < 0 ? -1 : 0, 0);
    failures += expect_result("dumpable_set_zero",
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0), 0);
    failures += expect_result("dumpable_get_zero",
        prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
    failures += expect_result("dumpable_invalid",
        prctl(PR_SET_DUMPABLE, 2, 0, 0, 0), -EINVAL);
    failures += expect_result("dumpable_restore",
        prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0), 0);

    original_timer_slack = prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    failures += expect_result("timerslack_initial_positive",
        original_timer_slack > 0 ? 1 : 0, 1);
    failures += expect_result("timerslack_set",
        prctl(PR_SET_TIMERSLACK, 1234567, 0, 0, 0), 0);
    failures += expect_result("timerslack_get",
        prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0), 1234567);
    failures += expect_result("timerslack_reset",
        prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0), 0);
    failures += expect_result("timerslack_default",
        prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0), original_timer_slack);

    original_thp = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    failures += expect_result("thp_initial_valid", original_thp < 0 ? -1 : 0,
                              0);
    failures += expect_result("thp_disable",
        prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0), 0);
    failures += expect_result("thp_get_disabled",
        prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0), 1);
    failures += expect_result("thp_except_advised",
        prctl(PR_SET_THP_DISABLE, 1, PR_THP_DISABLE_EXCEPT_ADVISED, 0, 0),
        0);
    failures += expect_result("thp_get_except_advised",
        prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0), 3);
    failures += expect_result("thp_invalid_flags",
        prctl(PR_SET_THP_DISABLE, 1, 1, 0, 0), -EINVAL);
    failures += expect_result("thp_extra_argument",
        prctl(PR_GET_THP_DISABLE, 1, 0, 0, 0), -EINVAL);
    failures += expect_result("thp_restore",
        prctl(PR_SET_THP_DISABLE, original_thp != 0,
              original_thp == 3 ? PR_THP_DISABLE_EXCEPT_ADVISED : 0,
              0, 0), 0);

    seccomp_mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    failures += expect_result("seccomp_mode_valid",
        seccomp_mode == 0 || seccomp_mode == 2 ? 1 : 0, 1);
    failures += expect_result("capbset_read",
        prctl(PR_CAPBSET_READ, 0, 0, 0, 0), 1);
    failures += expect_result("capbset_invalid",
        prctl(PR_CAPBSET_READ, 64, 0, 0, 0), -EINVAL);
    failures += expect_result("vma_invalid_range",
        prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0, 4096,
              (long)"edge-vma"), -EINVAL);
    failures += expect_result("no_new_privileges_set",
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
    failures += expect_result("no_new_privileges_get",
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), 1);
    failures += expect_result("no_new_privileges_args",
        prctl(PR_GET_NO_NEW_PRIVS, 1, 0, 0, 0), -EINVAL);

    putstr("prctl_state_abi_probe: ");
    putstr(failures ? "FAIL\n" : "OK\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    int result = run_probe();
    (void)raw_syscall6(SYS_exit, result, 0, 0, 0, 0, 0);
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
