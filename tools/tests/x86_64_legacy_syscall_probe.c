/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding x86_64 legacy syscall regression probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x86_64_legacy_syscall_probe requires x86_64"
#endif

#define SYS_write 1
#define SYS_rt_sigaction 13
#define SYS_rt_sigreturn 15
#define SYS_pause 34
#define SYS_alarm 37
#define SYS_fork 57
#define SYS_vfork 58
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_swapon 167
#define SYS_swapoff 168

#define EINTR 4
#define EFAULT 14
#define SIGALRM 14
#define SA_RESTORER UINT64_C(0x04000000)

struct linux_signal_action {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

static volatile uint64_t alarm_delivered;

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

__attribute__((naked, noreturn)) static void signal_restorer(void) {
    __asm__ volatile("mov $15, %rax\n\tsyscall");
}

__attribute__((force_align_arg_pointer))
static void alarm_handler(int signal_number) {
    if (signal_number == SIGALRM) alarm_delivered = 1;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    int position = (int)sizeof(output);

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&output[position],
                       (long)(sizeof(output) - (unsigned long)position),
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

static int wait_for_child(long child, int exit_code, const char *name) {
    int status = -1;
    int failures = 0;

    failures += expect_true(name, child > 0);
    if (child <= 0) return failures;
    failures += expect_result(
        "wait child",
        raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0), child);
    failures += expect_result(name, status, exit_code << 8);
    return failures;
}

static int test_fork(void) {
    long child = raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (child == 0) {
        (void)raw_syscall6(SYS_exit, 41, 0, 0, 0, 0, 0);
        for (;;) {}
    }
    return wait_for_child(child, 41, "fork child status");
}

static int test_vfork(void) {
    long child = raw_syscall6(SYS_vfork, 0, 0, 0, 0, 0, 0);
    if (child == 0) {
        (void)raw_syscall6(SYS_exit, 42, 0, 0, 0, 0, 0);
        for (;;) {}
    }
    return wait_for_child(child, 42, "vfork child status");
}

static int test_alarm_and_pause(void) {
    struct linux_signal_action action = {
        .handler = (uint64_t)(uintptr_t)alarm_handler,
        .flags = SA_RESTORER,
        .restorer = (uint64_t)(uintptr_t)signal_restorer,
        .mask = 0,
    };
    struct linux_signal_action old_action;
    int failures = 0;

    failures += expect_result(
        "install alarm handler",
        raw_syscall6(SYS_rt_sigaction, SIGALRM, (long)&action,
                     (long)&old_action, 8, 0, 0), 0);
    failures += expect_result(
        "alarm initial arm",
        raw_syscall6(SYS_alarm, 3, 0, 0, 0, 0, 0), 0);
    failures += expect_result(
        "alarm replacement",
        raw_syscall6(SYS_alarm, 0, 0, 0, 0, 0, 0), 3);
    alarm_delivered = 0;
    failures += expect_result(
        "alarm arm",
        raw_syscall6(SYS_alarm, 1, 0, 0, 0, 0, 0), 0);
    failures += expect_result(
        "pause signal wake",
        raw_syscall6(SYS_pause, 0, 0, 0, 0, 0, 0), -EINTR);
    failures += expect_true("alarm handler ran", alarm_delivered == 1);
    failures += expect_result(
        "alarm cancel",
        raw_syscall6(SYS_alarm, 0, 0, 0, 0, 0, 0), 0);
    failures += expect_result(
        "restore alarm handler",
        raw_syscall6(SYS_rt_sigaction, SIGALRM, (long)&old_action,
                     0, 8, 0, 0), 0);
    return failures;
}

static int test_swap_validation(void) {
    int failures = 0;
    failures += expect_result(
        "swapon null path",
        raw_syscall6(SYS_swapon, 0, 0, 0, 0, 0, 0), -EFAULT);
    failures += expect_result(
        "swapoff null path",
        raw_syscall6(SYS_swapoff, 0, 0, 0, 0, 0, 0), -EFAULT);
    return failures;
}

static int run_probe(void) {
    int failures = 0;
    failures += test_fork();
    failures += test_vfork();
    failures += test_alarm_and_pause();
    failures += test_swap_validation();
    print_text(failures ? "X86_LEGACY_SYSCALL_PROBE_FAIL\n" :
                          "X86_LEGACY_SYSCALL_PROBE_PASS\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    (void)raw_syscall6(SYS_exit, run_probe(), 0, 0, 0, 0, 0);
    for (;;) {}
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile("andq $-16, %rsp\ncall probe_entry");
}
