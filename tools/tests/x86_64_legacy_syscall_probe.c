/* SPDX-License-Identifier: MPL-2.0 */
/* Raw x86_64 legacy syscall regression probe for shared Linux policy. */

#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__) && defined(__linux__)

static volatile sig_atomic_t alarm_delivered;
static int failures;

static long raw_syscall6(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4,
                         long argument5) {
    register long r10 __asm__("r10") = argument3;
    register long r8 __asm__("r8") = argument4;
    register long r9 __asm__("r9") = argument5;
    long result;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long argument0, long argument1) {
    return raw_syscall6(number, argument0, argument1, 0, 0, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall6(number, argument0, 0, 0, 0, 0, 0);
}

static long raw_syscall0(long number) {
    return raw_syscall6(number, 0, 0, 0, 0, 0, 0);
}

static void fail_result(const char *operation, long result) {
    fprintf(stderr, "FAIL: %s result=%ld\n", operation, result);
    ++failures;
}

static void alarm_handler(int signal) {
    (void)signal;
    alarm_delivered = 1;
}

static void expect_child_status(long child, int expected, const char *name) {
    int status = 0;
    if (child < 0) {
        fail_result(name, child);
        return;
    }
    if (waitpid((pid_t)child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != expected) {
        fail_result(name, status);
        return;
    }
    printf("PASS: %s child=%ld status=%d\n", name, child, expected);
}

static void test_fork(void) {
    long child = raw_syscall0(SYS_fork);
    if (child == 0) _exit(41);
    expect_child_status(child, 41, "fork");
}

static void test_vfork(void) {
    long child = raw_syscall0(SYS_vfork);
    if (child == 0) _exit(42);
    expect_child_status(child, 42, "vfork");
}

static void test_alarm_and_pause(void) {
    struct sigaction action = {0};
    long result;

    action.sa_handler = alarm_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, 0) < 0) {
        fail_result("sigaction", -errno);
        return;
    }
    result = raw_syscall1(SYS_alarm, 3);
    if (result != 0) fail_result("alarm initial arm", result);
    result = raw_syscall1(SYS_alarm, 0);
    if (result != 3) fail_result("alarm replacement", result);
    alarm_delivered = 0;
    result = raw_syscall1(SYS_alarm, 1);
    if (result != 0) {
        fail_result("alarm arm", result);
        return;
    }
    result = raw_syscall0(SYS_pause);
    if (result != -EINTR || !alarm_delivered)
        fail_result("pause signal wake", result);
    else
        puts("PASS: alarm and pause signal wake");
    result = raw_syscall1(SYS_alarm, 0);
    if (result != 0) fail_result("alarm cancel", result);
}

static void test_swap_errors(void) {
    int before = failures;
    long result = raw_syscall2(SYS_swapon, 0, 0);
    if (result != -EFAULT) fail_result("swapon null path", result);
    result = raw_syscall1(SYS_swapoff, 0);
    if (result != -EFAULT) fail_result("swapoff null path", result);
    if (failures == before) puts("PASS: swap path validation");
}

#endif

int main(void) {
#if !defined(__x86_64__) || !defined(__linux__)
    puts("x86_64_legacy_syscall_probe: SKIP");
    return 0;
#else
    test_fork();
    test_vfork();
    test_alarm_and_pause();
    test_swap_errors();
    if (failures) {
        printf("x86_64_legacy_syscall_probe: FAIL failures=%d\n", failures);
        return 1;
    }
    puts("x86_64_legacy_syscall_probe: OK");
    return 0;
#endif
}
