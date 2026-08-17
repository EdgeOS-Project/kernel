/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for alternate signal-stack state and delivery.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_rt_sigaction 13
#define SYS_rt_sigreturn 15
#define SYS_getpid 39
#define SYS_exit 60
#define SYS_kill 62
#define SYS_sigaltstack 131
#define LINUX_MINSIGSTKSZ 2048u
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_kill 129
#define SYS_sigaltstack 132
#define SYS_rt_sigaction 134
#define SYS_rt_sigreturn 139
#define SYS_getpid 172
#define LINUX_MINSIGSTKSZ 5120u
#else
#error "signal_altstack_abi_probe requires a Linux 64-bit architecture"
#endif

#define EPERM 1
#define ENOMEM 12
#define EFAULT 14
#define EINVAL 22
#define SIGUSR1 10
#define SA_RESTORER UINT64_C(0x04000000)
#define SA_ONSTACK UINT64_C(0x08000000)
#define SA_SIGINFO UINT64_C(0x00000004)
#define SS_ONSTACK 1u
#define SS_DISABLE 2u
#define SS_AUTODISARM 0x80000000u

struct linux_signal_action {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

struct linux_stack {
    uint64_t sp;
    int32_t flags;
    uint32_t padding;
    uint64_t size;
};

struct linux_ucontext_prefix {
    uint64_t flags;
    uint64_t link;
    struct linux_stack stack;
};

static uint8_t alternate_stack[16384] __attribute__((aligned(16)));
static volatile long handler_query_result;
static volatile long handler_change_result;
static volatile uint64_t handler_stack_pointer;
static volatile int32_t handler_stack_flags;
static volatile uint32_t handler_phase;

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
    long result;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(a0), "S"(a1), "d"(a2), "r"(r10),
          "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall4(long number, long a0, long a1, long a2, long a3) {
    return raw_syscall6(number, a0, a1, a2, a3, 0, 0);
}

static long raw_syscall3(long number, long a0, long a1, long a2) {
    return raw_syscall6(number, a0, a1, a2, 0, 0, 0);
}

static long raw_syscall2(long number, long a0, long a1) {
    return raw_syscall6(number, a0, a1, 0, 0, 0, 0);
}

static long raw_syscall1(long number, long a0) {
    return raw_syscall6(number, a0, 0, 0, 0, 0, 0);
}

__attribute__((naked, noreturn)) static void signal_restorer(void) {
#if defined(__x86_64__)
    __asm__ __volatile__("mov $15, %rax\n\tsyscall");
#else
    __asm__ __volatile__("mov x8, #139\n\tsvc #0");
#endif
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
static void handle_usr1(int signal, void *information, void *context_address) {
    volatile uint8_t stack_marker = 0;
    struct linux_stack observed = {0, 0, 0, 0};
    struct linux_stack disabled = {0, SS_DISABLE, 0, 0};
    struct linux_ucontext_prefix *context =
        (struct linux_ucontext_prefix *)context_address;
    (void)information;
    if (signal != SIGUSR1) return;
    handler_stack_pointer = (uint64_t)(uintptr_t)&stack_marker;
    handler_query_result =
        raw_syscall2(SYS_sigaltstack, 0, (long)&observed);
    handler_stack_flags = observed.flags;
    handler_change_result = handler_phase == 1u ?
        raw_syscall2(SYS_sigaltstack, (long)&disabled, 0) : 0;
    if (handler_phase == 3u && context) {
        context->stack.flags = 4;
        context->stack.size = 1;
    }
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text, (long)text_length(text));
}

static void putdec(long value) {
    char buffer[24];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        putstr("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    if (!magnitude) {
        putstr("0");
        return;
    }
    while (magnitude && position) {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    }
    (void)raw_syscall3(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned)position));
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": result=");
    putdec(actual);
    putstr(" expected=");
    putdec(expected);
    putstr("\n");
    return 1;
}

static int test_signal_altstack(void) {
    struct linux_signal_action old_action;
    struct linux_signal_action action;
    struct linux_stack observed;
    struct linux_stack configured;
    struct linux_stack invalid;
    struct linux_stack disabled = {0, SS_DISABLE, 0, 0};
    uint64_t stack_start = (uint64_t)(uintptr_t)alternate_stack;
    uint64_t stack_end = stack_start + sizeof(alternate_stack);
    long pid = raw_syscall1(SYS_getpid, 0);
    int failures = 0;

    observed.sp = UINT64_MAX;
    observed.flags = -1;
    observed.padding = UINT32_MAX;
    observed.size = UINT64_MAX;
    failures += expect_result("query_initial",
        raw_syscall2(SYS_sigaltstack, 0, (long)&observed), 0);
    failures += expect_result("initial_flags", observed.flags, SS_DISABLE);
    failures += expect_result("initial_sp", (long)observed.sp, 0);
    failures += expect_result("initial_size", (long)observed.size, 0);

    configured.sp = stack_start;
    configured.flags = 0;
    configured.padding = 0;
    configured.size = sizeof(alternate_stack);
    failures += expect_result("old_pointer_fault_prevents_update",
        raw_syscall2(SYS_sigaltstack, (long)&configured, 1), -EFAULT);
    observed.flags = 0;
    failures += expect_result("query_after_old_fault",
        raw_syscall2(SYS_sigaltstack, 0, (long)&observed), 0);
    failures += expect_result("old_fault_committed_new_stack",
                              observed.flags, 0);
    failures += expect_result("new_pointer_fault",
        raw_syscall2(SYS_sigaltstack, 1, 0), -EFAULT);

    invalid = configured;
    invalid.flags = SS_ONSTACK;
    failures += expect_result("accept_onstack_mode",
        raw_syscall2(SYS_sigaltstack, (long)&invalid, 0), 0);
    observed.flags = -1;
    failures += expect_result("query_sanitized_onstack_mode",
        raw_syscall2(SYS_sigaltstack, 0, (long)&observed), 0);
    failures += expect_result("sanitized_onstack_mode", observed.flags, 0);
    invalid.flags = SS_DISABLE | SS_AUTODISARM;
    failures += expect_result("accept_disable_autodisarm",
        raw_syscall2(SYS_sigaltstack, (long)&invalid, 0), 0);
    observed.flags = -1;
    failures += expect_result("query_disable_autodisarm",
        raw_syscall2(SYS_sigaltstack, 0, (long)&observed), 0);
    failures += expect_result("disable_autodisarm_flags",
        (uint32_t)observed.flags, SS_DISABLE | SS_AUTODISARM);
    invalid.flags = 4;
    failures += expect_result("reject_unknown_flags",
        raw_syscall2(SYS_sigaltstack, (long)&invalid, 0), -EINVAL);
    invalid.flags = 0;
    invalid.size = LINUX_MINSIGSTKSZ - 1u;
    failures += expect_result("reject_small_stack",
        raw_syscall2(SYS_sigaltstack, (long)&invalid, 0), -ENOMEM);
    invalid.sp = UINT64_MAX - sizeof(alternate_stack) + 2u;
    invalid.size = sizeof(alternate_stack);
    failures += expect_result("accept_unchecked_stack_address",
        raw_syscall2(SYS_sigaltstack, (long)&invalid, 0), 0);

    failures += expect_result("install_stack",
        raw_syscall2(SYS_sigaltstack, (long)&configured, 0), 0);
    observed.sp = 0;
    observed.flags = -1;
    observed.size = 0;
    failures += expect_result("query_installed",
        raw_syscall2(SYS_sigaltstack, 0, (long)&observed), 0);
    failures += expect_result("installed_sp", (long)observed.sp,
                              (long)configured.sp);
    failures += expect_result("installed_size", (long)observed.size,
                              (long)configured.size);
    failures += expect_result("installed_flags", observed.flags, 0);

    action.handler = (uint64_t)(uintptr_t)handle_usr1;
    action.flags = SA_ONSTACK | SA_RESTORER | SA_SIGINFO;
    action.restorer = (uint64_t)(uintptr_t)signal_restorer;
    action.mask = 0;
    failures += expect_result("install_handler",
        raw_syscall4(SYS_rt_sigaction, SIGUSR1, (long)&action,
                     (long)&old_action, 8), 0);
    handler_phase = 1;
    handler_query_result = -1;
    handler_change_result = -1;
    handler_stack_pointer = 0;
    handler_stack_flags = -1;
    failures += expect_result("deliver_on_stack",
        raw_syscall2(SYS_kill, pid, SIGUSR1), 0);
    failures += expect_result("handler_query", handler_query_result, 0);
    failures += expect_result("handler_flags", handler_stack_flags,
                              SS_ONSTACK);
    failures += expect_result("handler_change_rejected",
                              handler_change_result, -EPERM);
    failures += expect_result("handler_used_altstack",
        handler_stack_pointer >= stack_start &&
        handler_stack_pointer < stack_end, 1);

    configured.flags = SS_AUTODISARM;
    failures += expect_result("install_autodisarm_stack",
        raw_syscall2(SYS_sigaltstack, (long)&configured, 0), 0);
    handler_phase = 2;
    handler_query_result = -1;
    handler_stack_flags = -1;
    failures += expect_result("deliver_autodisarm",
        raw_syscall2(SYS_kill, pid, SIGUSR1), 0);
    failures += expect_result("autodisarm_handler_query",
                              handler_query_result, 0);
    failures += expect_result("autodisarm_handler_flags",
                              handler_stack_flags, SS_DISABLE);
    observed.flags = -1;
    failures += expect_result("query_restored_autodisarm",
        raw_syscall2(SYS_sigaltstack, 0, (long)&observed), 0);
    failures += expect_result("restored_autodisarm_flags",
                              (uint32_t)observed.flags, SS_AUTODISARM);

    configured.flags = 0;
    failures += expect_result("install_restore_test_stack",
        raw_syscall2(SYS_sigaltstack, (long)&configured, 0), 0);
    action.flags = SA_RESTORER | SA_SIGINFO;
    failures += expect_result("install_main_stack_handler",
        raw_syscall4(SYS_rt_sigaction, SIGUSR1, (long)&action, 0, 8), 0);
    handler_phase = 3;
    failures += expect_result("deliver_invalid_saved_stack",
        raw_syscall2(SYS_kill, pid, SIGUSR1), 0);
    observed.sp = 0;
    observed.flags = -1;
    observed.size = 0;
    failures += expect_result("query_after_invalid_saved_stack",
        raw_syscall2(SYS_sigaltstack, 0, (long)&observed), 0);
    failures += expect_result("invalid_saved_stack_kept_sp",
                              (long)observed.sp, (long)configured.sp);
    failures += expect_result("invalid_saved_stack_kept_size",
                              (long)observed.size, (long)configured.size);
    failures += expect_result("invalid_saved_stack_kept_flags",
                              observed.flags, 0);

    failures += expect_result("disable_stack",
        raw_syscall2(SYS_sigaltstack, (long)&disabled, 0), 0);
    failures += expect_result("restore_handler",
        raw_syscall4(SYS_rt_sigaction, SIGUSR1, (long)&old_action, 0, 8), 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = test_signal_altstack();
    if (!failures)
        putstr("SIGNAL_ALTSTACK_ABI_PROBE_PASS failures: 0\n");
    else {
        putstr("SIGNAL_ALTSTACK_ABI_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
