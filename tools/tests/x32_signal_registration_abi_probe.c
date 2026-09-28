/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 signal-registration compatibility ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_signal_registration_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_exit 60
#define X32_SYS_rt_sigaction 512
#define X32_SYS_sigaltstack 525
#define EINVAL 22
#define SIGUSR1 10
#define SA_RESTORER 0x04000000u
#define SA_RESTART 0x10000000u
#define SS_DISABLE 2

struct compat_sigaction {
    uint32_t handler;
    uint32_t flags;
    uint32_t restorer;
    uint32_t mask[2];
};

struct compat_stack {
    uint32_t pointer;
    int32_t flags;
    uint32_t size;
};

static struct compat_sigaction new_action;
static struct compat_sigaction old_action;
static struct compat_stack new_stack;
static struct compat_stack old_stack;
static uint8_t alternate_stack[4096] __attribute__((aligned(16)));

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

static long x32_syscall4(
    long number, long a0, long a1, long a2, long a3) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, a3, 0, 0);
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

static uint32_t pointer32(const void *pointer) {
    return (uint32_t)(uintptr_t)pointer;
}

START_ATTRIBUTES void _start(void) {
    int failures = 0;

    new_action.handler = UINT32_C(0x12345000);
    new_action.flags = SA_RESTORER | SA_RESTART;
    new_action.restorer = UINT32_C(0x12346000);
    new_action.mask[0] = UINT32_C(1) << 11;
    new_action.mask[1] = UINT32_C(1) << 7;
    failures += expect_result(
        "install-action", x32_syscall4(
            X32_SYS_rt_sigaction, SIGUSR1, (long)&new_action, 0, 8), 0);
    failures += expect_result(
        "query-action", x32_syscall4(
            X32_SYS_rt_sigaction, SIGUSR1, 0, (long)&old_action, 8), 0);
    failures += expect_result("action-handler", old_action.handler,
                              new_action.handler);
    failures += expect_result("action-flags", old_action.flags,
                              new_action.flags);
    failures += expect_result("action-restorer", old_action.restorer,
                              new_action.restorer);
    failures += expect_result("action-mask-low", old_action.mask[0],
                              new_action.mask[0]);
    failures += expect_result("action-mask-high", old_action.mask[1],
                              new_action.mask[1]);
    failures += expect_result(
        "invalid-sigset-size", x32_syscall4(
            X32_SYS_rt_sigaction, SIGUSR1, 0, (long)&old_action, 4),
        -EINVAL);

    failures += expect_result(
        "query-initial-stack", x32_syscall4(
            X32_SYS_sigaltstack, 0, (long)&old_stack, 0, 0), 0);
    failures += expect_result("initial-stack-pointer", old_stack.pointer, 0);
    failures += expect_result("initial-stack-flags", old_stack.flags,
                              SS_DISABLE);
    failures += expect_result("initial-stack-size", old_stack.size, 0);

    new_stack.pointer = pointer32(alternate_stack);
    new_stack.flags = 0;
    new_stack.size = sizeof(alternate_stack);
    failures += expect_result(
        "install-stack", x32_syscall4(
            X32_SYS_sigaltstack, (long)&new_stack, 0, 0, 0), 0);
    failures += expect_result(
        "query-stack", x32_syscall4(
            X32_SYS_sigaltstack, 0, (long)&old_stack, 0, 0), 0);
    failures += expect_result("stack-pointer", old_stack.pointer,
                              new_stack.pointer);
    failures += expect_result("stack-flags", old_stack.flags, 0);
    failures += expect_result("stack-size", old_stack.size,
                              sizeof(alternate_stack));

    new_stack.pointer = 0;
    new_stack.flags = SS_DISABLE;
    new_stack.size = 0;
    failures += expect_result(
        "disable-stack", x32_syscall4(
            X32_SYS_sigaltstack, (long)&new_stack, 0, 0, 0), 0);

    if (failures) {
        print_text("X32_SIGNAL_REGISTRATION_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_SIGNAL_REGISTRATION_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
