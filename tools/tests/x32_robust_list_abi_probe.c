/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 robust-list compatibility ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_robust_list_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_exit 60
#define X32_SYS_set_robust_list 530
#define X32_SYS_get_robust_list 531
#define EINVAL 22
#define EFAULT 14
#define ESRCH 3
#define COMPAT_ROBUST_LIST_HEAD_SIZE 12

struct compat_robust_list_head {
    uint32_t next;
    int32_t futex_offset;
    uint32_t pending;
};

static struct compat_robust_list_head robust_head;
static uint32_t returned_head;
static uint32_t returned_length;

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

static long x32_syscall3(long number, long a0, long a1, long a2) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, 0, 0, 0);
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

    returned_head = UINT32_MAX;
    returned_length = UINT32_MAX;
    failures += expect_result(
        "get-initial", x32_syscall3(
            X32_SYS_get_robust_list, 0, (long)&returned_head,
            (long)&returned_length), 0);
    failures += expect_result("initial-head", returned_head, 0);
    failures += expect_result("initial-length", returned_length,
                              COMPAT_ROBUST_LIST_HEAD_SIZE);

    robust_head.next = pointer32(&robust_head);
    robust_head.futex_offset = 0;
    robust_head.pending = 0;
    failures += expect_result(
        "set", x32_syscall3(
            X32_SYS_set_robust_list, (long)&robust_head,
            COMPAT_ROBUST_LIST_HEAD_SIZE, 0), 0);
    returned_head = 0;
    returned_length = 0;
    failures += expect_result(
        "get-current", x32_syscall3(
            X32_SYS_get_robust_list, 0, (long)&returned_head,
            (long)&returned_length), 0);
    failures += expect_result("current-head", returned_head,
                              pointer32(&robust_head));
    failures += expect_result("current-length", returned_length,
                              COMPAT_ROBUST_LIST_HEAD_SIZE);

    failures += expect_result(
        "native-length-rejected", x32_syscall3(
            X32_SYS_set_robust_list, (long)&robust_head, 24, 0), -EINVAL);
    failures += expect_result(
        "unknown-pid", x32_syscall3(
            X32_SYS_get_robust_list, 0x7fffffff, (long)&returned_head,
            (long)&returned_length), -ESRCH);

    returned_length = UINT32_MAX;
    failures += expect_result(
        "head-fault", x32_syscall3(
            X32_SYS_get_robust_list, 0, 1, (long)&returned_length),
        -EFAULT);
    failures += expect_result("length-written-before-head-fault",
                              returned_length,
                              COMPAT_ROBUST_LIST_HEAD_SIZE);

    returned_head = UINT32_MAX;
    failures += expect_result(
        "length-fault", x32_syscall3(
            X32_SYS_get_robust_list, 0, (long)&returned_head, 1),
        -EFAULT);
    failures += expect_result("head-unchanged-after-length-fault",
                              returned_head, UINT32_MAX);

    if (failures) {
        print_text("X32_ROBUST_LIST_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_ROBUST_LIST_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
