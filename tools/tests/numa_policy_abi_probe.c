/* SPDX-License-Identifier: MPL-2.0 */
/* Linux NUMA policy ABI probe for single-node 64-bit systems. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#define SYS_get_mempolicy 239
#define SYS_mbind 237
#define SYS_set_mempolicy 238
#define SYS_migrate_pages 256
#define SYS_move_pages 279
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_exit 93
#define SYS_mbind 235
#define SYS_get_mempolicy 236
#define SYS_set_mempolicy 237
#define SYS_migrate_pages 238
#define SYS_move_pages 239
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "numa_policy_abi_probe requires a Linux 64-bit architecture"
#endif
#define SYS_set_mempolicy_home_node 450

#define EFAULT 14
#define EINVAL 22
#define ENOENT 2

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20

#define MPOL_DEFAULT 0
#define MPOL_BIND 2
#define MPOL_F_ADDR 2

#define PAGE_SIZE 4096u

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
    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory");
    return x0;
#endif
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
    char digits[24];
    unsigned long magnitude;
    int position = (int)sizeof(digits);

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&digits[position],
                       (long)(sizeof(digits) - (unsigned long)position),
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

static int run_tests(void) {
    unsigned long mask = 1u;
    unsigned long observed_mask = 0u;
    long page;
    long page_pointer;
    int node = 0;
    int status = -1;
    int mode = -1;
    int failures = 0;

    page = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("anonymous mapping", page > 0);
    if (page <= 0) return failures;
    *(volatile uint8_t *)(uintptr_t)page = 1u;
    page_pointer = page;

    failures += expect_result(
        "set unknown mode",
        raw_syscall6(SYS_set_mempolicy, 0x1000, 0, 0, 0, 0, 0),
        -EINVAL);
    failures += expect_result(
        "set bad mask pointer",
        raw_syscall6(SYS_set_mempolicy, MPOL_BIND, 1, 64, 0, 0, 0),
        -EFAULT);
    failures += expect_result(
        "set bind node zero",
        raw_syscall6(SYS_set_mempolicy, MPOL_BIND, (long)&mask,
                     64, 0, 0, 0), 0);
    failures += expect_result(
        "get bound policy",
        raw_syscall6(SYS_get_mempolicy, (long)&mode,
                     (long)&observed_mask, 64, 0, 0, 0), 0);
    failures += expect_true(
        "bound policy values", mode == MPOL_BIND && observed_mask == 1u);
    failures += expect_result(
        "restore before mbind",
        raw_syscall6(SYS_set_mempolicy, MPOL_DEFAULT, 0, 0, 0, 0, 0), 0);

    failures += expect_result(
        "mbind unknown flags",
        raw_syscall6(SYS_mbind, page, PAGE_SIZE, MPOL_BIND,
                     (long)&mask, 64, 8), -EINVAL);
    failures += expect_result(
        "mbind node zero",
        raw_syscall6(SYS_mbind, page, PAGE_SIZE, MPOL_BIND,
                     (long)&mask, 64, 0), 0);
    failures += expect_result(
        "mbind strict node zero",
        raw_syscall6(SYS_mbind, page, PAGE_SIZE, MPOL_BIND,
                     (long)&mask, 64, 1), 0);
    mode = -1;
    observed_mask = 0;
    failures += expect_result(
        "get address policy",
        raw_syscall6(SYS_get_mempolicy, (long)&mode,
                     (long)&observed_mask, 64, page, MPOL_F_ADDR, 0), 0);
    failures += expect_true(
        "address policy values", mode == MPOL_BIND && observed_mask == 1u);

    failures += expect_result(
        "migrate same node",
        raw_syscall6(SYS_migrate_pages, 0, 64, (long)&mask,
                     (long)&mask, 0, 0), 0);
    failures += expect_result(
        "migrate bad old mask",
        raw_syscall6(SYS_migrate_pages, 0, 64, 1,
                     (long)&mask, 0, 0), -EFAULT);

    failures += expect_result(
        "query page node",
        raw_syscall6(SYS_move_pages, 0, 1, (long)&page_pointer,
                     0, (long)&status, 0), 0);
    failures += expect_result("page on node zero", status, 0);
    status = -1;
    failures += expect_result(
        "move page to node zero",
        raw_syscall6(SYS_move_pages, 0, 1, (long)&page_pointer,
                     (long)&node, (long)&status, 0), 0);
    failures += expect_result("move status", status, 0);
    failures += expect_result(
        "move unknown flags",
        raw_syscall6(SYS_move_pages, 0, 0, 0, 0, 0, 8), -EINVAL);
    failures += expect_result(
        "move rejects mbind strict flag",
        raw_syscall6(SYS_move_pages, 0, 0, 0, 0, 0, 1), -EINVAL);
    failures += expect_result(
        "move missing arrays",
        raw_syscall6(SYS_move_pages, 0, 1, 0, 0, 0, 0), -EFAULT);

    failures += expect_result(
        "set home node",
        raw_syscall6(SYS_set_mempolicy_home_node, page, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result(
        "home zero length",
        raw_syscall6(SYS_set_mempolicy_home_node, page, 0,
                     0, 0, 0, 0), 0);
    failures += expect_result(
        "home unaligned",
        raw_syscall6(SYS_set_mempolicy_home_node, page + 1,
                     PAGE_SIZE, 0, 0, 0, 0), -EINVAL);
    failures += expect_result(
        "clear address policy",
        raw_syscall6(SYS_mbind, page, PAGE_SIZE, MPOL_DEFAULT,
                     0, 0, 0), 0);
    failures += expect_result(
        "home node without policy",
        raw_syscall6(SYS_set_mempolicy_home_node, page, PAGE_SIZE,
                     0, 0, 0, 0), -ENOENT);

    failures += expect_result(
        "restore default",
        raw_syscall6(SYS_set_mempolicy, MPOL_DEFAULT, 0, 0, 0, 0, 0), 0);
    failures += expect_result(
        "unmap", raw_syscall6(
            SYS_munmap, page, PAGE_SIZE, 0, 0, 0, 0), 0);

    if (!failures) print_text("NUMA_POLICY_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

START_ATTRIBUTES void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
