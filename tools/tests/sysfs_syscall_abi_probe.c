/* SPDX-License-Identifier: MPL-2.0 */
/* Raw x86_64 Linux sysfs syscall ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "sysfs_syscall_abi_probe requires x86_64"
#endif

#define SYS_write 1
#define SYS_exit 60
#define SYS_sysfs 139

#define EFAULT 14
#define EINVAL 22

static long raw_syscall3(long number, long a0, long a1, long a2) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return result;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int run_tests(void) {
    static const char missing[] = "edgeos-no-such-filesystem";
    static char name[64];
    long count;
    long index;
    int failures = 0;

    count = raw_syscall3(SYS_sysfs, 3, 0, 0);
    if (count <= 0) return failures + expect("filesystem count", count, 1);
    failures += expect(
        "option truncation", raw_syscall3(
            SYS_sysfs, (long)0x100000003ull, 0, 0), count);
    failures += expect(
        "name at index zero", raw_syscall3(
            SYS_sysfs, 2, (long)0x100000000ull, (long)name), 0);
    if (!name[0]) failures += expect("nonempty filesystem name", 0, 1);
    index = raw_syscall3(SYS_sysfs, 1, (long)name, 0);
    failures += expect("name round trip", index, 0);
    failures += expect(
        "missing filesystem", raw_syscall3(
            SYS_sysfs, 1, (long)missing, 0), -EINVAL);
    failures += expect(
        "null name", raw_syscall3(SYS_sysfs, 1, 0, 0), -EFAULT);
    failures += expect(
        "index at count", raw_syscall3(SYS_sysfs, 2, count, 0),
        -EINVAL);
    failures += expect(
        "null output", raw_syscall3(SYS_sysfs, 2, 0, 0), -EFAULT);
    failures += expect(
        "invalid option", raw_syscall3(SYS_sysfs, 0, 0, 0), -EINVAL);
    return failures;
}

__attribute__((noreturn)) void _start(void) {
    int failures = run_tests();
    print_text(failures ? "SYSFS_SYSCALL_ABI_PROBE_FAIL\n" :
                          "SYSFS_SYSCALL_ABI_PROBE_PASS\n");
    (void)raw_syscall3(SYS_exit, failures ? 1 : 0, 0, 0);
    for (;;) { }
}
