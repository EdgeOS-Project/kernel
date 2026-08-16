/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux mremap ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_mremap 25
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_mremap 216
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "mremap_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINVAL 22

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED_NOREPLACE 0x100000
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
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
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#endif
}

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
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

static long map_anonymous(long address, long length, long flags) {
    return raw_syscall6(SYS_mmap, address, length,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | flags, -1, 0);
}

static int test_repeated_growth(void) {
    const long initial_size = PAGE_SIZE * 65u;
    const long maximum_size = PAGE_SIZE * 2049u;
    volatile uint8_t *bytes;
    long mapping = map_anonymous(0, initial_size, 0);
    long old_size = initial_size;
    int failures = 0;

    failures += expect_true("growth source mapping", mapping > 0);
    if (mapping <= 0) return failures;
    bytes = (volatile uint8_t *)(uintptr_t)mapping;
    bytes[0] = 0x6du;
    bytes[PAGE_SIZE + 31u] = 0xb2u;

    for (long new_size = initial_size + PAGE_SIZE * 4u;
         new_size <= maximum_size; new_size += PAGE_SIZE * 4u) {
        long resized = raw_syscall6(
            SYS_mremap, mapping, old_size, new_size,
            MREMAP_MAYMOVE, 0, 0);

        if (resized <= 0) {
            failures += expect_true("repeated growth remap", 0);
            failures += expect_true(
                "failed growth preserves source",
                bytes[0] == 0x6du &&
                bytes[PAGE_SIZE + 31u] == 0xb2u);
            break;
        }
        mapping = resized;
        old_size = new_size;
        bytes = (volatile uint8_t *)(uintptr_t)mapping;
        if (bytes[0] != 0x6du ||
            bytes[PAGE_SIZE + 31u] != 0xb2u) {
            failures += expect_true("repeated growth preserves data", 0);
            break;
        }
        bytes[new_size - 1u] = (uint8_t)(new_size / PAGE_SIZE);
    }

    (void)raw_syscall6(SYS_munmap, mapping, old_size, 0, 0, 0, 0);
    return failures;
}

static int run_tests(void) {
    volatile uint8_t *bytes;
    long arena;
    long mapping;
    long blocker;
    long moved;
    long target;
    long fixed;
    int failures = 0;

    arena = map_anonymous(0, PAGE_SIZE * 4u, 0);
    failures += expect_true("arena reservation", arena > 0);
    if (arena <= 0) return failures;
    failures += expect_result(
        "release arena",
        raw_syscall6(SYS_munmap, arena, PAGE_SIZE * 4u,
                     0, 0, 0, 0), 0);
    mapping = map_anonymous(arena, PAGE_SIZE * 2u,
                            MAP_FIXED_NOREPLACE);
    failures += expect_true("source mapping", mapping > 0);
    if (mapping <= 0) return failures;
    bytes = (volatile uint8_t *)(uintptr_t)mapping;
    bytes[0] = 0x31u;
    bytes[PAGE_SIZE + 17u] = 0xa7u;

    failures += expect_result(
        "zero old length",
        raw_syscall6(SYS_mremap, mapping, 0, PAGE_SIZE,
                     MREMAP_MAYMOVE, 0, 0), -EINVAL);
    failures += expect_result(
        "unaligned old address",
        raw_syscall6(SYS_mremap, mapping + 1u, PAGE_SIZE, PAGE_SIZE,
                     MREMAP_MAYMOVE, 0, 0), -EINVAL);
    failures += expect_result(
        "fixed requires maymove",
        raw_syscall6(SYS_mremap, mapping, PAGE_SIZE, PAGE_SIZE,
                     MREMAP_FIXED, mapping + PAGE_SIZE * 3u, 0), -EINVAL);
    failures += expect_result(
        "unknown flags",
        raw_syscall6(SYS_mremap, mapping, PAGE_SIZE, PAGE_SIZE,
                     0x80000000u, 0, 0), -EINVAL);

    blocker = map_anonymous(mapping + PAGE_SIZE * 2u, PAGE_SIZE,
                            MAP_FIXED_NOREPLACE);
    failures += expect_result("growth blocker",
                              blocker, mapping + PAGE_SIZE * 2u);
    if (blocker != mapping + PAGE_SIZE * 2u) {
        (void)raw_syscall6(SYS_munmap, mapping, PAGE_SIZE * 2u,
                           0, 0, 0, 0);
        return failures;
    }

    moved = raw_syscall6(SYS_mremap, mapping, PAGE_SIZE * 2u,
                         PAGE_SIZE * 3u, MREMAP_MAYMOVE, 0, 0);
    failures += expect_true("maymove relocation",
                            moved > 0 && moved != mapping);
    if (moved <= 0 || moved == mapping) {
        (void)raw_syscall6(SYS_munmap, blocker, PAGE_SIZE, 0, 0, 0, 0);
        return failures;
    }
    bytes = (volatile uint8_t *)(uintptr_t)moved;
    failures += expect_true("relocation preserves data",
                            bytes[0] == 0x31u &&
                            bytes[PAGE_SIZE + 17u] == 0xa7u);
    bytes[PAGE_SIZE * 2u + 29u] = 0x5cu;

    failures += expect_result(
        "fixed overlap",
        raw_syscall6(SYS_mremap, moved, PAGE_SIZE * 3u,
                     PAGE_SIZE * 3u, MREMAP_MAYMOVE | MREMAP_FIXED,
                     moved + PAGE_SIZE, 0), -EINVAL);

    target = map_anonymous(0, PAGE_SIZE * 3u, 0);
    failures += expect_true("fixed target mapping", target > 0);
    if (target > 0) {
        fixed = raw_syscall6(SYS_mremap, moved, PAGE_SIZE * 3u,
                             PAGE_SIZE * 3u,
                             MREMAP_MAYMOVE | MREMAP_FIXED,
                             target, 0);
        failures += expect_result("fixed relocation", fixed, target);
        if (fixed == target) {
            bytes = (volatile uint8_t *)(uintptr_t)fixed;
            failures += expect_true("fixed relocation preserves data",
                                    bytes[0] == 0x31u &&
                                    bytes[PAGE_SIZE + 17u] == 0xa7u &&
                                    bytes[PAGE_SIZE * 2u + 29u] == 0x5cu);
            moved = fixed;
        }
    }

    fixed = raw_syscall6(SYS_mremap, moved, PAGE_SIZE * 3u,
                         PAGE_SIZE, 0, 0, 0);
    failures += expect_result("shrink in place", fixed, moved);
    if (fixed == moved) {
        bytes = (volatile uint8_t *)(uintptr_t)fixed;
        failures += expect_true("shrink preserves first page",
                                bytes[0] == 0x31u);
    }

    (void)raw_syscall6(SYS_munmap, moved, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, blocker, PAGE_SIZE, 0, 0, 0, 0);
    failures += test_repeated_growth();
    if (!failures) print_text("MREMAP_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
