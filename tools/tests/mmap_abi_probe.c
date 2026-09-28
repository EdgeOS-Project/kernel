/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux mmap ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#define SYS_openat 257
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "mmap_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EINVAL 22
#define EEXIST 17

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED_NOREPLACE 0x100000
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

static long map_memory(uint64_t address, uint64_t length,
                       uint64_t protection, uint64_t flags,
                       long descriptor, uint64_t offset) {
    return raw_syscall6(SYS_mmap, (long)address, (long)length,
                        (long)protection, (long)flags,
                        descriptor, (long)offset);
}

static long unmap_memory(uint64_t address, uint64_t length) {
    return raw_syscall6(SYS_munmap, (long)address, (long)length,
                        0, 0, 0, 0);
}

static int run_tests(void) {
    static const char busybox_path[] = "/bin/busybox";
    long descriptor;
    long mapping;
    long replacement;
    uint8_t *bytes;
    int failures = 0;

    failures += expect_result(
        "zero length",
        map_memory(0, 0, PROT_READ,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
        -EINVAL);
    failures += expect_result(
        "missing mapping type",
        map_memory(0, PAGE_SIZE, PROT_READ, MAP_ANONYMOUS, -1, 0),
        -EINVAL);
    failures += expect_result(
        "non-anonymous invalid descriptor",
        map_memory(0, PAGE_SIZE, PROT_READ, MAP_PRIVATE, -1, 0),
        -EBADF);
    failures += expect_result(
        "unaligned file offset",
        map_memory(0, PAGE_SIZE, PROT_READ, MAP_PRIVATE, -1, 1),
        -EINVAL);
    failures += expect_result(
        "unaligned fixed address",
        map_memory(1, PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                   -1, 0),
        -EINVAL);

    mapping = map_memory(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("anonymous mapping succeeds", mapping > 0);
    if (mapping > 0) {
        bytes = (uint8_t *)(uintptr_t)mapping;
        failures += expect_true("anonymous mapping is page aligned",
                                ((uint64_t)mapping & (PAGE_SIZE - 1u)) == 0);
        failures += expect_true("anonymous mapping starts zeroed",
                                bytes[0] == 0 && bytes[PAGE_SIZE - 1u] == 0);
        bytes[0] = 0x5au;
        bytes[PAGE_SIZE - 1u] = 0xa5u;
        failures += expect_true("anonymous mapping is writable",
                                bytes[0] == 0x5au &&
                                bytes[PAGE_SIZE - 1u] == 0xa5u);
        failures += expect_result(
            "anonymous munmap",
            unmap_memory((uint64_t)mapping, PAGE_SIZE), 0);
    }

    descriptor = raw_syscall6(SYS_openat, AT_FDCWD,
                              (long)busybox_path, O_RDONLY, 0, 0, 0);
    failures += expect_true("open file mapping source", descriptor >= 0);
    if (descriptor >= 0) {
        mapping = map_memory(0, PAGE_SIZE, PROT_READ,
                             MAP_PRIVATE, descriptor, 0);
        failures += expect_true("file mapping succeeds", mapping > 0);
        if (mapping > 0) {
            bytes = (uint8_t *)(uintptr_t)mapping;
            failures += expect_true(
                "file mapping exposes ELF bytes",
                bytes[0] == 0x7fu && bytes[1] == 'E' &&
                bytes[2] == 'L' && bytes[3] == 'F');
            failures += expect_result(
                "file munmap", unmap_memory((uint64_t)mapping, PAGE_SIZE), 0);
        }
        failures += expect_result(
            "close file mapping source",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    mapping = map_memory(0, 2u * PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("reserve fixed-noreplace span", mapping > 0);
    if (mapping > 0) {
        uint64_t second_page = (uint64_t)mapping + PAGE_SIZE;
        failures += expect_result(
            "release fixed-noreplace target",
            unmap_memory(second_page, PAGE_SIZE), 0);
        replacement = map_memory(
            second_page, PAGE_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1, 0);
        failures += expect_result(
            "fixed-noreplace exact placement", replacement,
            (long)second_page);
        failures += expect_result(
            "fixed-noreplace collision",
            map_memory(second_page, PAGE_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS |
                           MAP_FIXED_NOREPLACE,
                       -1, 0),
            -EEXIST);
        failures += expect_result(
            "release fixed-noreplace first page",
            unmap_memory((uint64_t)mapping, PAGE_SIZE), 0);
        if (replacement == (long)second_page) {
            failures += expect_result(
                "release fixed-noreplace mapped page",
                unmap_memory(second_page, PAGE_SIZE), 0);
        }
    }

    mapping = map_memory(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("reserve fixed replacement", mapping > 0);
    if (mapping > 0) {
        bytes = (uint8_t *)(uintptr_t)mapping;
        bytes[0] = 0x5au;
        replacement = map_memory(
            (uint64_t)mapping, PAGE_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        failures += expect_result(
            "fixed replacement address", replacement, mapping);
        if (replacement == mapping) {
            bytes = (uint8_t *)(uintptr_t)replacement;
            failures += expect_true("fixed replacement is zeroed",
                                    bytes[0] == 0);
            failures += expect_result(
                "release fixed replacement",
                unmap_memory((uint64_t)replacement, PAGE_SIZE), 0);
        }
    }

    return failures;
}

START_ATTRIBUTES void _start(void) {
    int failures = run_tests();
    if (failures) {
        print_text("MMAP_ABI_PROBE_FAILED failures=");
        print_number(failures);
        print_text("\n");
    } else {
        print_text("MMAP_ABI_PROBE_PASS\n");
    }
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
