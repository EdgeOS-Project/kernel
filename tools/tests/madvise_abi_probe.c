/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux madvise ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_mincore 27
#define SYS_madvise 28
#define SYS_clone 56
#define SYS_wait4 61
#define SYS_exit 60
#define SYS_ftruncate 77
#define SYS_openat 257
#define SYS_memfd_create 319
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_close 57
#define SYS_exit 93
#define SYS_openat 56
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mincore 232
#define SYS_madvise 233
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_ftruncate 46
#define SYS_memfd_create 279
#else
#error "madvise_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINVAL 22
#define ENOMEM 12

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define AT_FDCWD -100
#define PAGE_SIZE 4096u

#define MADV_NORMAL 0
#define MADV_RANDOM 1
#define MADV_SEQUENTIAL 2
#define MADV_WILLNEED 3
#define MADV_DONTNEED 4
#define MADV_FREE 8
#define MADV_MERGEABLE 12
#define MADV_UNMERGEABLE 13
#define MADV_HUGEPAGE 14
#define MADV_NOHUGEPAGE 15
#define MADV_DONTDUMP 16
#define MADV_DODUMP 17
#define MADV_WIPEONFORK 18
#define MADV_KEEPONFORK 19
#define MADV_COLD 20
#define MADV_PAGEOUT 21
#define MADV_POPULATE_READ 22
#define MADV_POPULATE_WRITE 23

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

static long madvise_raw(uint64_t address, uint64_t length, uint64_t advice) {
    return raw_syscall6(SYS_madvise, (long)address, (long)length,
                        (long)advice, 0, 0, 0);
}

static int wait_for_clean_child(long child) {
    int status = -1;
    long waited;
    if (child <= 0) return 0;
    waited = raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0);
    return waited == child && (status & 0x7fu) == 0 &&
           ((status >> 8) & 0xff) == 0;
}

static int run_tests(void) {
    static const uint32_t hints[] = {
        MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED,
        MADV_FREE, MADV_MERGEABLE, MADV_UNMERGEABLE,
        MADV_HUGEPAGE, MADV_NOHUGEPAGE, MADV_DONTDUMP, MADV_DODUMP,
        MADV_COLD, MADV_PAGEOUT,
    };
    uint8_t residency = 0;
    volatile uint8_t *mapping;
    long mapped;
    int failures = 0;

    failures += expect_result("zero length",
        madvise_raw(PAGE_SIZE, 0, MADV_NORMAL), 0);
    failures += expect_result("zero length invalid advice",
        madvise_raw(PAGE_SIZE, 0, 99), -EINVAL);
    failures += expect_result("unaligned zero length",
        madvise_raw(PAGE_SIZE + 1u, 0, MADV_NORMAL), -EINVAL);
    failures += expect_result("overflow range",
        madvise_raw(UINT64_MAX & ~(uint64_t)(PAGE_SIZE - 1u),
                    PAGE_SIZE * 2u, MADV_NORMAL), -EINVAL);
    failures += expect_result("unmapped range",
        madvise_raw(PAGE_SIZE, PAGE_SIZE, MADV_NORMAL), -ENOMEM);

    mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE * 3u,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("anonymous mapping", mapped > 0);
    if (mapped <= 0) return failures;
    mapping = (volatile uint8_t *)(uintptr_t)mapped;

    failures += expect_result("populate read",
        madvise_raw((uint64_t)mapped, PAGE_SIZE, MADV_POPULATE_READ), 0);
    failures += expect_result("read population residency",
        raw_syscall6(SYS_mincore, mapped, PAGE_SIZE,
                     (long)&residency, 0, 0, 0), 0);
    failures += expect_true("read population resident", residency & 1u);

    residency = 0;
    failures += expect_result("populate write",
        madvise_raw((uint64_t)mapped + PAGE_SIZE, PAGE_SIZE,
                    MADV_POPULATE_WRITE), 0);
    failures += expect_result("write population residency",
        raw_syscall6(SYS_mincore, mapped + PAGE_SIZE, PAGE_SIZE,
                     (long)&residency, 0, 0, 0), 0);
    failures += expect_true("write population resident", residency & 1u);

    mapping[0] = 0x11u;
    mapping[PAGE_SIZE] = 0x22u;
    mapping[PAGE_SIZE * 2u] = 0x33u;
    failures += expect_result("discard middle page",
        madvise_raw((uint64_t)mapped + PAGE_SIZE, PAGE_SIZE,
                    MADV_DONTNEED), 0);
    failures += expect_true("discarded page reads zero",
        mapping[PAGE_SIZE] == 0);
    failures += expect_true("discard preserves neighbors",
        mapping[0] == 0x11u && mapping[PAGE_SIZE * 2u] == 0x33u);

    failures += expect_result("enable wipe on fork",
        madvise_raw((uint64_t)mapped + PAGE_SIZE, PAGE_SIZE,
                    MADV_WIPEONFORK), 0);
    {
        long child = raw_syscall6(SYS_clone, 17, 0, 0, 0, 0, 0);
        failures += expect_true("wipe-on-fork clone", child >= 0);
        if (child == 0) {
            int child_failed =
                mapping[0] != 0x11u || mapping[PAGE_SIZE] != 0u ||
                mapping[PAGE_SIZE * 2u] != 0x33u;
            raw_syscall6(SYS_exit, child_failed, 0, 0, 0, 0, 0);
            __builtin_unreachable();
        }
        if (child > 0)
            failures += expect_true("wipe-on-fork child state",
                                    wait_for_clean_child(child));
    }
    mapping[PAGE_SIZE] = 0x44u;
    failures += expect_result("disable wipe on fork",
        madvise_raw((uint64_t)mapped + PAGE_SIZE, PAGE_SIZE,
                    MADV_KEEPONFORK), 0);
    {
        long child = raw_syscall6(SYS_clone, 17, 0, 0, 0, 0, 0);
        failures += expect_true("keep-on-fork clone", child >= 0);
        if (child == 0) {
            int child_failed = mapping[PAGE_SIZE] != 0x44u;
            raw_syscall6(SYS_exit, child_failed, 0, 0, 0, 0, 0);
            __builtin_unreachable();
        }
        if (child > 0)
            failures += expect_true("keep-on-fork child state",
                                    wait_for_clean_child(child));
    }

    mapping[PAGE_SIZE] = 0x55u;
    failures += expect_result("lazy free private anonymous page",
        madvise_raw((uint64_t)mapped + PAGE_SIZE, PAGE_SIZE,
                    MADV_FREE), 0);
    failures += expect_true("lazy-free contents remain valid or become zero",
        mapping[PAGE_SIZE] == 0x55u || mapping[PAGE_SIZE] == 0u);

    mapping[0] = 0x66u;
    failures += expect_result("pageout private anonymous page",
        madvise_raw((uint64_t)mapped, PAGE_SIZE, MADV_PAGEOUT), 0);
    residency = 1u;
    failures += expect_result("pageout residency query",
        raw_syscall6(SYS_mincore, mapped, PAGE_SIZE,
                     (long)&residency, 0, 0, 0), 0);
    if ((residency & 1u) == 0)
        print_text("MADVISE_PAGEOUT_RECLAIMED\n");
    failures += expect_true("pageout preserves page contents",
        mapping[0] == 0x66u);

    {
        static const char memfd_name[] = "madvise-shared";
        long descriptor = raw_syscall6(
            SYS_memfd_create, (long)memfd_name, 0, 0, 0, 0, 0);
        long first_alias = -1;
        long second_alias = -1;

        failures += expect_true("shared pageout memfd", descriptor >= 0);
        if (descriptor >= 0)
            failures += expect_result("shared pageout truncate",
                raw_syscall6(SYS_ftruncate, descriptor, PAGE_SIZE,
                             0, 0, 0, 0), 0);
        if (descriptor >= 0) {
            first_alias = raw_syscall6(
                SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_SHARED, descriptor, 0);
            second_alias = raw_syscall6(
                SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_SHARED, descriptor, 0);
            failures += expect_true("shared pageout first alias",
                                    first_alias > 0);
            failures += expect_true("shared pageout second alias",
                                    second_alias > 0);
        }
        if (first_alias > 0 && second_alias > 0) {
            volatile uint8_t *first =
                (volatile uint8_t *)(uintptr_t)first_alias;
            volatile uint8_t *second =
                (volatile uint8_t *)(uintptr_t)second_alias;
            uint8_t first_residency = 1u;
            uint8_t second_residency = 1u;

            first[0] = 0x7au;
            first[PAGE_SIZE - 1u] = 0xc3u;
            failures += expect_true("shared alias initial visibility",
                second[0] == 0x7au && second[PAGE_SIZE - 1u] == 0xc3u);
            failures += expect_result("shared pageout advice",
                madvise_raw((uint64_t)first_alias, PAGE_SIZE,
                            MADV_PAGEOUT), 0);
            failures += expect_result("shared pageout first residency",
                raw_syscall6(SYS_mincore, first_alias, PAGE_SIZE,
                             (long)&first_residency, 0, 0, 0), 0);
            failures += expect_result("shared pageout second residency",
                raw_syscall6(SYS_mincore, second_alias, PAGE_SIZE,
                             (long)&second_residency, 0, 0, 0), 0);
            if (!(first_residency & 1u) && !(second_residency & 1u))
                print_text("MADVISE_SHMEM_PAGEOUT_RECLAIMED\n");
            /*
             * MADV_PAGEOUT is best effort.  Without configured swap, Linux
             * may accept the request while leaving shmem pages resident.
             */
            failures += expect_true("shared pageout preserves object",
                second[0] == 0x7au && second[PAGE_SIZE - 1u] == 0xc3u);
            second[1] = 0x5du;
            failures += expect_true("shared pageout restored alias visibility",
                                    first[1] == 0x5du);
        }
        if (second_alias > 0)
            failures += expect_result("unmap shared pageout second alias",
                raw_syscall6(SYS_munmap, second_alias, PAGE_SIZE,
                             0, 0, 0, 0), 0);
        if (first_alias > 0)
            failures += expect_result("unmap shared pageout first alias",
                raw_syscall6(SYS_munmap, first_alias, PAGE_SIZE,
                             0, 0, 0, 0), 0);
        if (descriptor >= 0)
            failures += expect_result("close shared pageout memfd",
                raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    {
        long descriptor = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)"/etc/hostname", 0,
            0, 0, 0);
        long file_mapping = -1;
        uint8_t first_byte = 0;

        failures += expect_true("pageout file descriptor", descriptor >= 0);
        if (descriptor >= 0) {
            file_mapping = raw_syscall6(
                SYS_mmap, 0, PAGE_SIZE, PROT_READ, MAP_PRIVATE,
                descriptor, 0);
            failures += expect_true("pageout file mapping", file_mapping > 0);
        }
        if (file_mapping > 0) {
            volatile uint8_t *file_bytes =
                (volatile uint8_t *)(uintptr_t)file_mapping;
            first_byte = file_bytes[0];
            failures += expect_true("pageout file initial contents",
                                    first_byte != 0u);
            failures += expect_result("pageout file advice",
                madvise_raw((uint64_t)file_mapping, PAGE_SIZE,
                            MADV_PAGEOUT), 0);
            residency = 1u;
            failures += expect_result("pageout file residency query",
                raw_syscall6(SYS_mincore, file_mapping, PAGE_SIZE,
                             (long)&residency, 0, 0, 0), 0);
            if ((residency & 1u) == 0)
                print_text("MADVISE_FILE_PAGEOUT_RECLAIMED\n");
            failures += expect_true("pageout file preserves contents",
                                    file_bytes[0] == first_byte);
            failures += expect_result("unmap pageout file",
                raw_syscall6(SYS_munmap, file_mapping, PAGE_SIZE,
                             0, 0, 0, 0), 0);
        }
        if (descriptor >= 0) {
            long private_mapping = raw_syscall6(
                SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE, descriptor, 0);
            failures += expect_true("private file mapping",
                                    private_mapping > 0);
            if (private_mapping > 0) {
                volatile uint8_t *private_bytes =
                    (volatile uint8_t *)(uintptr_t)private_mapping;
                uint8_t private_value = private_bytes[0] ^ 0x5au;

                private_bytes[0] = private_value;
                failures += expect_result("private file pageout advice",
                    madvise_raw((uint64_t)private_mapping, PAGE_SIZE,
                                MADV_PAGEOUT), 0);
                residency = 1u;
                failures += expect_result("private file pageout residency",
                    raw_syscall6(SYS_mincore, private_mapping, PAGE_SIZE,
                                 (long)&residency, 0, 0, 0), 0);
                if ((residency & 1u) == 0)
                    print_text("MADVISE_PRIVATE_FILE_PAGEOUT_RECLAIMED\n");
                failures += expect_true("private file pageout preserves COW",
                                        private_bytes[0] == private_value);
                failures += expect_result("unmap private file",
                    raw_syscall6(SYS_munmap, private_mapping, PAGE_SIZE,
                                 0, 0, 0, 0), 0);
            }
        }
        if (descriptor >= 0)
            failures += expect_result("close pageout file",
                raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    for (uint32_t index = 0;
         index < sizeof(hints) / sizeof(hints[0]); ++index) {
        long result = madvise_raw((uint64_t)mapped, PAGE_SIZE, hints[index]);

        failures += expect_true("known advice",
                                result == 0 || result == -EINVAL);
    }
    failures += expect_result("32-bit advice conversion",
        madvise_raw((uint64_t)mapped, PAGE_SIZE,
                    UINT64_C(1) << 32), 0);
    failures += expect_result("invalid advice",
        madvise_raw((uint64_t)mapped, PAGE_SIZE, 99), -EINVAL);

    failures += expect_result("unmap range",
        raw_syscall6(SYS_munmap, mapped, PAGE_SIZE * 3u,
                     0, 0, 0, 0), 0);
    if (!failures) print_text("MADVISE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
