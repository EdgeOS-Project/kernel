/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS copy_file_range Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_lseek 8
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_ftruncate 77
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_memfd_create 319
#define SYS_copy_file_range 326
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_unlinkat 35
#define SYS_openat 56
#define SYS_close 57
#define SYS_lseek 62
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_ftruncate 46
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mprotect 226
#define SYS_memfd_create 279
#define SYS_copy_file_range 285
#else
#error "copy_file_range_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR 0x0002
#define O_CREAT 0x0040
#define O_TRUNC 0x0200
#define O_APPEND 0x0400
#define O_DIRECTORY 0x10000
#define SEEK_SET 0
#define SEEK_CUR 1
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define EBADF 9
#define EFAULT 14
#define EISDIR 21
#define EINVAL 22
#define EXDEV 18
#define EOVERFLOW 75
#define PAGE_SIZE 4096

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
    char buffer[32];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[--position] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned long)position),
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

static int expect_bytes(const char *name, const char *actual,
                        const char *expected, unsigned long length) {
    for (unsigned long index = 0; index < length; ++index) {
        if (actual[index] == expected[index]) continue;
        print_text("FAIL ");
        print_text(name);
        print_text(" byte=");
        print_number((long)index);
        print_text("\n");
        return 1;
    }
    return 0;
}

static long open_file(const char *path, long flags) {
    return raw_syscall6(SYS_openat, AT_FDCWD, (long)path, flags, 0600, 0, 0);
}

static long copy_range(long input, int64_t *input_offset, long output,
                       int64_t *output_offset, uint64_t length,
                       uint32_t flags) {
    return raw_syscall6(SYS_copy_file_range, input, (long)input_offset,
                        output, (long)output_offset, (long)length,
                        (long)flags);
}

static int reset_file(long descriptor) {
    if (raw_syscall6(SYS_ftruncate, descriptor, 0, 0, 0, 0, 0) < 0)
        return -1;
    return raw_syscall6(SYS_lseek, descriptor, 0, SEEK_SET, 0, 0, 0) < 0 ?
           -1 : 0;
}

static int read_at_start(long descriptor, char *buffer, unsigned long length) {
    if (raw_syscall6(SYS_lseek, descriptor, 0, SEEK_SET, 0, 0, 0) < 0)
        return -1;
    return (int)raw_syscall6(SYS_read, descriptor, (long)buffer,
                             (long)length, 0, 0, 0);
}

static int test_policy_order(long input, long output) {
    int failures = 0;
    int64_t input_offset = 0;
    int64_t output_offset = 0;
    long readonly;
    long directory;

    failures += expect_result("invalid descriptors before flags",
        copy_range(-1, 0, -1, 0, 1, 1), -EBADF);
    failures += expect_result("invalid descriptors at zero length",
        copy_range(-1, 0, -1, 0, 0, 0), -EBADF);
    failures += expect_result("input pointer before flags",
        copy_range(input, (int64_t *)1, output, &output_offset, 1, 1),
        -EFAULT);
    failures += expect_result("output pointer before flags",
        copy_range(input, &input_offset, output, (int64_t *)1, 1, 1),
        -EFAULT);
    failures += expect_result("unsupported flags",
        copy_range(input, &input_offset, output, &output_offset, 1, 1),
        -EINVAL);
    failures += expect_result("zero length", copy_range(
        input, &input_offset, output, &output_offset, 0, 0), 0);
    failures += expect_result("zero length input offset unchanged",
                              input_offset, 0);
    failures += expect_result("zero length output offset unchanged",
                              output_offset, 0);

    input_offset = -1;
    failures += expect_result("negative input offset",
        copy_range(input, &input_offset, output, &output_offset, 1, 0),
        -EOVERFLOW);
    failures += expect_result("negative input offset at zero length",
        copy_range(input, &input_offset, output, &output_offset, 0, 0),
        -EINVAL);
    input_offset = 0;
    output_offset = -1;
    failures += expect_result("negative output offset",
        copy_range(input, &input_offset, output, &output_offset, 1, 0),
        -EOVERFLOW);

    readonly = open_file("/tmp/edgeos-copy-range-output", O_RDONLY);
    failures += expect_result("read-only output",
        copy_range(input, 0, readonly, 0, 0, 0), -EBADF);
    if (readonly >= 0) (void)raw_syscall6(SYS_close, readonly, 0, 0, 0, 0, 0);
    readonly = open_file("/tmp/edgeos-copy-range-output",
                         O_WRONLY | O_APPEND);
    failures += expect_result("append output",
        copy_range(input, 0, readonly, 0, 1, 0), -EBADF);
    if (readonly >= 0) (void)raw_syscall6(SYS_close, readonly, 0, 0, 0, 0, 0);

    directory = open_file("/tmp", O_RDONLY | O_DIRECTORY);
    failures += expect_result("input directory",
        copy_range(directory, 0, output, 0, 0, 0), -EISDIR);
    failures += expect_result("output directory",
        copy_range(input, 0, directory, 0, 1, 0), -EISDIR);
    if (directory >= 0)
        (void)raw_syscall6(SYS_close, directory, 0, 0, 0, 0, 0);
    return failures;
}

static int test_copy_and_offsets(long input, long output) {
    static const char expected[] = {
        0, 0, 0, '2', '3', '4', '5', '6', '7', '8', '9', 0
    };
    char observed[sizeof(expected)] = {0};
    int failures = 0;
    int64_t input_offset = 2;
    int64_t output_offset = 3;
    long copied;

    if (reset_file(output) < 0) return 1;
    (void)raw_syscall6(SYS_lseek, input, 5, SEEK_SET, 0, 0, 0);
    (void)raw_syscall6(SYS_lseek, output, 7, SEEK_SET, 0, 0, 0);
    copied = copy_range(input, &input_offset, output, &output_offset, 8, 0);
    failures += expect_result("explicit copy result", copied, 8);
    failures += expect_result("explicit input offset", input_offset, 10);
    failures += expect_result("explicit output offset", output_offset, 11);
    failures += expect_result("input descriptor offset unchanged",
        raw_syscall6(SYS_lseek, input, 0, SEEK_CUR, 0, 0, 0), 5);
    failures += expect_result("output descriptor offset unchanged",
        raw_syscall6(SYS_lseek, output, 0, SEEK_CUR, 0, 0, 0), 7);
    failures += expect_result("explicit copy readback",
                              read_at_start(output, observed, 11), 11);
    failures += expect_bytes("explicit copy bytes", observed, expected, 11);

    if (reset_file(output) < 0) return failures + 1;
    (void)raw_syscall6(SYS_lseek, input, 4, SEEK_SET, 0, 0, 0);
    copied = copy_range(input, 0, output, 0, 6, 0);
    failures += expect_result("current-offset copy result", copied, 6);
    failures += expect_result("current input offset",
        raw_syscall6(SYS_lseek, input, 0, SEEK_CUR, 0, 0, 0), 10);
    failures += expect_result("current output offset",
        raw_syscall6(SYS_lseek, output, 0, SEEK_CUR, 0, 0, 0), 6);
    return failures;
}

static int test_same_file(long descriptor) {
    int failures = 0;
    int64_t input_offset = 0;
    int64_t output_offset = 1;
    failures += expect_result("overlapping same-file ranges",
        copy_range(descriptor, &input_offset, descriptor, &output_offset,
                   4, 0), -EINVAL);
    output_offset = 12;
    failures += expect_result("nonoverlapping same-file ranges",
        copy_range(descriptor, &input_offset, descriptor, &output_offset,
                   4, 0), 4);
    failures += expect_result("same-file input offset", input_offset, 4);
    failures += expect_result("same-file output offset", output_offset, 16);
    return failures;
}

static int test_copyback_fault(long input, long output) {
    int failures = 0;
    int64_t output_offset = 0;
    int64_t input_offset = 0;
    char observed[3] = {0};
    long page;

    page = raw_syscall6(SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page < 0) return expect_result("copyback mmap", page, 0);
    *(int64_t *)(uintptr_t)page = 0;
    if (raw_syscall6(SYS_mprotect, page, PAGE_SIZE, PROT_READ,
                     0, 0, 0) < 0) {
        (void)raw_syscall6(SYS_munmap, page, PAGE_SIZE, 0, 0, 0, 0);
        return 1;
    }
    (void)reset_file(output);
    failures += expect_result("input offset copyback fault",
        copy_range(input, (int64_t *)(uintptr_t)page, output,
                   &output_offset, 3, 0), -EFAULT);
    failures += expect_result("other offset survives copyback fault",
                              output_offset, 3);
    failures += expect_result("copy completed before copyback fault",
                              read_at_start(output, observed, 3), 3);
    failures += expect_bytes("copyback fault data", observed, "012", 3);

    (void)raw_syscall6(SYS_mprotect, page, PAGE_SIZE,
                       PROT_READ | PROT_WRITE, 0, 0, 0);
    *(int64_t *)(uintptr_t)page = 0;
    (void)raw_syscall6(SYS_mprotect, page, PAGE_SIZE, PROT_READ,
                       0, 0, 0);
    input_offset = 0;
    (void)reset_file(output);
    failures += expect_result("output offset copyback fault",
        copy_range(input, &input_offset, output,
                   (int64_t *)(uintptr_t)page, 2, 0), -EFAULT);
    failures += expect_result("input offset updated before output fault",
                              input_offset, 2);
    (void)raw_syscall6(SYS_munmap, page, PAGE_SIZE, 0, 0, 0, 0);
    return failures;
}

static int test_memfd(long filesystem_output) {
    static const char payload[] = "memfd-copy";
    char observed[sizeof(payload)] = {0};
    int64_t input_offset = 0;
    int64_t output_offset = 0;
    long input;
    long output;
    int failures = 0;

    input = raw_syscall6(SYS_memfd_create, (long)"copy-range-input",
                         0, 0, 0, 0, 0);
    output = raw_syscall6(SYS_memfd_create, (long)"copy-range-output",
                          0, 0, 0, 0, 0);
    if (input < 0 || output < 0) {
        if (input >= 0)
            (void)raw_syscall6(SYS_close, input, 0, 0, 0, 0, 0);
        if (output >= 0)
            (void)raw_syscall6(SYS_close, output, 0, 0, 0, 0, 0);
        return expect_result("memfd setup", input < 0 ? input : output, 0);
    }
    failures += expect_result("write memfd",
        raw_syscall6(SYS_write, input, (long)payload,
                     (long)(sizeof(payload) - 1u), 0, 0, 0),
        (long)(sizeof(payload) - 1u));
    failures += expect_result("memfd copy",
        copy_range(input, &input_offset, output, &output_offset,
                   sizeof(payload) - 1u, 0),
        (long)(sizeof(payload) - 1u));
    failures += expect_result("memfd input offset", input_offset,
                              sizeof(payload) - 1u);
    failures += expect_result("memfd output offset", output_offset,
                              sizeof(payload) - 1u);
    failures += expect_result("memfd readback",
                              read_at_start(output, observed,
                                            sizeof(payload) - 1u),
                              sizeof(payload) - 1u);
    failures += expect_bytes("memfd copy bytes", observed, payload,
                             sizeof(payload) - 1u);
    input_offset = 0;
    output_offset = 0;
    failures += expect_result("cross-filesystem copy",
        copy_range(input, &input_offset, filesystem_output, &output_offset,
                   1, 0), -EXDEV);
    (void)raw_syscall6(SYS_close, input, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, output, 0, 0, 0, 0, 0);
    return failures;
}

static int run_tests(void) {
    static const char payload[] = "0123456789abcdef";
    const char *input_path = "/tmp/edgeos-copy-range-input";
    const char *output_path = "/tmp/edgeos-copy-range-output";
    long input;
    long output;
    int failures = 0;

    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)input_path, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)output_path, 0, 0, 0, 0);
    input = open_file(input_path, O_CREAT | O_TRUNC | O_RDWR);
    output = open_file(output_path, O_CREAT | O_TRUNC | O_RDWR);
    if (input < 0 || output < 0) {
        print_text("FAIL setup\n");
        return 1;
    }
    failures += expect_result("write input",
        raw_syscall6(SYS_write, input, (long)payload,
                     (long)(sizeof(payload) - 1u), 0, 0, 0),
        (long)(sizeof(payload) - 1u));

    failures += test_policy_order(input, output);
    failures += test_copy_and_offsets(input, output);
    failures += test_same_file(input);
    failures += test_copyback_fault(input, output);
    failures += test_memfd(output);

    (void)raw_syscall6(SYS_close, input, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, output, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)input_path, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)output_path, 0, 0, 0, 0);
    if (!failures) print_text("COPY_FILE_RANGE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
