/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux openat2 ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_fstat 5
#define SYS_exit 60
#define SYS_creat 85
#define SYS_openat 257
#define SYS_openat2 437
#define SYS_unlinkat 263
#define O_DIRECTORY 0x10000
#define O_NOFOLLOW 0x20000
#define O_LARGEFILE 0x8000
#define O_TMPFILE 0x410000
#define STAT_MODE_OFFSET 24
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_fstat 80
#define SYS_exit 93
#define SYS_openat 56
#define SYS_openat2 437
#define SYS_unlinkat 35
#define O_DIRECTORY 0x4000
#define O_NOFOLLOW 0x8000
#define O_LARGEFILE 0x20000
#define O_TMPFILE 0x404000
#define STAT_MODE_OFFSET 16
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "openat2_abi_probe requires a Linux 64-bit architecture"
#endif

#define E2BIG 7
#define EAGAIN 11
#define EFAULT 14
#define ENOENT 2
#define EXDEV 18
#define EINVAL 22
#define ENOTDIR 20
#define ELOOP 40
#define EOPNOTSUPP 95

#define AT_FDCWD (-100)
#define O_WRONLY 0x1
#define O_RDWR 0x2
#define O_CREAT 0x40
#define O_TRUNC 0x200
#define O_CLOEXEC 0x80000
#define O_PATH 0x200000
#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
#define RESOLVE_CACHED 0x20

struct open_how_test {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
    uint64_t extra;
};

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

static int expect_descriptor(const char *name, long descriptor) {
    if (descriptor >= 0) {
        return expect_result(name,
                             raw_syscall6(SYS_close, descriptor, 0, 0,
                                          0, 0, 0), 0);
    }
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(descriptor);
    print_text("\n");
    return 1;
}

static int expect_descriptor_mode(const char *name, long descriptor,
                                  uint32_t expected_mode) {
    uint8_t stat_buffer[160];
    uint32_t actual_mode;
    int failures = 0;

    if (descriptor < 0) return expect_descriptor(name, descriptor);
    for (unsigned long index = 0; index < sizeof(stat_buffer); ++index)
        stat_buffer[index] = 0;
    failures += expect_result(
        "fstat created descriptor",
        raw_syscall6(SYS_fstat, descriptor, (long)stat_buffer,
                     0, 0, 0, 0), 0);
    actual_mode = *(uint32_t *)(void *)(stat_buffer + STAT_MODE_OFFSET);
    if ((actual_mode & 07777u) != expected_mode) {
        print_text("FAIL ");
        print_text(name);
        print_text(" mode=");
        print_number(actual_mode & 07777u);
        print_text(" expected=");
        print_number(expected_mode);
        print_text("\n");
        ++failures;
    }
    failures += expect_result(
        "close mode descriptor",
        raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    return failures;
}

static int expect_elf_descriptor(const char *name, long descriptor) {
    uint8_t header[4];
    long count;
    int failures = 0;
    if (descriptor < 0) return expect_descriptor(name, descriptor);
    count = raw_syscall6(SYS_read, descriptor, (long)header,
                         sizeof(header), 0, 0, 0);
    if (count != (long)sizeof(header) || header[0] != 0x7fu ||
        header[1] != 'E' || header[2] != 'L' || header[3] != 'F') {
        print_text("FAIL ");
        print_text(name);
        print_text(" did not resolve to ELF\n");
        failures = 1;
    }
    failures += expect_result(
        "close ELF descriptor",
        raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    return failures;
}

static long open_how(const char *path, struct open_how_test *how,
                     unsigned long size) {
    return raw_syscall6(SYS_openat2, AT_FDCWD, (long)path, (long)how,
                        (long)size, 0, 0);
}

static long open_how_at(long directory, const char *path,
                        struct open_how_test *how, unsigned long size) {
    return raw_syscall6(SYS_openat2, directory, (long)path, (long)how,
                        (long)size, 0, 0);
}

static void proc_descriptor_path(char *path, long descriptor) {
    static const char prefix[] = "/proc/self/fd/";
    char digits[24];
    unsigned long value = (unsigned long)descriptor;
    unsigned int count = 0;
    unsigned int offset = 0;

    while (prefix[offset]) {
        path[offset] = prefix[offset];
        ++offset;
    }
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    while (count) path[offset++] = digits[--count];
    path[offset] = 0;
}

static long open_at(const char *path, long flags) {
    return raw_syscall6(SYS_openat, AT_FDCWD, (long)path, flags,
                        0, 0, 0);
}

static void remove_path(const char *path) {
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);
}

static int run_tests(void) {
    static const char null_path[] = "/dev/null";
    static const char regular_path[] = "/bin/ls";
    static const char symlink_path[] = "/bin/sh";
    static const char temporary_directory[] = "/tmp";
    static const char created_path[] = "/tmp/edgeos-open-abi-probe";
    struct open_how_test how = {0, 0, 0, 0};
    long result;
    int failures = 0;

    result = open_how(null_path, &how, 24);
    failures += expect_descriptor("basic open", result);

    failures += expect_result(
        "short structure", open_how(null_path, &how, 23), -EINVAL);
    failures += expect_result(
        "null structure",
        raw_syscall6(SYS_openat2, AT_FDCWD, (long)null_path, 0, 24, 0, 0),
        -EFAULT);

    how.extra = 0;
    result = open_how(null_path, &how, sizeof(how));
    failures += expect_descriptor("zero extension", result);
    how.extra = 1;
    failures += expect_result(
        "nonzero extension", open_how(null_path, &how, sizeof(how)), -E2BIG);
    how.extra = 0;

    how.flags = 1ull << 63;
    failures += expect_result(
        "unknown open flag", open_how(null_path, &how, 24), -EINVAL);
    how.flags = 0;
    how.mode = 0600;
    failures += expect_result(
        "mode without create", open_how(null_path, &how, 24), -EINVAL);
    how.mode = 0;
    how.resolve = 1ull << 63;
    failures += expect_result(
        "unknown resolve flag", open_how(null_path, &how, 24), -EINVAL);
    how.resolve = RESOLVE_BENEATH | RESOLVE_IN_ROOT;
    failures += expect_result(
        "incompatible resolve flags", open_how(null_path, &how, 24),
        -EINVAL);
    how.resolve = RESOLVE_NO_XDEV;
    result = open_how(null_path, &how, 24);
    if (result >= 0) {
        failures += expect_result(
            "close resolved open",
            raw_syscall6(SYS_close, result, 0, 0, 0, 0, 0), 0);
    } else if (result != -EOPNOTSUPP && result != -EXDEV) {
        failures += expect_result("known resolve request", result,
                                  -EOPNOTSUPP);
    }
    how.resolve = 0;

    result = open_at(symlink_path, 0);
    failures += expect_elf_descriptor("openat follows symlink", result);
    result = open_at(symlink_path, O_LARGEFILE);
    failures += expect_elf_descriptor(
        "openat largefile follows symlink", result);
    failures += expect_result(
        "openat nofollow rejects symlink",
        open_at(symlink_path, O_NOFOLLOW), -ELOOP);

    {
        char descriptor_path[48];
        long directory = open_at("/bin", O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (directory < 0) {
            failures += expect_descriptor("constraint directory", directory);
        } else {
            failures += expect_descriptor(
                "dirfd baseline",
                raw_syscall6(SYS_openat, directory, (long)"sh",
                             O_PATH | O_CLOEXEC, 0, 0, 0));
            how.flags = O_PATH | O_CLOEXEC;
            how.mode = 0;
            how.resolve = RESOLVE_BENEATH;
            failures += expect_descriptor(
                "beneath internal symlink",
                open_how_at(directory, "sh", &how, 24));
            failures += expect_result(
                "beneath parent escape",
                open_how_at(directory, "../etc/passwd", &how, 24),
                -EXDEV);
            failures += expect_result(
                "beneath absolute escape",
                open_how_at(directory, "/etc/passwd", &how, 24),
                -EXDEV);

            how.resolve = RESOLVE_IN_ROOT;
            failures += expect_descriptor(
                "in-root absolute path",
                open_how_at(directory, "/ls", &how, 24));
            failures += expect_descriptor(
                "in-root parent clamp",
                open_how_at(directory, "../../ls", &how, 24));
            failures += expect_result(
                "in-root absolute symlink target",
                open_how_at(directory, "/awk", &how, 24), -ENOENT);

            how.resolve = RESOLVE_NO_SYMLINKS;
            failures += expect_result(
                "no symlinks", open_how(symlink_path, &how, 24),
                -ELOOP);
            proc_descriptor_path(descriptor_path, directory);
            how.resolve = RESOLVE_NO_MAGICLINKS;
            failures += expect_result(
                "no proc magic links",
                open_how(descriptor_path, &how, 24), -ELOOP);
            failures += expect_result(
                "close constraint directory",
                raw_syscall6(SYS_close, directory, 0, 0, 0, 0, 0), 0);
        }
    }

    how.flags = O_PATH | O_CLOEXEC;
    how.mode = 0;
    how.resolve = 0;
    failures += expect_descriptor(
        "cached warmup", open_how("/usr/bin/ls", &how, 24));
    how.resolve = RESOLVE_CACHED;
    failures += expect_descriptor(
        "cached path hit", open_how("/usr/bin/ls", &how, 24));
    failures += expect_result(
        "cached path miss",
        open_how("/usr/bin/edgeos-openat2-cache-miss", &how, 24),
        -EAGAIN);
    how.resolve = 0;

    remove_path(created_path);
    result = raw_syscall6(SYS_openat, AT_FDCWD, (long)created_path,
                          O_CREAT | O_WRONLY | O_TRUNC, 0, 0, 0);
    failures += expect_descriptor_mode("openat creates mode zero", result, 0);
    remove_path(created_path);

#if defined(__x86_64__)
    result = raw_syscall6(SYS_open, (long)symlink_path, 0, 0, 0, 0, 0);
    failures += expect_elf_descriptor("open alias follows symlink", result);
    remove_path(created_path);
    result = raw_syscall6(SYS_creat, (long)created_path, 0600, 0, 0, 0, 0);
    failures += expect_descriptor_mode("creat alias", result, 0600);
    remove_path(created_path);
#endif

    how.flags = O_DIRECTORY;
    failures += expect_result(
        "directory requires directory",
        open_how(regular_path, &how, 24), -ENOTDIR);
    how.flags = O_NOFOLLOW;
    failures += expect_result(
        "nofollow rejects symlink", open_how(symlink_path, &how, 24),
        -ELOOP);
    how.flags = O_PATH | O_NOFOLLOW | O_CLOEXEC;
    result = open_how(symlink_path, &how, 24);
    failures += expect_descriptor("path nofollow symlink", result);

    how.flags = O_TMPFILE | O_RDWR | O_CLOEXEC;
    how.mode = 0600;
    result = open_how(temporary_directory, &how, 24);
    failures += expect_descriptor("anonymous temporary file", result);

    if (!failures) print_text("OPENAT2_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

START_ATTRIBUTES void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
