/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux getdents64 ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_getdents64 217
#define SYS_openat 257
#define SYS_unlinkat 263
#define O_DIRECTORY 0x10000
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_unlinkat 35
#define SYS_openat 56
#define SYS_close 57
#define SYS_getdents64 61
#define SYS_write 64
#define SYS_exit 93
#define O_DIRECTORY 0x4000
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "getdents64_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EFAULT 14
#define ENOTDIR 20
#define EINVAL 22

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0x40
#define O_EXCL 0x80

struct linux_dirent64_test {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

_Static_assert(__builtin_offsetof(struct linux_dirent64_test, d_name) == 19,
               "Linux dirent64 name offset");

static uint8_t directory_buffer[4096];

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

static int string_equal(const char *left, const char *right) {
    unsigned long index = 0;
    while (left[index] && right[index] && left[index] == right[index])
        ++index;
    return left[index] == right[index];
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

static long open_path(const char *path, long flags, long mode) {
    return raw_syscall6(SYS_openat, AT_FDCWD, (long)path, flags,
                        mode, 0, 0);
}

static long read_directory(long descriptor, void *buffer,
                           unsigned long capacity) {
    return raw_syscall6(SYS_getdents64, descriptor, (long)buffer,
                        (long)capacity, 0, 0, 0);
}

static int valid_directory_type(uint8_t type) {
    return type == 0 || type == 1 || type == 2 || type == 4 ||
           type == 6 || type == 8 || type == 10 || type == 12 ||
           type == 14;
}

static int parse_records(long byte_count, int *found_nonzero_offset,
                         int *found_dot, int *found_dotdot,
                         int *found_created) {
    static const char created_name[] = "edgeos-getdents64-abi-probe";
    unsigned long position = 0;
    int failures = 0;

    while (position < (unsigned long)byte_count) {
        struct linux_dirent64_test *entry =
            (struct linux_dirent64_test *)(void *)(directory_buffer + position);
        unsigned long name_capacity;
        unsigned long name_length = 0;

        if (entry->d_reclen < 24 || (entry->d_reclen & 7u) != 0 ||
            entry->d_reclen > (unsigned long)byte_count - position) {
            print_text("FAIL malformed dirent64 record\n");
            return failures + 1;
        }
        name_capacity = entry->d_reclen - 19u;
        while (name_length < name_capacity && entry->d_name[name_length])
            ++name_length;
        if (name_length == name_capacity) {
            print_text("FAIL unterminated dirent64 name\n");
            ++failures;
        } else {
            if (string_equal(entry->d_name, ".")) *found_dot = 1;
            if (string_equal(entry->d_name, "..")) *found_dotdot = 1;
            if (string_equal(entry->d_name, created_name)) *found_created = 1;
        }
        if (!entry->d_ino) {
            print_text("FAIL zero dirent64 inode\n");
            ++failures;
        }
        if (entry->d_off) *found_nonzero_offset = 1;
        if (!valid_directory_type(entry->d_type)) {
            print_text("FAIL invalid dirent64 type\n");
            ++failures;
        }
        position += entry->d_reclen;
    }
    if (position != (unsigned long)byte_count) {
        print_text("FAIL dirent64 byte count boundary\n");
        ++failures;
    }
    return failures;
}

static int run_tests(void) {
    static const char temporary_directory[] = "/tmp";
    static const char regular_file[] = "/dev/null";
    static const char created_path[] =
        "/tmp/edgeos-getdents64-abi-probe";
    long descriptor;
    long result;
    unsigned int enumeration_calls = 0;
    int found_nonzero_offset = 0;
    int found_dot = 0;
    int found_dotdot = 0;
    int found_created = 0;
    int failures = 0;

    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)created_path,
                       0, 0, 0, 0);
    descriptor = open_path(created_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) {
        print_text("FAIL create enumeration target actual=");
        print_number(descriptor);
        print_text("\n");
        ++failures;
    } else {
        failures += expect_result(
            "close enumeration target",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    failures += expect_result(
        "invalid descriptor",
        read_directory(-1, directory_buffer, sizeof(directory_buffer)),
        -EBADF);

    descriptor = open_path(regular_file, O_RDONLY, 0);
    if (descriptor < 0) {
        print_text("FAIL open regular file actual=");
        print_number(descriptor);
        print_text("\n");
        ++failures;
    } else {
        failures += expect_result(
            "regular file is not directory",
            read_directory(descriptor, directory_buffer,
                           sizeof(directory_buffer)),
            -ENOTDIR);
        failures += expect_result(
            "close regular file",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    descriptor = open_path(temporary_directory, O_RDONLY | O_DIRECTORY, 0);
    if (descriptor < 0) {
        print_text("FAIL open small-buffer directory actual=");
        print_number(descriptor);
        print_text("\n");
        ++failures;
    } else {
        failures += expect_result(
            "too-small record buffer",
            read_directory(descriptor, directory_buffer, 1), -EINVAL);
        failures += expect_result(
            "invalid output buffer",
            read_directory(descriptor, (void *)1, sizeof(directory_buffer)),
            -EFAULT);
        failures += expect_result(
            "close small-buffer directory",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    descriptor = open_path(temporary_directory, O_RDONLY | O_DIRECTORY, 0);
    if (descriptor < 0) {
        print_text("FAIL open partial directory actual=");
        print_number(descriptor);
        print_text("\n");
        ++failures;
    } else {
        result = read_directory(descriptor, directory_buffer, 24);
        if (result != 24) {
            print_text("FAIL single-record read actual=");
            print_number(result);
            print_text(" expected=24\n");
            ++failures;
        } else {
            failures += parse_records(result, &found_nonzero_offset,
                                      &found_dot, &found_dotdot,
                                      &found_created);
        }
        do {
            result = read_directory(descriptor, directory_buffer,
                                    sizeof(directory_buffer));
            if (result < 0) {
                print_text("FAIL directory enumeration actual=");
                print_number(result);
                print_text("\n");
                ++failures;
                break;
            }
            failures += parse_records(result, &found_nonzero_offset,
                                      &found_dot, &found_dotdot,
                                      &found_created);
            ++enumeration_calls;
            if (enumeration_calls > 1024u) {
                print_text("FAIL directory enumeration did not reach EOF\n");
                ++failures;
                break;
            }
        } while (result > 0);
        if (!found_nonzero_offset || !found_dot || !found_dotdot ||
            !found_created) {
            print_text("FAIL expected directory entries missing\n");
            ++failures;
        }
        if (result == 0) {
            failures += expect_result(
                "stable end of directory",
                read_directory(descriptor, directory_buffer,
                               sizeof(directory_buffer)), 0);
        }
        failures += expect_result(
            "close enumerated directory",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    failures += expect_result(
        "remove enumeration target",
        raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)created_path,
                     0, 0, 0, 0), 0);
    return failures;
}

START_ATTRIBUTES void _start(void) {
    int failures = run_tests();
    if (failures) {
        print_text("GETDENTS64_ABI_PROBE_FAILED failures=");
        print_number(failures);
        print_text("\n");
    } else {
        print_text("GETDENTS64_ABI_PROBE_PASS\n");
    }
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
