/* SPDX-License-Identifier: MPL-2.0 */
/* Raw native x86_64 Linux getdents ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "getdents_abi_probe requires x86_64"
#endif

#define SYS_write 1
#define SYS_close 3
#define SYS_getdents 78
#define SYS_exit 60
#define SYS_openat 257
#define SYS_unlinkat 263

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0x40
#define O_EXCL 0x80
#define O_DIRECTORY 0x10000

#define EBADF 9
#define EFAULT 14
#define ENOTDIR 20
#define EINVAL 22

struct linux_dirent_test {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    char d_name[];
};

_Static_assert(__builtin_offsetof(struct linux_dirent_test, d_name) == 18,
               "Linux native dirent name offset");

static uint8_t g_buffer[4096];

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

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static int text_equal(const char *left, const char *right) {
    unsigned long index = 0;
    while (left[index] && right[index] && left[index] == right[index])
        ++index;
    return left[index] == right[index];
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
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
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count,
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
    return raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path, flags, mode, 0, 0);
}

static long read_directory(long descriptor, void *buffer,
                           unsigned long capacity) {
    return raw_syscall6(
        SYS_getdents, descriptor, (long)buffer, (long)capacity, 0, 0, 0);
}

static int valid_type(uint8_t type) {
    return type == 0u || type == 1u || type == 2u || type == 4u ||
           type == 6u || type == 8u || type == 10u || type == 12u ||
           type == 14u;
}

static int parse_records(long byte_count, int *found_offset,
                         int *found_dot, int *found_dotdot,
                         int *found_created) {
    static const char created_name[] = "edgeos-getdents-abi-probe";
    unsigned long position = 0;
    int failures = 0;

    while (position < (unsigned long)byte_count) {
        struct linux_dirent_test *entry =
            (struct linux_dirent_test *)(void *)(g_buffer + position);
        unsigned long name_limit;
        unsigned long name_length = 0;
        uint8_t type;

        if (entry->d_reclen < 24u || (entry->d_reclen & 7u) != 0u ||
            entry->d_reclen > (unsigned long)byte_count - position) {
            print_text("FAIL malformed native dirent record\n");
            return failures + 1;
        }
        type = g_buffer[position + entry->d_reclen - 1u];
        name_limit = entry->d_reclen - 19u;
        while (name_length < name_limit && entry->d_name[name_length])
            ++name_length;
        if (name_length == name_limit) {
            print_text("FAIL unterminated native dirent name\n");
            ++failures;
        } else {
            if (text_equal(entry->d_name, ".")) *found_dot = 1;
            if (text_equal(entry->d_name, "..")) *found_dotdot = 1;
            if (text_equal(entry->d_name, created_name)) *found_created = 1;
        }
        if (!entry->d_ino) {
            print_text("FAIL zero native dirent inode\n");
            ++failures;
        }
        if (entry->d_off) *found_offset = 1;
        if (!valid_type(type)) {
            print_text("FAIL invalid native dirent type\n");
            ++failures;
        }
        position += entry->d_reclen;
    }
    if (position != (unsigned long)byte_count) {
        print_text("FAIL native dirent byte boundary\n");
        ++failures;
    }
    return failures;
}

static int run_tests(void) {
    static const char created_path[] = "/tmp/edgeos-getdents-abi-probe";
    long descriptor;
    long result;
    unsigned int calls = 0;
    int found_offset = 0;
    int found_dot = 0;
    int found_dotdot = 0;
    int found_created = 0;
    int failures = 0;

    (void)raw_syscall6(
        SYS_unlinkat, AT_FDCWD, (long)created_path, 0, 0, 0, 0);
    descriptor = open_path(created_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) {
        print_text("FAIL create enumeration target\n");
        ++failures;
    } else {
        failures += expect_result("close target", raw_syscall6(
            SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    failures += expect_result("bad descriptor", read_directory(
        -1, g_buffer, sizeof(g_buffer)), -EBADF);
    descriptor = open_path("/dev/null", O_RDONLY, 0);
    if (descriptor >= 0) {
        failures += expect_result("not directory", read_directory(
            descriptor, g_buffer, sizeof(g_buffer)), -ENOTDIR);
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    } else {
        print_text("FAIL open regular file\n");
        ++failures;
    }

    descriptor = open_path("/tmp", O_RDONLY | O_DIRECTORY, 0);
    if (descriptor < 0) return failures + 1;
    failures += expect_result(
        "small buffer", read_directory(descriptor, g_buffer, 1), -EINVAL);
    failures += expect_result("bad output", read_directory(
        descriptor, (void *)1, sizeof(g_buffer)), -EFAULT);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);

    descriptor = open_path("/tmp", O_RDONLY | O_DIRECTORY, 0);
    if (descriptor < 0) return failures + 1;
    do {
        result = read_directory(descriptor, g_buffer, sizeof(g_buffer));
        if (result < 0) {
            print_text("FAIL enumerate directory\n");
            ++failures;
            break;
        }
        failures += parse_records(result, &found_offset, &found_dot,
                                  &found_dotdot, &found_created);
        if (++calls > 1024u) {
            print_text("FAIL enumeration did not reach EOF\n");
            ++failures;
            break;
        }
    } while (result > 0);
    if (!found_offset || !found_dot || !found_dotdot || !found_created) {
        print_text("FAIL expected native directory entries missing\n");
        ++failures;
    }
    if (result == 0)
        failures += expect_result("stable EOF", read_directory(
            descriptor, g_buffer, sizeof(g_buffer)), 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    failures += expect_result("remove target", raw_syscall6(
        SYS_unlinkat, AT_FDCWD, (long)created_path, 0, 0, 0, 0), 0);
    return failures;
}

__attribute__((noreturn, force_align_arg_pointer))
void _start(void) {
    int failures = run_tests();
    print_text(failures ? "GETDENTS_ABI_PROBE_FAILED\n" :
                          "GETDENTS_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
