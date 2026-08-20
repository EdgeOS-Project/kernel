/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux xattrat ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_openat 257
#define SYS_unlinkat 263
#elif defined(__aarch64__)
#define SYS_unlinkat 35
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#else
#error "xattrat_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_setxattrat 463
#define SYS_getxattrat 464
#define SYS_listxattrat 465
#define SYS_removexattrat 466

#define AT_FDCWD (-100)
#define AT_EMPTY_PATH 0x1000u
#define O_RDWR 2u
#define O_CREAT 64u
#define O_EXCL 128u
#define O_DIRECTORY 65536u
#define E2BIG 7
#define EBADF 9
#define EFAULT 14
#define EEXIST 17
#define EINVAL 22
#define ERANGE 34
#define ENODATA 61
#define XATTR_CREATE 1u

struct xattr_args {
    uint64_t value;
    uint32_t size;
    uint32_t flags;
};

struct extended_xattr_args {
    struct xattr_args current;
    uint64_t extension;
};

static const char g_path[] = "/tmp/edgeos-xattrat-abi-probe";
static const char g_relative_path[] = "edgeos-xattrat-abi-probe";
static const char g_name[] = "user.edgeos.xattrat";
static const char g_fd_name[] = "user.edgeos.xattrat.fd";
static const char g_relative_name[] = "user.edgeos.xattrat.relative";
static const char g_extension_name[] = "user.edgeos.xattrat.extension";
static const char g_value[] = "edgeos-xattrat-value";
static char g_read_buffer[64];
static char g_list_buffer[512];

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

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = (unsigned char)value;
    return destination;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static int bytes_equal(const char *left, const char *right,
                       unsigned long length) {
    unsigned long index;
    for (index = 0; index < length; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
}

static void print_integer(int64_t value) {
    char buffer[32];
    char digits[24];
    unsigned long length = 0;
    unsigned long count = 0;
    uint64_t magnitude;
    if (value < 0) {
        buffer[length++] = '-';
        magnitude = (uint64_t)(-(value + 1)) + 1u;
    } else {
        magnitude = (uint64_t)value;
    }
    do {
        digits[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    while (count) buffer[length++] = digits[--count];
    buffer[length++] = '\n';
    (void)raw_syscall6(SYS_write, 1, (long)buffer, (long)length,
                       0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\nactual/expected\n");
    print_integer(actual);
    print_integer(expected);
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int list_contains(const char *list, uint32_t length,
                         const char *name) {
    uint32_t offset = 0;
    uint32_t name_length = (uint32_t)text_length(name);
    while (offset < length) {
        uint32_t end = offset;
        while (end < length && list[end]) ++end;
        if (end == length) return 0;
        if (end - offset == name_length &&
            bytes_equal(list + offset, name, name_length))
            return 1;
        offset = end + 1u;
    }
    return 0;
}

static long set_attribute(long descriptor, const char *path,
                          uint32_t at_flags, const char *name,
                          uint32_t flags) {
    struct xattr_args arguments = {
        (uint64_t)(uintptr_t)g_value,
        sizeof(g_value) - 1u,
        flags,
    };
    return raw_syscall6(
        SYS_setxattrat, descriptor, (long)path, at_flags, (long)name,
        (long)&arguments, sizeof(arguments));
}

static int run_tests(void) {
    struct xattr_args arguments;
    struct extended_xattr_args extended;
    long descriptor;
    long directory_descriptor;
    long result;
    int failures = 0;

    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)g_path,
                       0, 0, 0, 0);
    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)g_path,
        O_CREAT | O_EXCL | O_RDWR, 0600, 0, 0);
    failures += expect_true("create probe file", descriptor >= 0);
    if (descriptor < 0) return failures;

    failures += expect("setxattrat path",
        set_attribute(AT_FDCWD, g_path, 0, g_name, XATTR_CREATE), 0);
    failures += expect("setxattrat create existing",
        set_attribute(AT_FDCWD, g_path, 0, g_name, XATTR_CREATE), -EEXIST);

    memset(g_read_buffer, 0, sizeof(g_read_buffer));
    arguments.value = (uint64_t)(uintptr_t)g_read_buffer;
    arguments.size = sizeof(g_read_buffer);
    arguments.flags = 0;
    result = raw_syscall6(
        SYS_getxattrat, AT_FDCWD, (long)g_path, 0, (long)g_name,
        (long)&arguments, sizeof(arguments));
    failures += expect("getxattrat path", result, sizeof(g_value) - 1u);
    failures += expect_true("getxattrat value",
        bytes_equal(g_read_buffer, g_value, sizeof(g_value) - 1u));

    memset(g_list_buffer, 0, sizeof(g_list_buffer));
    result = raw_syscall6(
        SYS_listxattrat, AT_FDCWD, (long)g_path, 0,
        (long)g_list_buffer, sizeof(g_list_buffer), 0);
    failures += expect_true("listxattrat path", result > 0);
    if (result > 0)
        failures += expect_true("listxattrat contains name",
            list_contains(g_list_buffer, (uint32_t)result, g_name));

    failures += expect("removexattrat path", raw_syscall6(
        SYS_removexattrat, AT_FDCWD, (long)g_path, 0,
        (long)g_name, 0, 0), 0);
    failures += expect("getxattrat removed", raw_syscall6(
        SYS_getxattrat, AT_FDCWD, (long)g_path, 0, (long)g_name,
        (long)&arguments, sizeof(arguments)), -ENODATA);

    failures += expect("setxattrat empty path",
        set_attribute(descriptor, "", AT_EMPTY_PATH, g_fd_name, 0), 0);
    failures += expect("getxattrat null path", raw_syscall6(
        SYS_getxattrat, descriptor, 0, AT_EMPTY_PATH, (long)g_fd_name,
        (long)&arguments, sizeof(arguments)), sizeof(g_value) - 1u);
    failures += expect("removexattrat empty path", raw_syscall6(
        SYS_removexattrat, descriptor, (long)"", AT_EMPTY_PATH,
        (long)g_fd_name, 0, 0), 0);
    failures += expect("setxattrat bad empty fd",
        set_attribute(-1, "", AT_EMPTY_PATH, g_fd_name, 0), -EBADF);

    directory_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)"/tmp", O_DIRECTORY, 0, 0, 0);
    failures += expect_true("open relative directory",
                            directory_descriptor >= 0);
    if (directory_descriptor >= 0) {
        failures += expect("setxattrat relative path", set_attribute(
            directory_descriptor, g_relative_path, 0,
            g_relative_name, 0), 0);
        failures += expect("getxattrat relative path", raw_syscall6(
            SYS_getxattrat, directory_descriptor, (long)g_relative_path,
            0, (long)g_relative_name, (long)&arguments,
            sizeof(arguments)), sizeof(g_value) - 1u);
        failures += expect("removexattrat relative path", raw_syscall6(
            SYS_removexattrat, directory_descriptor,
            (long)g_relative_path, 0, (long)g_relative_name, 0, 0), 0);
        (void)raw_syscall6(
            SYS_close, directory_descriptor, 0, 0, 0, 0, 0);
    }

    extended.current.value = (uint64_t)(uintptr_t)g_value;
    extended.current.size = sizeof(g_value) - 1u;
    extended.current.flags = 0;
    extended.extension = 0;
    failures += expect("setxattrat zero extension", raw_syscall6(
        SYS_setxattrat, AT_FDCWD, (long)g_path, 0,
        (long)g_extension_name, (long)&extended, sizeof(extended)), 0);
    extended.extension = 1;
    failures += expect("setxattrat nonzero extension", raw_syscall6(
        SYS_setxattrat, AT_FDCWD, (long)g_path, 0,
        (long)g_name, (long)&extended, sizeof(extended)), -E2BIG);
    failures += expect("removexattrat extension", raw_syscall6(
        SYS_removexattrat, AT_FDCWD, (long)g_path, 0,
        (long)g_extension_name, 0, 0), 0);

    failures += expect("setxattrat short args", raw_syscall6(
        SYS_setxattrat, AT_FDCWD, (long)g_path, 0, (long)g_name,
        (long)&arguments, sizeof(arguments) - 1u), -EINVAL);
    failures += expect("setxattrat oversize args", raw_syscall6(
        SYS_setxattrat, AT_FDCWD, (long)g_path, 0, (long)g_name,
        (long)&arguments, 4097), -E2BIG);
    arguments.flags = 1;
    failures += expect("getxattrat nonzero flags", raw_syscall6(
        SYS_getxattrat, AT_FDCWD, (long)g_path, 0, (long)g_name,
        (long)&arguments, sizeof(arguments)), -EINVAL);
    failures += expect("removexattrat invalid at flags", raw_syscall6(
        SYS_removexattrat, AT_FDCWD, (long)g_path, 0x80000000u,
        0, 0, 0), -EINVAL);
    failures += expect("listxattrat empty without flag", raw_syscall6(
        SYS_listxattrat, AT_FDCWD, (long)"", 0, 0, 0, 0), -2);

    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)g_path,
                       0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_tests();
    print_text(failures ? "xattrat-abi: FAIL\n" : "xattrat-abi: PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
