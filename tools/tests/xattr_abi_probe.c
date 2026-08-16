/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux extended-attribute ABI probe for native Linux and EdgeOS guests.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#ifndef SYS_setxattr
#define SYS_setxattr 5
#define SYS_lsetxattr 6
#define SYS_fsetxattr 7
#define SYS_getxattr 8
#define SYS_lgetxattr 9
#define SYS_fgetxattr 10
#define SYS_listxattr 11
#define SYS_llistxattr 12
#define SYS_flistxattr 13
#define SYS_removexattr 14
#define SYS_lremovexattr 15
#define SYS_fremovexattr 16
#endif
#else
#ifndef SYS_setxattr
#define SYS_setxattr 188
#define SYS_lsetxattr 189
#define SYS_fsetxattr 190
#define SYS_getxattr 191
#define SYS_lgetxattr 192
#define SYS_fgetxattr 193
#define SYS_listxattr 194
#define SYS_llistxattr 195
#define SYS_flistxattr 196
#define SYS_removexattr 197
#define SYS_lremovexattr 198
#define SYS_fremovexattr 199
#endif
#endif

#define XATTR_CREATE 1
#define XATTR_REPLACE 2

static const char g_path[] = "/tmp/edgeos-xattr-abi-probe";
static const char g_main_name[] = "user.edgeos.main";
static const char g_link_name[] = "user.edgeos.link";
static const char g_fd_name[] = "user.edgeos.fd";
static const char g_procfd_name[] = "user.edgeos.procfd";
static const char g_missing_name[] = "user.edgeos.missing";
static const char g_value[] = "edgeos-xattr-value";
static char g_read_buffer[64];
static char g_list_buffer[1024];
static char g_long_name[257];
static unsigned char g_large_value[65537];
static int g_failures;

static void record_call(const char *name, long result, int saved_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
}

static void expect_success(const char *name, long result, int saved_errno,
                           long expected) {
    record_call(name, result, saved_errno);
    if (result != expected || saved_errno != 0) ++g_failures;
}

static void expect_error(const char *name, long result, int saved_errno,
                         int expected_errno) {
    record_call(name, result, saved_errno);
    if (result != -1 || saved_errno != expected_errno) ++g_failures;
}

static int list_contains(const char *list, size_t length, const char *name) {
    size_t offset = 0;
    size_t name_length = strlen(name);
    while (offset < length) {
        size_t end = offset;
        while (end < length && list[end]) ++end;
        if (end == length) return 0;
        if (end - offset == name_length &&
            memcmp(list + offset, name, name_length) == 0)
            return 1;
        offset = end + 1u;
    }
    return 0;
}

static void test_set_and_get(int descriptor) {
    long result;
    int saved_errno;
    size_t value_length = sizeof(g_value) - 1u;

    errno = 0;
    result = syscall(SYS_setxattr, g_path, g_main_name, g_value,
                     value_length, XATTR_CREATE);
    expect_success("setxattr_create", result, errno, 0);

    errno = 0;
    result = syscall(SYS_setxattr, g_path, g_main_name, g_value,
                     value_length, XATTR_CREATE);
    expect_error("setxattr_create_existing", result, errno, EEXIST);

    errno = 0;
    result = syscall(SYS_getxattr, g_path, g_main_name, 0, 0);
    expect_success("getxattr_query", result, errno, (long)value_length);

    errno = 0;
    result = syscall(SYS_getxattr, g_path, g_main_name, g_read_buffer,
                     value_length - 1u);
    expect_error("getxattr_short", result, errno, ERANGE);

    memset(g_read_buffer, 0, sizeof(g_read_buffer));
    errno = 0;
    result = syscall(SYS_getxattr, g_path, g_main_name, g_read_buffer,
                     sizeof(g_read_buffer));
    saved_errno = errno;
    expect_success("getxattr_value", result, saved_errno,
                   (long)value_length);
    if (result == (long)value_length &&
        memcmp(g_read_buffer, g_value, value_length) != 0)
        ++g_failures;

    memset(g_read_buffer, 0, sizeof(g_read_buffer));
    errno = 0;
    result = syscall(SYS_lgetxattr, g_path, g_main_name, g_read_buffer,
                     sizeof(g_read_buffer));
    saved_errno = errno;
    expect_success("lgetxattr_value", result, saved_errno,
                   (long)value_length);
    if (result == (long)value_length &&
        memcmp(g_read_buffer, g_value, value_length) != 0)
        ++g_failures;

    memset(g_read_buffer, 0, sizeof(g_read_buffer));
    errno = 0;
    result = syscall(SYS_fgetxattr, descriptor, g_main_name, g_read_buffer,
                     sizeof(g_read_buffer));
    saved_errno = errno;
    expect_success("fgetxattr_value", result, saved_errno,
                   (long)value_length);
    if (result == (long)value_length &&
        memcmp(g_read_buffer, g_value, value_length) != 0)
        ++g_failures;
}

static void test_additional_setters(int descriptor) {
    long result;
    errno = 0;
    result = syscall(SYS_lsetxattr, g_path, g_link_name, g_value,
                     sizeof(g_value) - 1u, 0);
    expect_success("lsetxattr", result, errno, 0);

    errno = 0;
    result = syscall(SYS_fsetxattr, descriptor, g_fd_name, g_value,
                     sizeof(g_value) - 1u, 0);
    expect_success("fsetxattr", result, errno, 0);

    errno = 0;
    result = syscall(SYS_setxattr, g_path, g_missing_name, g_value,
                     sizeof(g_value) - 1u, XATTR_REPLACE);
    expect_error("setxattr_replace_missing", result, errno, ENODATA);
}

static void test_lists(int descriptor) {
    static const long calls[] = {
        SYS_listxattr, SYS_llistxattr, SYS_flistxattr,
    };
    static const char *const names[] = {
        "listxattr", "llistxattr", "flistxattr",
    };
    size_t index;
    for (index = 0; index < sizeof(calls) / sizeof(calls[0]); ++index) {
        long result;
        int saved_errno;
        errno = 0;
        if (calls[index] == SYS_flistxattr)
            result = syscall(calls[index], descriptor, 0, 0);
        else
            result = syscall(calls[index], g_path, 0, 0);
        saved_errno = errno;
        record_call(names[index], result, saved_errno);
        if (result <= 0 || saved_errno != 0 ||
            (size_t)result > sizeof(g_list_buffer)) {
            ++g_failures;
            continue;
        }
        memset(g_list_buffer, 0xa5, sizeof(g_list_buffer));
        errno = 0;
        if (calls[index] == SYS_flistxattr)
            result = syscall(calls[index], descriptor, g_list_buffer,
                             sizeof(g_list_buffer));
        else
            result = syscall(calls[index], g_path, g_list_buffer,
                             sizeof(g_list_buffer));
        saved_errno = errno;
        record_call(names[index], result, saved_errno);
        if (result <= 0 || saved_errno != 0 ||
            !list_contains(g_list_buffer, (size_t)result, g_main_name) ||
            !list_contains(g_list_buffer, (size_t)result, g_link_name) ||
            !list_contains(g_list_buffer, (size_t)result, g_fd_name))
            ++g_failures;
    }
}

static void test_errors(void) {
    long result;
    memset(g_long_name, 'n', sizeof(g_long_name) - 1u);
    g_long_name[sizeof(g_long_name) - 1u] = 0;

    errno = 0;
    result = syscall(SYS_setxattr, g_path, g_main_name, g_value,
                     sizeof(g_value) - 1u, 4);
    expect_error("setxattr_invalid_flags", result, errno, EINVAL);

    errno = 0;
    result = syscall(SYS_setxattr, g_path, "", g_value,
                     sizeof(g_value) - 1u, 0);
    expect_error("setxattr_empty_name", result, errno, ERANGE);

    errno = 0;
    result = syscall(SYS_setxattr, g_path, 0, g_value,
                     sizeof(g_value) - 1u, 0);
    expect_error("setxattr_null_name", result, errno, EFAULT);

    errno = 0;
    result = syscall(SYS_setxattr, g_path, g_long_name, g_value,
                     sizeof(g_value) - 1u, 0);
    expect_error("setxattr_long_name", result, errno, ERANGE);

    errno = 0;
    result = syscall(SYS_setxattr, g_path, g_main_name, g_large_value,
                     sizeof(g_large_value), 0);
    expect_error("setxattr_large_value", result, errno, E2BIG);

    errno = 0;
    result = syscall(SYS_fgetxattr, -1, g_main_name, g_read_buffer,
                     sizeof(g_read_buffer));
    expect_error("fgetxattr_badfd", result, errno, EBADF);
}

static void test_removers(int descriptor) {
    long result;
    errno = 0;
    result = syscall(SYS_fremovexattr, descriptor, g_fd_name);
    expect_success("fremovexattr", result, errno, 0);

    errno = 0;
    result = syscall(SYS_lremovexattr, g_path, g_link_name);
    expect_success("lremovexattr", result, errno, 0);

    errno = 0;
    result = syscall(SYS_removexattr, g_path, g_main_name);
    expect_success("removexattr", result, errno, 0);

    errno = 0;
    result = syscall(SYS_getxattr, g_path, g_main_name, 0, 0);
    expect_error("getxattr_removed", result, errno, ENODATA);
}

static void test_procfd_magic_link(void) {
    char path[64];
    int descriptor;
    long result;

    descriptor = open(g_path, O_PATH | O_CLOEXEC);
    if (descriptor < 0) {
        record_call("procfd_open", -1, errno);
        ++g_failures;
        return;
    }
    snprintf(path, sizeof(path), "/proc/self/fd/%d", descriptor);

    errno = 0;
    result = syscall(SYS_setxattr, path, g_procfd_name, g_value,
                     sizeof(g_value) - 1u, XATTR_CREATE);
    expect_success("procfd_setxattr", result, errno, 0);

    errno = 0;
    result = syscall(SYS_getxattr, path, g_procfd_name, 0, 0);
    expect_success("procfd_getxattr", result, errno,
                   (long)(sizeof(g_value) - 1u));

    errno = 0;
    result = syscall(SYS_removexattr, path, g_procfd_name);
    expect_success("procfd_removexattr", result, errno, 0);

    errno = 0;
    result = syscall(SYS_removexattr, path, g_procfd_name);
    expect_error("procfd_removexattr_missing", result, errno, ENODATA);
    close(descriptor);
}

int main(void) {
    int descriptor;
    unlink(g_path);
    descriptor = open(g_path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (descriptor < 0) {
        dprintf(STDOUT_FILENO, "xattr_probe_open_errno:%d\n", errno);
        return 1;
    }
    test_set_and_get(descriptor);
    test_additional_setters(descriptor);
    test_lists(descriptor);
    test_errors();
    test_procfd_magic_link();
    test_removers(descriptor);
    close(descriptor);
    unlink(g_path);
    dprintf(STDOUT_FILENO, "XATTR_ABI_PROBE_%s failures:%d\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
