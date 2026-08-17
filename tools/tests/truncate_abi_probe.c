/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux truncate and ftruncate ABI probe for native and guest parity.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#ifndef SYS_truncate
#define SYS_truncate 45
#define SYS_ftruncate 46
#define SYS_memfd_create 279
#endif
#else
#ifndef SYS_truncate
#define SYS_truncate 76
#define SYS_ftruncate 77
#define SYS_memfd_create 319
#endif
#endif

#define EDGE_MFD_ALLOW_SEALING 0x0002u

static const char g_path[] = "/root/edgeos-truncate-abi-probe";
static const char g_link[] = "/root/edgeos-truncate-abi-link";
static int g_failures;

static void expect_result(const char *name, long result, int saved_errno,
                          long expected_result, int expected_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != expected_result || saved_errno != expected_errno)
        ++g_failures;
}

static void expect_truncate(const char *name, const char *path,
                            int64_t length, long expected_result,
                            int expected_errno) {
    long result;
    int saved_errno;
    errno = 0;
    result = syscall(SYS_truncate, path, length);
    saved_errno = errno;
    expect_result(name, result, saved_errno, expected_result, expected_errno);
}

static void expect_ftruncate(const char *name, int descriptor,
                             int64_t length, long expected_result,
                             int expected_errno) {
    long result;
    int saved_errno;
    errno = 0;
    result = syscall(SYS_ftruncate, descriptor, length);
    saved_errno = errno;
    expect_result(name, result, saved_errno, expected_result, expected_errno);
}

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
    size_t index;
    for (index = 0; index < length; ++index)
        if (bytes[index]) return 0;
    return 1;
}

static void test_path_truncate(int descriptor, int observer) {
    struct stat status;
    uint8_t bytes[4];

    if (write(descriptor, "abcdefghij", 10) != 10) {
        dprintf(STDOUT_FILENO, "path_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }
    expect_truncate("path_shrink", g_path, 4, 0, 0);
    if (stat(g_path, &status) < 0 || status.st_size != 4) ++g_failures;
    if (fstat(observer, &status) < 0 || status.st_size != 4) ++g_failures;
    dprintf(STDOUT_FILENO, "path_shrink_size:%lld\n",
            (long long)status.st_size);
    expect_truncate("path_extend", g_path, 8, 0, 0);
    memset(bytes, 0xa5, sizeof(bytes));
    if (pread(descriptor, bytes, sizeof(bytes), 4) != (ssize_t)sizeof(bytes) ||
        !bytes_are_zero(bytes, sizeof(bytes)))
        ++g_failures;
    dprintf(STDOUT_FILENO, "path_extend_zero:%d\n",
            bytes_are_zero(bytes, sizeof(bytes)));

    unlink(g_link);
    if (symlink(g_path, g_link) < 0) {
        dprintf(STDOUT_FILENO, "path_symlink_setup_errno:%d\n", errno);
        ++g_failures;
    } else {
        expect_truncate("path_symlink_follow", g_link, 2, 0, 0);
        if (stat(g_path, &status) < 0 || status.st_size != 2) ++g_failures;
        dprintf(STDOUT_FILENO, "path_symlink_size:%lld\n",
                (long long)status.st_size);
    }

    expect_truncate("path_null", 0, 1, -1, EFAULT);
    expect_truncate("path_null_negative", 0, -1, -1, EINVAL);
    expect_truncate("path_empty", "", 1, -1, ENOENT);
    expect_truncate("path_missing", "/root/edgeos-truncate-missing", 1,
                    -1, ENOENT);
    expect_truncate("path_directory", "/root", 1, -1, EISDIR);
    expect_truncate("path_negative", g_path, -1, -1, EINVAL);
    expect_truncate("path_missing_negative",
                    "/root/edgeos-truncate-missing", -1, -1, EINVAL);
}

static void test_fd_truncate(int descriptor, int readonly_descriptor,
                             int pipe_descriptor, int socket_descriptor) {
    struct stat status;
    uint8_t bytes[5];
    off_t position;

    if (ftruncate(descriptor, 10) < 0 ||
        pwrite(descriptor, "0123456789", 10, 0) != 10 ||
        lseek(descriptor, 7, SEEK_SET) != 7) {
        dprintf(STDOUT_FILENO, "fd_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }
    expect_ftruncate("fd_shrink", descriptor, 3, 0, 0);
    position = lseek(descriptor, 0, SEEK_CUR);
    if (fstat(descriptor, &status) < 0 || status.st_size != 3 || position != 7)
        ++g_failures;
    if (fstat(readonly_descriptor, &status) < 0 || status.st_size != 3)
        ++g_failures;
    dprintf(STDOUT_FILENO, "fd_shrink_size:%lld offset:%lld\n",
            (long long)status.st_size, (long long)position);
    expect_ftruncate("fd_extend", descriptor, 8, 0, 0);
    memset(bytes, 0xa5, sizeof(bytes));
    if (pread(descriptor, bytes, sizeof(bytes), 3) != (ssize_t)sizeof(bytes) ||
        !bytes_are_zero(bytes, sizeof(bytes)))
        ++g_failures;
    position = lseek(descriptor, 0, SEEK_CUR);
    dprintf(STDOUT_FILENO, "fd_extend_zero:%d offset:%lld\n",
            bytes_are_zero(bytes, sizeof(bytes)), (long long)position);
    if (position != 7) ++g_failures;

    expect_ftruncate("fd_bad", -1, 1, -1, EBADF);
    expect_ftruncate("fd_bad_negative", -1, -1, -1, EINVAL);
    expect_ftruncate("fd_read_only", readonly_descriptor, 1, -1, EINVAL);
    expect_ftruncate("fd_pipe", pipe_descriptor, 1, -1, EINVAL);
    expect_ftruncate("fd_socket", socket_descriptor, 1, -1, EINVAL);
    expect_ftruncate("fd_negative", descriptor, -1, -1, EINVAL);
}

static void test_seals(void) {
    int descriptor;

    descriptor = (int)syscall(SYS_memfd_create, "truncate-write-seal",
                              EDGE_MFD_ALLOW_SEALING);
    if (descriptor < 0 || ftruncate(descriptor, 4096) < 0 ||
        fcntl(descriptor, F_ADD_SEALS, F_SEAL_WRITE) < 0) {
        dprintf(STDOUT_FILENO, "truncate_write_seal_setup_errno:%d\n", errno);
        ++g_failures;
    } else {
        expect_ftruncate("truncate_write_seal_shrink", descriptor, 2048,
                         0, 0);
        expect_ftruncate("truncate_write_seal_grow", descriptor, 4096,
                         0, 0);
    }
    if (descriptor >= 0) close(descriptor);

    descriptor = (int)syscall(SYS_memfd_create, "truncate-shrink-seal",
                              EDGE_MFD_ALLOW_SEALING);
    if (descriptor < 0 || ftruncate(descriptor, 4096) < 0 ||
        fcntl(descriptor, F_ADD_SEALS, F_SEAL_SHRINK) < 0) {
        dprintf(STDOUT_FILENO, "truncate_shrink_seal_setup_errno:%d\n", errno);
        ++g_failures;
    } else {
        expect_ftruncate("truncate_shrink_seal_same", descriptor, 4096,
                         0, 0);
        expect_ftruncate("truncate_shrink_seal", descriptor, 2048,
                         -1, EPERM);
    }
    if (descriptor >= 0) close(descriptor);

    descriptor = (int)syscall(SYS_memfd_create, "truncate-grow-seal",
                              EDGE_MFD_ALLOW_SEALING);
    if (descriptor < 0 || ftruncate(descriptor, 4096) < 0 ||
        fcntl(descriptor, F_ADD_SEALS, F_SEAL_GROW) < 0) {
        dprintf(STDOUT_FILENO, "truncate_grow_seal_setup_errno:%d\n", errno);
        ++g_failures;
    } else {
        expect_ftruncate("truncate_grow_seal_same", descriptor, 4096,
                         0, 0);
        expect_ftruncate("truncate_grow_seal", descriptor, 8192,
                         -1, EPERM);
    }
    if (descriptor >= 0) close(descriptor);
}

int main(void) {
    int descriptor;
    int readonly_descriptor;
    int pipe_descriptors[2];
    int socket_descriptor;

    unlink(g_link);
    unlink(g_path);
    descriptor = open(g_path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (descriptor < 0) {
        dprintf(STDOUT_FILENO, "truncate_file_setup_errno:%d\n", errno);
        return 1;
    }
    readonly_descriptor = open(g_path, O_RDONLY);
    socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (readonly_descriptor < 0 || pipe(pipe_descriptors) < 0 ||
        socket_descriptor < 0) {
        dprintf(STDOUT_FILENO, "truncate_descriptor_setup_errno:%d\n", errno);
        return 1;
    }

    test_path_truncate(descriptor, readonly_descriptor);
    test_fd_truncate(descriptor, readonly_descriptor, pipe_descriptors[1],
                     socket_descriptor);
    test_seals();

    close(socket_descriptor);
    close(pipe_descriptors[0]);
    close(pipe_descriptors[1]);
    close(readonly_descriptor);
    close(descriptor);
    unlink(g_link);
    unlink(g_path);
    dprintf(STDOUT_FILENO, "TRUNCATE_ABI_PROBE_%s failures:%d\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
