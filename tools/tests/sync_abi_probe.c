/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux filesystem synchronization ABI probe for native and guest parity.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#ifndef SYS_sync
#define SYS_sync 81
#define SYS_fsync 82
#define SYS_fdatasync 83
#define SYS_sync_file_range 84
#define SYS_syncfs 267
#define SYS_memfd_create 279
#endif
#else
#ifndef SYS_fsync
#define SYS_fsync 74
#define SYS_fdatasync 75
#define SYS_sync 162
#define SYS_sync_file_range 277
#define SYS_syncfs 306
#define SYS_memfd_create 319
#endif
#endif

static const char g_path[] = "/tmp/edgeos-sync-abi-probe";
static int g_failures;

static void expect_result(const char *name, long result, int saved_errno,
                          long expected_result, int expected_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != expected_result || saved_errno != expected_errno)
        ++g_failures;
}

static void expect_call1(const char *name, long number, long argument,
                         long expected_result, int expected_errno) {
    long result;
    int saved_errno;
    errno = 0;
    result = syscall(number, argument);
    saved_errno = errno;
    expect_result(name, result, saved_errno, expected_result, expected_errno);
}

static void expect_range(const char *name, int descriptor, long offset,
                         long length, unsigned long flags,
                         long expected_result, int expected_errno) {
    long result;
    int saved_errno;
    errno = 0;
    result = syscall(SYS_sync_file_range, descriptor, offset, length, flags);
    saved_errno = errno;
    expect_result(name, result, saved_errno, expected_result, expected_errno);
}

static void test_file(int descriptor) {
    expect_call1("file_fsync", SYS_fsync, descriptor, 0, 0);
    expect_call1("file_fdatasync", SYS_fdatasync, descriptor, 0, 0);
    expect_call1("file_syncfs", SYS_syncfs, descriptor, 0, 0);
    expect_range("file_sync_file_range", descriptor, 0, 3, 7u, 0, 0);
}

static void test_pipe(int descriptor) {
    expect_call1("pipe_fsync", SYS_fsync, descriptor, -1, EINVAL);
    expect_call1("pipe_fdatasync", SYS_fdatasync, descriptor, -1, EINVAL);
    expect_call1("pipe_syncfs", SYS_syncfs, descriptor, 0, 0);
    expect_range("pipe_sync_file_range", descriptor, 0, 3, 0, -1,
                 ESPIPE);
}

static void test_memfd(int descriptor) {
    expect_call1("memfd_fsync", SYS_fsync, descriptor, 0, 0);
    expect_call1("memfd_fdatasync", SYS_fdatasync, descriptor, 0, 0);
    expect_call1("memfd_syncfs", SYS_syncfs, descriptor, 0, 0);
    expect_range("memfd_sync_file_range", descriptor, 0, 3, 0, 0, 0);
}

static void test_socket(int descriptor) {
    expect_call1("socket_fsync", SYS_fsync, descriptor, -1, EINVAL);
    expect_call1("socket_fdatasync", SYS_fdatasync, descriptor, -1,
                 EINVAL);
    expect_call1("socket_syncfs", SYS_syncfs, descriptor, 0, 0);
    expect_range("socket_sync_file_range", descriptor, 0, 3, 0, -1,
                 ESPIPE);
}

static void test_errors(int descriptor) {
    expect_call1("fsync_badfd", SYS_fsync, -1, -1, EBADF);
    expect_call1("syncfs_badfd", SYS_syncfs, -1, -1, EBADF);
    expect_range("sync_file_range_badfd", -1, 0, 1, 0, -1, EBADF);
    expect_range("sync_file_range_negative_offset", descriptor, -1, 1, 0,
                 -1, EINVAL);
    expect_range("sync_file_range_negative_length", descriptor, 0, -1, 0,
                 -1, EINVAL);
    expect_range("sync_file_range_invalid_flags", descriptor, 0, 1, 8u,
                 -1, EINVAL);
}

int main(void) {
    int descriptor;
    int pipe_descriptors[2];
    int memory_descriptor;
    int socket_descriptor;
    long result;
    int saved_errno;

    unlink(g_path);
    descriptor = open(g_path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (descriptor < 0 || write(descriptor, "abc", 3) != 3 ||
        pipe(pipe_descriptors) < 0) {
        dprintf(STDOUT_FILENO, "sync_probe_setup_errno:%d\n", errno);
        return 1;
    }
    memory_descriptor = (int)syscall(SYS_memfd_create, "edgeos-sync", 0);
    socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (memory_descriptor < 0 || socket_descriptor < 0) {
        dprintf(STDOUT_FILENO, "sync_probe_descriptor_errno:%d\n", errno);
        return 1;
    }

    test_file(descriptor);
    test_pipe(pipe_descriptors[0]);
    test_memfd(memory_descriptor);
    test_socket(socket_descriptor);
    test_errors(descriptor);

    errno = 0;
    result = syscall(SYS_sync);
    saved_errno = errno;
    expect_result("sync", result, saved_errno, 0, 0);

    close(socket_descriptor);
    close(memory_descriptor);
    close(pipe_descriptors[0]);
    close(pipe_descriptors[1]);
    close(descriptor);
    unlink(g_path);
    dprintf(STDOUT_FILENO, "SYNC_ABI_PROBE_%s failures:%d\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
