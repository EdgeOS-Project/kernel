/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux fallocate ABI and data-semantics probe for native and guest parity.
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
#ifndef SYS_fallocate
#define SYS_fallocate 47
#define SYS_memfd_create 279
#endif
#else
#ifndef SYS_fallocate
#define SYS_fallocate 285
#define SYS_memfd_create 319
#endif
#endif

#define EDGE_FALLOC_FL_KEEP_SIZE 0x01u
#define EDGE_FALLOC_FL_PUNCH_HOLE 0x02u
#define EDGE_FALLOC_FL_ZERO_RANGE 0x10u
#define EDGE_MFD_ALLOW_SEALING 0x0002u

static const char g_path[] = "/root/edgeos-fallocate-abi-probe";
static int g_failures;

static long call_fallocate(int descriptor, uint32_t mode, int64_t offset,
                           int64_t length) {
    return syscall(SYS_fallocate, descriptor, mode, offset, length);
}

static void expect_result(const char *name, long result, int saved_errno,
                          long expected_result, int expected_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != expected_result || saved_errno != expected_errno)
        ++g_failures;
}

static void expect_fallocate(const char *name, int descriptor, uint32_t mode,
                             int64_t offset, int64_t length,
                             long expected_result, int expected_errno) {
    long result;
    int saved_errno;
    errno = 0;
    result = call_fallocate(descriptor, mode, offset, length);
    saved_errno = errno;
    expect_result(name, result, saved_errno, expected_result, expected_errno);
}

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
    size_t index;
    for (index = 0; index < length; ++index)
        if (bytes[index]) return 0;
    return 1;
}

static void test_regular_file(int descriptor) {
    struct stat status;
    uint8_t bytes[32];
    off_t position;
    ssize_t count;

    if (write(descriptor, "abcdef", 6) != 6 ||
        lseek(descriptor, 2, SEEK_SET) != 2) {
        dprintf(STDOUT_FILENO, "regular_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }
    expect_fallocate("regular_allocate", descriptor, 0, 4096, 4096, 0, 0);
    if (fstat(descriptor, &status) < 0) {
        dprintf(STDOUT_FILENO, "regular_stat_errno:%d\n", errno);
        ++g_failures;
        return;
    }
    position = lseek(descriptor, 0, SEEK_CUR);
    dprintf(STDOUT_FILENO, "regular_size:%lld offset:%lld\n",
            (long long)status.st_size, (long long)position);
    if (status.st_size != 8192 || position != 2) ++g_failures;
    memset(bytes, 0xa5, sizeof(bytes));
    count = pread(descriptor, bytes, sizeof(bytes), 4096);
    dprintf(STDOUT_FILENO, "regular_zero_count:%lld zero:%d\n",
            (long long)count,
            count == (ssize_t)sizeof(bytes) &&
                bytes_are_zero(bytes, sizeof(bytes)));
    if (count != (ssize_t)sizeof(bytes) ||
        !bytes_are_zero(bytes, sizeof(bytes)))
        ++g_failures;

    expect_fallocate("regular_keep_size", descriptor,
                     EDGE_FALLOC_FL_KEEP_SIZE, 12288, 4096, 0, 0);
    if (fstat(descriptor, &status) < 0 || status.st_size != 8192)
        ++g_failures;
    dprintf(STDOUT_FILENO, "regular_keep_size_value:%lld\n",
            (long long)status.st_size);

    errno = 0;
    {
        long zero_result = call_fallocate(
            descriptor, EDGE_FALLOC_FL_ZERO_RANGE, 2, 3);
        int zero_errno = errno;

        dprintf(STDOUT_FILENO, "regular_zero_range_rc:%ld errno:%d\n",
                zero_result, zero_errno);
        if (zero_result == 0) {
            memset(bytes, 0, sizeof(bytes));
            count = pread(descriptor, bytes, 6, 0);
            dprintf(STDOUT_FILENO, "regular_zero_bytes:%d\n",
                    count == 6 && bytes[0] == 'a' && bytes[1] == 'b' &&
                        bytes[2] == 0 && bytes[3] == 0 && bytes[4] == 0 &&
                        bytes[5] == 'f');
            if (count != 6 || bytes[0] != 'a' || bytes[1] != 'b' ||
                bytes[2] != 0 || bytes[3] != 0 || bytes[4] != 0 ||
                bytes[5] != 'f')
                ++g_failures;
        } else if (zero_result != -1 || zero_errno != EOPNOTSUPP) {
            ++g_failures;
        }
    }
}

static void test_memory_file(int descriptor) {
    struct stat status;
    uint8_t bytes[8];

    if (ftruncate(descriptor, 4096) < 0 ||
        pwrite(descriptor, "abcdefgh", 8, 0) != 8) {
        dprintf(STDOUT_FILENO, "memfd_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }
    expect_fallocate("memfd_zero_range", descriptor,
                     EDGE_FALLOC_FL_ZERO_RANGE, 2, 3,
                     -1, EOPNOTSUPP);
    memset(bytes, 0, sizeof(bytes));
    if (pread(descriptor, bytes, sizeof(bytes), 0) != (ssize_t)sizeof(bytes)) {
        dprintf(STDOUT_FILENO, "memfd_zero_read_errno:%d\n", errno);
        ++g_failures;
    } else {
        int unchanged = !memcmp(bytes, "abcdefgh", sizeof(bytes));
        dprintf(STDOUT_FILENO, "memfd_zero_unchanged:%d\n", unchanged);
        if (!unchanged) ++g_failures;
    }
    expect_fallocate("memfd_punch", descriptor,
                     EDGE_FALLOC_FL_PUNCH_HOLE |
                         EDGE_FALLOC_FL_KEEP_SIZE,
                     0, 4096, 0, 0);
    if (fstat(descriptor, &status) < 0 || status.st_size != 4096)
        ++g_failures;
    memset(bytes, 0xa5, sizeof(bytes));
    if (pread(descriptor, bytes, sizeof(bytes), 0) != (ssize_t)sizeof(bytes) ||
        !bytes_are_zero(bytes, sizeof(bytes)))
        ++g_failures;
    dprintf(STDOUT_FILENO, "memfd_punch_size:%lld zero:%d\n",
            (long long)status.st_size, bytes_are_zero(bytes, sizeof(bytes)));
    expect_fallocate("memfd_punch_without_keep", descriptor,
                     EDGE_FALLOC_FL_PUNCH_HOLE, 0, 4096,
                     -1, EOPNOTSUPP);
    expect_fallocate("memfd_unknown_mode", descriptor, 0x80000000u,
                     0, 4096, -1, EOPNOTSUPP);
}

static void test_seals(void) {
    int descriptor;

    descriptor = (int)syscall(SYS_memfd_create, "fallocate-write-seal",
                              EDGE_MFD_ALLOW_SEALING);
    if (descriptor < 0 || ftruncate(descriptor, 4096) < 0 ||
        fcntl(descriptor, F_ADD_SEALS, F_SEAL_WRITE) < 0) {
        dprintf(STDOUT_FILENO, "write_seal_setup_errno:%d\n", errno);
        ++g_failures;
    } else {
        expect_fallocate("memfd_write_seal_allocate", descriptor, 0,
                         0, 4096, 0, 0);
        expect_fallocate("memfd_write_seal_punch", descriptor,
                         EDGE_FALLOC_FL_PUNCH_HOLE |
                             EDGE_FALLOC_FL_KEEP_SIZE,
                         0, 4096, -1, EPERM);
    }
    if (descriptor >= 0) close(descriptor);

    descriptor = (int)syscall(SYS_memfd_create, "fallocate-grow-seal",
                              EDGE_MFD_ALLOW_SEALING);
    if (descriptor < 0 || ftruncate(descriptor, 4096) < 0 ||
        fcntl(descriptor, F_ADD_SEALS, F_SEAL_GROW) < 0) {
        dprintf(STDOUT_FILENO, "grow_seal_setup_errno:%d\n", errno);
        ++g_failures;
    } else {
        expect_fallocate("memfd_grow_seal", descriptor, 0, 4096, 4096,
                         -1, EPERM);
        expect_fallocate("memfd_grow_seal_keep_size", descriptor,
                         EDGE_FALLOC_FL_KEEP_SIZE, 4096, 4096,
                         -1, EPERM);
    }
    if (descriptor >= 0) close(descriptor);
}

static void test_errors(int writable_descriptor, int readonly_descriptor,
                        int directory_descriptor, int pipe_descriptor,
                        int socket_descriptor) {
    expect_fallocate("bad_fd", -1, 0, 0, 4096, -1, EBADF);
    expect_fallocate("read_only", readonly_descriptor, 0, 0, 4096,
                     -1, EBADF);
    expect_fallocate("negative_offset", writable_descriptor, 0, -1, 4096,
                     -1, EINVAL);
    expect_fallocate("negative_length", writable_descriptor, 0, 0, -1,
                     -1, EINVAL);
    expect_fallocate("zero_length", writable_descriptor, 0, 0, 0,
                     -1, EINVAL);
    expect_fallocate("directory", directory_descriptor, 0, 0, 4096,
                     -1, EBADF);
    expect_fallocate("pipe", pipe_descriptor, 0, 0, 4096,
                     -1, ESPIPE);
    expect_fallocate("socket", socket_descriptor, 0, 0, 4096,
                     -1, ENODEV);
}

int main(void) {
    int writable_descriptor;
    int readonly_descriptor;
    int directory_descriptor;
    int pipe_descriptors[2];
    int socket_descriptors[2];
    int memory_descriptor;

    unlink(g_path);
    writable_descriptor = open(g_path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (writable_descriptor < 0) {
        dprintf(STDOUT_FILENO, "fallocate_file_setup_errno:%d\n", errno);
        return 1;
    }
    readonly_descriptor = open(g_path, O_RDONLY);
    directory_descriptor = open("/tmp", O_RDONLY | O_DIRECTORY);
    memory_descriptor = (int)syscall(SYS_memfd_create, "fallocate-data", 0);
    socket_descriptors[0] = socket_descriptors[1] = -1;
    (void)socketpair(AF_UNIX, SOCK_STREAM, 0, socket_descriptors);
    if (readonly_descriptor < 0 || directory_descriptor < 0 ||
        pipe(pipe_descriptors) < 0 || memory_descriptor < 0 ||
        socket_descriptors[0] < 0) {
        dprintf(STDOUT_FILENO, "fallocate_descriptor_setup_errno:%d\n",
                errno);
        return 1;
    }

    test_regular_file(writable_descriptor);
    test_memory_file(memory_descriptor);
    test_seals();
    test_errors(writable_descriptor, readonly_descriptor,
                directory_descriptor, pipe_descriptors[1],
                socket_descriptors[0]);

    close(socket_descriptors[0]);
    close(socket_descriptors[1]);
    close(memory_descriptor);
    close(pipe_descriptors[0]);
    close(pipe_descriptors[1]);
    close(directory_descriptor);
    close(readonly_descriptor);
    close(writable_descriptor);
    unlink(g_path);
    dprintf(STDOUT_FILENO, "FALLOCATE_ABI_PROBE_%s failures:%d\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
