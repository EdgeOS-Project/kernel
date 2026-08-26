/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux readahead and file-advice ABI probe for native and guest parity.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#ifndef SYS_readahead
#define SYS_readahead 213
#define SYS_fadvise64 223
#define SYS_memfd_create 279
#endif
#else
#ifndef SYS_readahead
#define SYS_readahead 187
#define SYS_fadvise64 221
#define SYS_memfd_create 319
#endif
#endif

#define EDGE_FADV_NORMAL 0
#define EDGE_FADV_RANDOM 1
#define EDGE_FADV_SEQUENTIAL 2
#define EDGE_FADV_WILLNEED 3
#define EDGE_FADV_DONTNEED 4
#define EDGE_FADV_NOREUSE 5

static const char g_path[] = "/tmp/edgeos-file-advice-abi-probe";
static int g_failures;

static void expect_result(const char *name, long result, int saved_errno,
                          long expected_result, int expected_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != expected_result || saved_errno != expected_errno)
        ++g_failures;
}

static void expect_readahead(const char *name, int descriptor,
                             int64_t offset, size_t count,
                             long expected_result, int expected_errno) {
    long result;
    int saved_errno;
    errno = 0;
    result = syscall(SYS_readahead, descriptor, offset, count);
    saved_errno = errno;
    expect_result(name, result, saved_errno, expected_result, expected_errno);
}

static void expect_fadvise(const char *name, int descriptor,
                           int64_t offset, int64_t length, int advice,
                           long expected_result, int expected_errno) {
    long result;
    int saved_errno;
    errno = 0;
    result = syscall(SYS_fadvise64, descriptor, offset, length, advice);
    saved_errno = errno;
    expect_result(name, result, saved_errno, expected_result, expected_errno);
}

static void test_regular_files(int read_descriptor, int write_descriptor) {
    off_t position;

    if (lseek(read_descriptor, 3, SEEK_SET) != 3) {
        dprintf(STDOUT_FILENO, "readahead_lseek_setup_errno:%d\n", errno);
        ++g_failures;
    }
    expect_readahead("file_readahead", read_descriptor, 0, 4096, 0, 0);
    position = lseek(read_descriptor, 0, SEEK_CUR);
    dprintf(STDOUT_FILENO, "file_readahead_offset:%lld\n",
            (long long)position);
    if (position != 3) ++g_failures;
    expect_readahead("write_only_readahead", write_descriptor, 0, 1,
                     -1, EBADF);

    expect_fadvise("file_fadvise_normal", read_descriptor, 0, 0,
                   EDGE_FADV_NORMAL, 0, 0);
    expect_fadvise("file_fadvise_random", read_descriptor, 0, 0,
                   EDGE_FADV_RANDOM, 0, 0);
    expect_fadvise("file_fadvise_sequential", read_descriptor, 0, 0,
                   EDGE_FADV_SEQUENTIAL, 0, 0);
    expect_fadvise("file_fadvise_willneed", read_descriptor, 0, 4096,
                   EDGE_FADV_WILLNEED, 0, 0);
    expect_fadvise("file_fadvise_dontneed", read_descriptor, 0, 4096,
                   EDGE_FADV_DONTNEED, 0, 0);
    expect_fadvise("file_fadvise_noreuse", read_descriptor, 0, 4096,
                   EDGE_FADV_NOREUSE, 0, 0);
    expect_fadvise("write_only_fadvise", write_descriptor, 0, 1,
                   EDGE_FADV_WILLNEED, 0, 0);
}

static void test_descriptor_kinds(int directory_descriptor,
                                  int pipe_descriptor,
                                  int memory_descriptor,
                                  int socket_descriptor) {
    expect_readahead("directory_readahead", directory_descriptor, 0, 1,
                     -1, EINVAL);
    expect_readahead("pipe_readahead", pipe_descriptor, 0, 1,
                     -1, EINVAL);
    expect_readahead("memfd_readahead", memory_descriptor, 0, 1, 0, 0);
    expect_readahead("socket_readahead", socket_descriptor, 0, 1,
                     -1, EINVAL);

    expect_fadvise("directory_fadvise", directory_descriptor, 0, 1,
                   EDGE_FADV_NORMAL, 0, 0);
    expect_fadvise("pipe_fadvise", pipe_descriptor, 0, 1,
                   EDGE_FADV_NORMAL, -1, ESPIPE);
    expect_fadvise("memfd_fadvise", memory_descriptor, 0, 1,
                   EDGE_FADV_NORMAL, 0, 0);
    expect_fadvise("socket_fadvise", socket_descriptor, 0, 1,
                   EDGE_FADV_NORMAL, 0, 0);
}

static void test_errors(int descriptor) {
    expect_readahead("readahead_badfd", -1, 0, 1, -1, EBADF);
    expect_readahead("readahead_negative_offset", descriptor, -1, 1,
                     -1, EINVAL);
    expect_readahead("readahead_zero_count", descriptor, 0, 0, 0, 0);

    expect_fadvise("fadvise_badfd", -1, 0, 1, EDGE_FADV_NORMAL,
                   -1, EBADF);
    expect_fadvise("fadvise_negative_offset", descriptor, -1, 1,
                   EDGE_FADV_NORMAL, -1, EINVAL);
    expect_fadvise("fadvise_negative_length", descriptor, 0, -1,
                   EDGE_FADV_NORMAL, -1, EINVAL);
    expect_fadvise("fadvise_invalid_advice", descriptor, 0, 1, 6,
                   -1, EINVAL);
}

int main(void) {
    int read_descriptor;
    int write_descriptor;
    int directory_descriptor;
    int pipe_descriptors[2];
    int memory_descriptor;
    int socket_descriptors[2];

    unlink(g_path);
    write_descriptor = open(g_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (write_descriptor < 0 ||
        write(write_descriptor, "edgeos-file-advice", 18) != 18) {
        dprintf(STDOUT_FILENO, "file_advice_setup_errno:%d\n", errno);
        return 1;
    }
    read_descriptor = open(g_path, O_RDONLY);
    directory_descriptor = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (read_descriptor < 0 || directory_descriptor < 0 ||
        pipe(pipe_descriptors) < 0) {
        dprintf(STDOUT_FILENO, "file_advice_descriptor_errno:%d\n", errno);
        return 1;
    }
    memory_descriptor = (int)syscall(SYS_memfd_create,
                                     "edgeos-file-advice", 0);
    socket_descriptors[0] = socket_descriptors[1] = -1;
    (void)socketpair(AF_UNIX, SOCK_STREAM, 0, socket_descriptors);
    if (memory_descriptor < 0 || socket_descriptors[0] < 0) {
        dprintf(STDOUT_FILENO, "file_advice_special_fd_errno:%d\n", errno);
        return 1;
    }

    test_regular_files(read_descriptor, write_descriptor);
    test_descriptor_kinds(directory_descriptor, pipe_descriptors[0],
                          memory_descriptor, socket_descriptors[0]);
    test_errors(read_descriptor);

    close(socket_descriptors[0]);
    close(socket_descriptors[1]);
    close(memory_descriptor);
    close(pipe_descriptors[0]);
    close(pipe_descriptors[1]);
    close(directory_descriptor);
    close(read_descriptor);
    close(write_descriptor);
    unlink(g_path);
    dprintf(STDOUT_FILENO, "FILE_ADVICE_ABI_PROBE_%s failures:%d\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
