/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux scalar and vectored I/O ABI probe for native and guest parity.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#if defined(__aarch64__)
#ifndef SYS_pwrite64
#define SYS_pwrite64 68
#endif
#ifndef SYS_preadv
#define SYS_preadv 69
#define SYS_pwritev 70
#define SYS_preadv2 286
#define SYS_pwritev2 287
#endif
#else
#ifndef SYS_pwrite64
#define SYS_pwrite64 18
#endif
#ifndef SYS_preadv
#define SYS_preadv 295
#define SYS_pwritev 296
#define SYS_preadv2 327
#define SYS_pwritev2 328
#endif
#endif

#define EDGE_RWF_DSYNC 0x00000002u
#define EDGE_RWF_SYNC 0x00000004u
#define EDGE_RWF_APPEND 0x00000010u
#define EDGE_RWF_NOAPPEND 0x00000020u

static const char g_path[] = "/tmp/edgeos-vector-io-abi-probe";
static char g_pipe_fill[4096];
static char g_pipe_read[8192];
static char g_pipe_first[2048];
static char g_pipe_second[2048];
static int g_failures;

static void expect_result(const char *name, long result, int saved_errno,
                          long expected_result, int expected_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != expected_result || saved_errno != expected_errno)
        ++g_failures;
}

static long raw_preadv(int descriptor, const struct iovec *vectors,
                       unsigned long count, int64_t offset) {
    return syscall(SYS_preadv, descriptor, vectors, count,
                   (uint64_t)offset, 0UL);
}

static long raw_pwritev(int descriptor, const struct iovec *vectors,
                        unsigned long count, int64_t offset) {
    return syscall(SYS_pwritev, descriptor, vectors, count,
                   (uint64_t)offset, 0UL);
}

static long raw_pwrite64(int descriptor, const void *buffer,
                         size_t length, int64_t offset) {
    return syscall(SYS_pwrite64, descriptor, buffer, length,
                   (uint64_t)offset);
}

static long raw_preadv2(int descriptor, const struct iovec *vectors,
                        unsigned long count, int64_t offset,
                        unsigned long flags) {
    return syscall(SYS_preadv2, descriptor, vectors, count,
                   (uint64_t)offset, 0UL, flags);
}

static long raw_pwritev2(int descriptor, const struct iovec *vectors,
                         unsigned long count, int64_t offset,
                         unsigned long flags) {
    return syscall(SYS_pwritev2, descriptor, vectors, count,
                   (uint64_t)offset, 0UL, flags);
}

static int read_exact(int descriptor, char *buffer, size_t length,
                      int64_t offset) {
    ssize_t result = pread(descriptor, buffer, length, offset);
    return result == (ssize_t)length;
}

static void test_zero_vectors(int descriptor) {
    const struct iovec *invalid_vectors =
        (const struct iovec *)(uintptr_t)1;
    int pipe_descriptors[2];
    long result;
    int saved_errno;

    errno = 0;
    result = readv(descriptor, invalid_vectors, 0);
    saved_errno = errno;
    expect_result("readv_zero", result, saved_errno, 0, 0);

    errno = 0;
    result = writev(descriptor, invalid_vectors, 0);
    saved_errno = errno;
    expect_result("writev_zero", result, saved_errno, 0, 0);

    errno = 0;
    result = raw_preadv(descriptor, invalid_vectors, 0, 17);
    saved_errno = errno;
    expect_result("preadv_zero_regular", result, saved_errno, 0, 0);

    errno = 0;
    result = raw_pwritev(descriptor, invalid_vectors, 0, 17);
    saved_errno = errno;
    expect_result("pwritev_zero_regular", result, saved_errno, 0, 0);

    errno = 0;
    result = readv(-1, invalid_vectors, 0);
    saved_errno = errno;
    expect_result("readv_bad_fd_zero", result, saved_errno, -1, EBADF);

    errno = 0;
    result = writev(-1, invalid_vectors, 0);
    saved_errno = errno;
    expect_result("writev_bad_fd_zero", result, saved_errno, -1, EBADF);

    errno = 0;
    result = raw_preadv(-1, invalid_vectors, 0, 0);
    saved_errno = errno;
    expect_result("preadv_bad_fd_zero", result, saved_errno, -1, EBADF);

    errno = 0;
    result = raw_pwritev(-1, invalid_vectors, 0, 0);
    saved_errno = errno;
    expect_result("pwritev_bad_fd_zero", result, saved_errno, -1, EBADF);

    errno = 0;
    result = raw_preadv(descriptor, invalid_vectors, 0, -1);
    saved_errno = errno;
    expect_result("preadv_negative_offset_zero", result, saved_errno,
                  -1, EINVAL);

    errno = 0;
    result = raw_pwritev(descriptor, invalid_vectors, 0, -1);
    saved_errno = errno;
    expect_result("pwritev_negative_offset_zero", result, saved_errno,
                  -1, EINVAL);

    errno = 0;
    result = raw_preadv(-1, invalid_vectors, 0, -1);
    saved_errno = errno;
    expect_result("preadv_negative_offset_bad_fd_zero",
                  result, saved_errno, -1, EINVAL);

    errno = 0;
    result = raw_pwritev(-1, invalid_vectors, 0, -1);
    saved_errno = errno;
    expect_result("pwritev_negative_offset_bad_fd_zero",
                  result, saved_errno, -1, EINVAL);

    errno = 0;
    result = syscall(SYS_readv, descriptor, 0, 1025);
    saved_errno = errno;
    expect_result("readv_iov_max", result, saved_errno, -1, EINVAL);

    if (pipe2(pipe_descriptors, O_CLOEXEC) < 0) {
        dprintf(STDOUT_FILENO, "zero_vector_pipe_setup_errno:%d\n",
                errno);
        ++g_failures;
        return;
    }

    errno = 0;
    result = readv(pipe_descriptors[0], invalid_vectors, 0);
    saved_errno = errno;
    expect_result("readv_zero_pipe", result, saved_errno, 0, 0);

    errno = 0;
    result = writev(pipe_descriptors[1], invalid_vectors, 0);
    saved_errno = errno;
    expect_result("writev_zero_pipe", result, saved_errno, 0, 0);

    errno = 0;
    result = raw_preadv(pipe_descriptors[0], invalid_vectors, 0, 0);
    saved_errno = errno;
    expect_result("preadv_zero_pipe", result, saved_errno, -1, ESPIPE);

    errno = 0;
    result = raw_pwritev(pipe_descriptors[1], invalid_vectors, 0, 0);
    saved_errno = errno;
    expect_result("pwritev_zero_pipe", result, saved_errno, -1, ESPIPE);

    errno = 0;
    result = raw_preadv(pipe_descriptors[1], invalid_vectors, 0, 0);
    saved_errno = errno;
    expect_result("preadv_zero_write_pipe", result, saved_errno,
                  -1, ESPIPE);

    errno = 0;
    result = raw_pwritev(pipe_descriptors[0], invalid_vectors, 0, 0);
    saved_errno = errno;
    expect_result("pwritev_zero_read_pipe", result, saved_errno,
                  -1, ESPIPE);

    errno = 0;
    result = raw_preadv(pipe_descriptors[0], invalid_vectors, 0, -1);
    saved_errno = errno;
    expect_result("preadv_negative_offset_pipe_zero",
                  result, saved_errno, -1, EINVAL);

    errno = 0;
    result = raw_pwritev(pipe_descriptors[1], invalid_vectors, 0, -1);
    saved_errno = errno;
    expect_result("pwritev_negative_offset_pipe_zero",
                  result, saved_errno, -1, EINVAL);

    close(pipe_descriptors[0]);
    close(pipe_descriptors[1]);
}

static void test_scalar_validation(void) {
    char byte = 0;
    int readonly_descriptor = open(g_path, O_RDONLY);
    int writeonly_descriptor = open(g_path, O_WRONLY);
    long result;
    int saved_errno;

    if (readonly_descriptor < 0 || writeonly_descriptor < 0) {
        dprintf(STDOUT_FILENO, "scalar_validation_setup_errno:%d\n",
                errno);
        ++g_failures;
        return;
    }

    errno = 0;
    result = read(-1, &byte, 0);
    saved_errno = errno;
    expect_result("read_bad_fd_zero", result, saved_errno, -1, EBADF);
    errno = 0;
    result = write(-1, &byte, 0);
    saved_errno = errno;
    expect_result("write_bad_fd_zero", result, saved_errno, -1, EBADF);
    errno = 0;
    result = read(writeonly_descriptor, &byte, 0);
    saved_errno = errno;
    expect_result("read_writeonly_zero", result, saved_errno, -1, EBADF);
    errno = 0;
    result = write(readonly_descriptor, &byte, 0);
    saved_errno = errno;
    expect_result("write_readonly_zero", result, saved_errno, -1, EBADF);
    errno = 0;
    result = pread(writeonly_descriptor, &byte, 0, 0);
    saved_errno = errno;
    expect_result("pread_writeonly_zero", result, saved_errno, -1, EBADF);
    errno = 0;
    result = pwrite(readonly_descriptor, &byte, 0, 0);
    saved_errno = errno;
    expect_result("pwrite_readonly_zero", result, saved_errno, -1, EBADF);

    errno = 0;
    result = pread(-1, &byte, 1, -1);
    saved_errno = errno;
    expect_result("pread_negative_offset_bad_fd", result, saved_errno,
                  -1, EINVAL);
    errno = 0;
    result = pwrite(-1, &byte, 1, -1);
    saved_errno = errno;
    expect_result("pwrite_negative_offset_bad_fd", result, saved_errno,
                  -1, EINVAL);

    close(writeonly_descriptor);
    close(readonly_descriptor);
}

static void test_scalar_zero_descriptor_semantics(void) {
    char byte = 0;
    struct iovec vector = {
        .iov_base = &byte,
        .iov_len = 0,
    };
    int descriptor = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    long result;
    int saved_errno;

    if (descriptor < 0) {
        dprintf(STDOUT_FILENO, "eventfd_zero_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }

    errno = 0;
    result = read(descriptor, &byte, 0);
    saved_errno = errno;
    expect_result("eventfd_read_zero", result, saved_errno, -1, EINVAL);
    errno = 0;
    result = write(descriptor, &byte, 0);
    saved_errno = errno;
    expect_result("eventfd_write_zero", result, saved_errno, -1, EINVAL);
    errno = 0;
    result = readv(descriptor, &vector, 1);
    saved_errno = errno;
    expect_result("eventfd_readv_zero", result, saved_errno, 0, 0);
    errno = 0;
    result = writev(descriptor, &vector, 1);
    saved_errno = errno;
    expect_result("eventfd_writev_zero", result, saved_errno, 0, 0);

    close(descriptor);
}

static void expect_record_result(const char *socket_name,
                                 const char *operation,
                                 long result, int saved_errno,
                                 long expected_result,
                                 int expected_errno) {
    char name[96];

    snprintf(name, sizeof(name), "%s_%s", socket_name, operation);
    expect_result(name, result, saved_errno,
                  expected_result, expected_errno);
}

static void test_record_zero_length_type(int type,
                                         const char *socket_name) {
    int descriptors[2];
    char byte = 0;
    struct iovec zero_vector = {
        .iov_base = (void *)(uintptr_t)1,
        .iov_len = 0,
    };
    long result;
    int saved_errno;

    if (socketpair(AF_UNIX,
                   type | SOCK_CLOEXEC | SOCK_NONBLOCK,
                   0, descriptors) < 0) {
        dprintf(STDOUT_FILENO, "%s_zero_setup_errno:%d\n",
                socket_name, errno);
        ++g_failures;
        return;
    }

    errno = 0;
    result = write(descriptors[0],
                   (const void *)(uintptr_t)1, 0);
    saved_errno = errno;
    expect_record_result(socket_name, "write_zero",
                         result, saved_errno, 0, 0);
    errno = 0;
    result = recv(descriptors[1], &byte, 1, 0);
    saved_errno = errno;
    expect_record_result(socket_name, "write_zero_record",
                         result, saved_errno, 0, 0);

    errno = 0;
    result = writev(descriptors[0], &zero_vector, 1);
    saved_errno = errno;
    expect_record_result(socket_name, "writev_zero",
                         result, saved_errno, 0, 0);
    errno = 0;
    result = recv(descriptors[1], &byte, 1, 0);
    saved_errno = errno;
    expect_record_result(socket_name, "writev_zero_no_record",
                         result, saved_errno, -1, EAGAIN);

    byte = 'R';
    if (send(descriptors[0], &byte, 1, 0) != 1) {
        ++g_failures;
    } else {
        errno = 0;
        result = read(descriptors[1], (void *)(uintptr_t)1, 0);
        saved_errno = errno;
        expect_record_result(socket_name, "read_zero",
                             result, saved_errno, 0, 0);
        byte = 0;
        errno = 0;
        result = recv(descriptors[1], &byte, 1, 0);
        saved_errno = errno;
        expect_record_result(socket_name, "read_zero_preserves_record",
                             result, saved_errno, 1, 0);
        if (byte != 'R') ++g_failures;
    }

    byte = 'V';
    if (send(descriptors[0], &byte, 1, 0) != 1) {
        ++g_failures;
    } else {
        errno = 0;
        result = readv(descriptors[1], &zero_vector, 1);
        saved_errno = errno;
        expect_record_result(socket_name, "readv_zero",
                             result, saved_errno, 0, 0);
        byte = 0;
        errno = 0;
        result = recv(descriptors[1], &byte, 1, 0);
        saved_errno = errno;
        expect_record_result(socket_name, "readv_zero_preserves_record",
                             result, saved_errno, 1, 0);
        if (byte != 'V') ++g_failures;
    }

    close(descriptors[0]);
    close(descriptors[1]);
}

static void test_record_zero_length(void) {
    test_record_zero_length_type(SOCK_DGRAM, "unix_dgram");
    test_record_zero_length_type(SOCK_SEQPACKET, "unix_seqpacket");
}

static void test_pipe_atomic_vectors(void) {
    int descriptors[2];
    char valid[2] = {'O', 'K'};
    struct iovec atomic_vectors[2] = {
        { .iov_base = g_pipe_first, .iov_len = sizeof(g_pipe_first) },
        { .iov_base = g_pipe_second, .iov_len = sizeof(g_pipe_second) },
    };
    struct iovec fault_vectors[2] = {
        { .iov_base = valid, .iov_len = sizeof(valid) },
        { .iov_base = (void *)(uintptr_t)1, .iov_len = 2 },
    };
    uint64_t filled = 0;
    uint64_t drained = 0;
    long result;
    int saved_errno;

    memset(g_pipe_fill, 'F', sizeof(g_pipe_fill));
    memset(g_pipe_first, 'A', sizeof(g_pipe_first));
    memset(g_pipe_second, 'B', sizeof(g_pipe_second));
    if (pipe2(descriptors, O_CLOEXEC | O_NONBLOCK) < 0) {
        dprintf(STDOUT_FILENO, "pipe_atomic_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }

    for (;;) {
        result = write(descriptors[1], g_pipe_fill,
                       sizeof(g_pipe_fill));
        if (result < 0) {
            if (errno != EAGAIN) ++g_failures;
            break;
        }
        filled += (uint64_t)result;
    }
    if (read(descriptors[0], g_pipe_read, 2048) != 2048) {
        ++g_failures;
    } else {
        errno = 0;
        result = writev(descriptors[1], atomic_vectors, 2);
        saved_errno = errno;
        expect_result("pipe_writev_atomic_admission",
                      result, saved_errno, -1, EAGAIN);
    }
    for (;;) {
        result = read(descriptors[0], g_pipe_read,
                      sizeof(g_pipe_read));
        if (result < 0) {
            if (errno != EAGAIN) ++g_failures;
            break;
        }
        for (long index = 0; index < result; ++index) {
            if (g_pipe_read[index] != 'F') {
                ++g_failures;
                break;
            }
        }
        drained += (uint64_t)result;
    }
    if (filled < 2048 || drained != filled - 2048) ++g_failures;

    errno = 0;
    result = writev(descriptors[1], fault_vectors, 2);
    saved_errno = errno;
    expect_result("pipe_writev_atomic_fault",
                  result, saved_errno, -1, EFAULT);
    errno = 0;
    result = read(descriptors[0], g_pipe_read, sizeof(g_pipe_read));
    saved_errno = errno;
    expect_result("pipe_writev_atomic_fault_empty",
                  result, saved_errno, -1, EAGAIN);

    close(descriptors[0]);
    close(descriptors[1]);
}

static void test_vector_error_ordering(int descriptor) {
    int writeonly_descriptor = open(g_path, O_WRONLY);
    long result;
    int saved_errno;

    if (writeonly_descriptor < 0) {
        dprintf(STDOUT_FILENO,
                "vector_error_ordering_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }

    errno = 0;
    result = syscall(SYS_readv, -1, 0, 1025);
    saved_errno = errno;
    expect_result("readv_bad_fd_iov_max", result, saved_errno,
                  -1, EBADF);

    errno = 0;
    result = syscall(SYS_readv, writeonly_descriptor, 0, 1025);
    saved_errno = errno;
    expect_result("readv_writeonly_iov_max", result, saved_errno,
                  -1, EBADF);

    errno = 0;
    result = raw_preadv(-1, 0, 1025, -1);
    saved_errno = errno;
    expect_result("preadv_negative_offset_bad_fd_iov_max",
                  result, saved_errno, -1, EINVAL);

    errno = 0;
    result = raw_preadv(descriptor, 0, 0, -1);
    saved_errno = errno;
    expect_result("preadv_negative_offset_zero",
                  result, saved_errno, -1, EINVAL);

    errno = 0;
    result = raw_preadv2(-1, 0, 0, -2, 0x80000000UL);
    saved_errno = errno;
    expect_result("preadv2_negative_offset_bad_fd_unknown_flag",
                  result, saved_errno, -1, EINVAL);

    errno = 0;
    result = raw_preadv2(-1, 0, 0, 0, 0x80000000UL);
    saved_errno = errno;
    expect_result("preadv2_bad_fd_unknown_flag",
                  result, saved_errno, -1, EBADF);

    errno = 0;
    result = raw_preadv2(descriptor, 0, 0, 0, 0x80000000UL);
    saved_errno = errno;
    expect_result("preadv2_zero_unknown_flag",
                  result, saved_errno, 0, 0);

    errno = 0;
    result = raw_preadv2(descriptor, 0, 1, 0, 0x80000000UL);
    saved_errno = errno;
    expect_result("preadv2_bad_iovec_unknown_flag",
                  result, saved_errno, -1, EFAULT);

    close(writeonly_descriptor);
}

static void test_sequential_vectors(int descriptor) {
    char first[3] = "ab";
    char second[5] = "cdef";
    char read_first[3] = {0};
    char read_second[5] = {0};
    char contents[7] = {0};
    struct iovec write_vectors[2] = {
        { .iov_base = first, .iov_len = 2 },
        { .iov_base = second, .iov_len = 4 },
    };
    struct iovec read_vectors[2] = {
        { .iov_base = read_first, .iov_len = 2 },
        { .iov_base = read_second, .iov_len = 4 },
    };
    ssize_t result;

    if (ftruncate(descriptor, 0) < 0 || lseek(descriptor, 0, SEEK_SET) < 0) {
        dprintf(STDOUT_FILENO, "sequential_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }
    errno = 0;
    result = writev(descriptor, write_vectors, 2);
    expect_result("writev_two", result, errno, 6, 0);
    dprintf(STDOUT_FILENO, "writev_offset:%lld\n",
            (long long)lseek(descriptor, 0, SEEK_CUR));
    if (lseek(descriptor, 0, SEEK_CUR) != 6 ||
        !read_exact(descriptor, contents, 6, 0) ||
        memcmp(contents, "abcdef", 6))
        ++g_failures;

    if (lseek(descriptor, 0, SEEK_SET) != 0) ++g_failures;
    errno = 0;
    result = readv(descriptor, read_vectors, 2);
    expect_result("readv_two", result, errno, 6, 0);
    dprintf(STDOUT_FILENO, "readv_data:%s%s offset:%lld\n",
            read_first, read_second,
            (long long)lseek(descriptor, 0, SEEK_CUR));
    if (memcmp(read_first, "ab", 2) || memcmp(read_second, "cdef", 4) ||
        lseek(descriptor, 0, SEEK_CUR) != 6)
        ++g_failures;
}

static void test_positioned_vectors(int descriptor) {
    char input_a[3] = "XY";
    char input_b[3] = "Z!";
    char output_a[3] = {0};
    char output_b[3] = {0};
    char contents[9] = {0};
    struct iovec input[2] = {
        { .iov_base = input_a, .iov_len = 2 },
        { .iov_base = input_b, .iov_len = 2 },
    };
    struct iovec output[2] = {
        { .iov_base = output_a, .iov_len = 2 },
        { .iov_base = output_b, .iov_len = 2 },
    };
    long result;
    int saved_errno;

    if (ftruncate(descriptor, 0) < 0 ||
        pwrite(descriptor, "abcdefgh", 8, 0) != 8 ||
        lseek(descriptor, 6, SEEK_SET) != 6) {
        dprintf(STDOUT_FILENO, "positioned_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }

    errno = 0;
    result = raw_preadv(descriptor, output, 2, 1);
    saved_errno = errno;
    expect_result("preadv_two", result, saved_errno, 4, 0);
    dprintf(STDOUT_FILENO, "preadv_data:%s%s offset:%lld\n",
            output_a, output_b,
            (long long)lseek(descriptor, 0, SEEK_CUR));
    if (memcmp(output_a, "bc", 2) || memcmp(output_b, "de", 2) ||
        lseek(descriptor, 0, SEEK_CUR) != 6)
        ++g_failures;

    errno = 0;
    result = raw_pwritev(descriptor, input, 2, 2);
    saved_errno = errno;
    expect_result("pwritev_two", result, saved_errno, 4, 0);
    if (!read_exact(descriptor, contents, 8, 0)) {
        ++g_failures;
    } else {
        dprintf(STDOUT_FILENO, "pwritev_data:%s offset:%lld\n", contents,
                (long long)lseek(descriptor, 0, SEEK_CUR));
        if (memcmp(contents, "abXYZ!gh", 8) ||
            lseek(descriptor, 0, SEEK_CUR) != 6)
            ++g_failures;
    }
}

static void test_current_position_v2(int descriptor) {
    char output_a[2] = {0};
    char output_b[2] = {0};
    char input_a = 'Q';
    char input_b = 'R';
    char contents[9] = {0};
    struct iovec output[2] = {
        { .iov_base = output_a, .iov_len = 1 },
        { .iov_base = output_b, .iov_len = 1 },
    };
    struct iovec input[2] = {
        { .iov_base = &input_a, .iov_len = 1 },
        { .iov_base = &input_b, .iov_len = 1 },
    };
    long result;
    int saved_errno;

    if (lseek(descriptor, 1, SEEK_SET) != 1) ++g_failures;
    errno = 0;
    result = raw_preadv2(descriptor, output, 2, -1, 0);
    saved_errno = errno;
    expect_result("preadv2_current", result, saved_errno, 2, 0);
    dprintf(STDOUT_FILENO, "preadv2_current_data:%c%c offset:%lld\n",
            output_a[0], output_b[0],
            (long long)lseek(descriptor, 0, SEEK_CUR));
    if (output_a[0] != 'b' || output_b[0] != 'X' ||
        lseek(descriptor, 0, SEEK_CUR) != 3)
        ++g_failures;

    errno = 0;
    result = raw_pwritev2(descriptor, input, 2, -1, 0);
    saved_errno = errno;
    expect_result("pwritev2_current", result, saved_errno, 2, 0);
    if (!read_exact(descriptor, contents, 8, 0)) {
        ++g_failures;
    } else {
        dprintf(STDOUT_FILENO,
                "pwritev2_current_data:%s offset:%lld\n", contents,
                (long long)lseek(descriptor, 0, SEEK_CUR));
        if (memcmp(contents, "abXQR!gh", 8) ||
            lseek(descriptor, 0, SEEK_CUR) != 5)
            ++g_failures;
    }
}

static void test_append_and_flags(int descriptor) {
    char value = 'Z';
    char contents[10] = {0};
    struct iovec vector = { .iov_base = &value, .iov_len = 1 };
    long result;
    int saved_errno;

    if (lseek(descriptor, 2, SEEK_SET) != 2) ++g_failures;
    errno = 0;
    result = raw_pwritev2(descriptor, &vector, 1, 0, EDGE_RWF_APPEND);
    saved_errno = errno;
    expect_result("pwritev2_append", result, saved_errno, 1, 0);
    if (!read_exact(descriptor, contents, 9, 0)) {
        ++g_failures;
    } else {
        dprintf(STDOUT_FILENO, "pwritev2_append_data:%s offset:%lld\n",
                contents, (long long)lseek(descriptor, 0, SEEK_CUR));
        if (memcmp(contents, "abXQR!ghZ", 9) ||
            lseek(descriptor, 0, SEEK_CUR) != 2)
            ++g_failures;
    }

    errno = 0;
    result = raw_pwritev2(descriptor, &vector, 1, 0,
                          EDGE_RWF_DSYNC | EDGE_RWF_SYNC);
    saved_errno = errno;
    expect_result("pwritev2_sync_flags", result, saved_errno, 1, 0);

    errno = 0;
    result = raw_preadv2(descriptor, &vector, 1, 0, EDGE_RWF_APPEND);
    saved_errno = errno;
    expect_result("preadv2_append_flag", result, saved_errno, 1, 0);

    errno = 0;
    result = raw_pwritev2(descriptor, &vector, 1, 0, 0x80000000UL);
    saved_errno = errno;
    expect_result("pwritev2_unknown_flag", result, saved_errno,
                  -1, EOPNOTSUPP);

    errno = 0;
    result = raw_preadv2(descriptor, &vector, 1, -2, 0);
    saved_errno = errno;
    expect_result("preadv2_negative_two", result, saved_errno,
                  -1, EINVAL);
}

static void test_append_override(void) {
    char value = 'Y';
    char contents[8] = {0};
    struct iovec vector = { .iov_base = &value, .iov_len = 1 };
    int descriptor = open(g_path, O_RDWR | O_APPEND);
    long result;
    int saved_errno;

    if (descriptor < 0 || ftruncate(descriptor, 0) < 0 ||
        write(descriptor, "abc", 3) != 3 ||
        lseek(descriptor, 0, SEEK_SET) != 0) {
        dprintf(STDOUT_FILENO, "append_override_setup_errno:%d\n", errno);
        ++g_failures;
        if (descriptor >= 0) close(descriptor);
        return;
    }

    errno = 0;
    result = raw_pwrite64(descriptor, "X", 1, 0);
    saved_errno = errno;
    expect_result("pwrite_o_append", result, saved_errno, 1, 0);
    if (!read_exact(descriptor, contents, 4, 0) ||
        memcmp(contents, "abcX", 4) || lseek(descriptor, 0, SEEK_CUR) != 0)
        ++g_failures;
    dprintf(STDOUT_FILENO, "pwrite_o_append_data:%.*s offset:%lld\n",
            4, contents, (long long)lseek(descriptor, 0, SEEK_CUR));

    errno = 0;
    result = raw_pwritev2(descriptor, &vector, 1, 1,
                          EDGE_RWF_NOAPPEND);
    saved_errno = errno;
    expect_result("pwritev2_noappend", result, saved_errno, 1, 0);
    memset(contents, 0, sizeof(contents));
    if (!read_exact(descriptor, contents, 4, 0) ||
        memcmp(contents, "aYcX", 4) || lseek(descriptor, 0, SEEK_CUR) != 0)
        ++g_failures;
    dprintf(STDOUT_FILENO, "pwritev2_noappend_data:%.*s offset:%lld\n",
            4, contents, (long long)lseek(descriptor, 0, SEEK_CUR));

    close(descriptor);
}

static void test_partial_fault(int descriptor) {
    char first[3] = "12";
    struct iovec vectors[2] = {
        { .iov_base = first, .iov_len = 2 },
        { .iov_base = (void *)(uintptr_t)1, .iov_len = 2 },
    };
    long result;
    int saved_errno;

    if (ftruncate(descriptor, 0) < 0 || lseek(descriptor, 0, SEEK_SET) < 0) {
        ++g_failures;
        return;
    }
    errno = 0;
    result = writev(descriptor, vectors, 2);
    saved_errno = errno;
    expect_result("writev_partial_fault", result, saved_errno, 2, 0);
}

int main(void) {
    int descriptor;

    unlink(g_path);
    descriptor = open(g_path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (descriptor < 0) {
        dprintf(STDOUT_FILENO, "vector_io_setup_errno:%d\n", errno);
        return 1;
    }

    test_zero_vectors(descriptor);
    test_scalar_validation();
    test_scalar_zero_descriptor_semantics();
    test_record_zero_length();
    test_pipe_atomic_vectors();
    test_vector_error_ordering(descriptor);
    test_sequential_vectors(descriptor);
    test_positioned_vectors(descriptor);
    test_current_position_v2(descriptor);
    test_append_and_flags(descriptor);
    test_append_override();
    test_partial_fault(descriptor);

    close(descriptor);
    unlink(g_path);
    dprintf(STDOUT_FILENO, "VECTOR_IO_ABI_PROBE_%s failures:%d\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
