/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux-visible file-descriptor publication and rollback regression probe.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

enum {
    FD_SCAN_LIMIT = 4096,
    DUPLICATE_MINIMUM = 64,
    DUPLICATE_THREADS = 24,
    DUPLICATES_PER_BATCH = 8,
    DUPLICATE_ITERATIONS = 1000,
};

typedef struct fd_snapshot {
    unsigned char open[FD_SCAN_LIMIT];
} fd_snapshot_t;

typedef struct fault_region {
    void *mapping;
    size_t length;
    void *fault_page;
    void *control_data_fault;
} fault_region_t;

static _Noreturn void fail(const char *test, const char *format, ...) {
    va_list arguments;

    if (!test)
        test = "unknown";
    if (!format)
        format = "unspecified failure";
    fprintf(stderr, "FD_PUBLICATION_ABI_PROBE_FAIL %s: ", test);
    va_start(arguments, format);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

static void close_checked(int descriptor, const char *test) {
    if (close(descriptor) < 0)
        fail(test, "close(%d) failed with errno=%d", descriptor, errno);
}

static void take_fd_snapshot(fd_snapshot_t *snapshot, const char *test) {
    for (int descriptor = 0;
         descriptor < FD_SCAN_LIMIT; ++descriptor) {
        int flags;

        errno = 0;
        flags = fcntl(descriptor, F_GETFD);
        if (flags >= 0) {
            snapshot->open[descriptor] = 1;
        } else if (errno == EBADF) {
            snapshot->open[descriptor] = 0;
        } else {
            fail(test, "F_GETFD(%d) failed with errno=%d",
                 descriptor, errno);
        }
    }
}

static void require_same_snapshot(const fd_snapshot_t *expected,
                                  const char *test) {
    fd_snapshot_t observed;

    take_fd_snapshot(&observed, test);
    for (int descriptor = 0;
         descriptor < FD_SCAN_LIMIT; ++descriptor) {
        if (observed.open[descriptor] == expected->open[descriptor])
            continue;
        fail(test, "descriptor %d changed from %s to %s",
             descriptor,
             expected->open[descriptor] ? "open" : "closed",
             observed.open[descriptor] ? "open" : "closed");
    }
}

static int nth_free_descriptor(const fd_snapshot_t *snapshot,
                               int minimum,
                               unsigned int ordinal,
                               const char *test) {
    for (int descriptor = minimum;
         descriptor < FD_SCAN_LIMIT; ++descriptor) {
        if (snapshot->open[descriptor])
            continue;
        if (ordinal == 0)
            return descriptor;
        --ordinal;
    }
    fail(test, "not enough free descriptors below %d", FD_SCAN_LIMIT);
}

static void require_cloexec(int descriptor, int expected,
                            const char *test) {
    int flags = fcntl(descriptor, F_GETFD);

    if (flags < 0)
        fail(test, "F_GETFD(%d) failed with errno=%d",
             descriptor, errno);
    if (!!(flags & FD_CLOEXEC) != !!expected) {
        fail(test, "descriptor %d has CLOEXEC=%d, expected %d",
             descriptor, !!(flags & FD_CLOEXEC), !!expected);
    }
}

static void require_efault(long result, int saved_errno,
                           const char *test) {
    if (result != -1 || saved_errno != EFAULT) {
        fail(test, "result=%ld errno=%d, expected -1/EFAULT",
             result, saved_errno);
    }
}

static void require_error(long result, int saved_errno,
                          int expected_errno, const char *test) {
    if (result != -1 || saved_errno != expected_errno) {
        fail(test, "result=%ld errno=%d, expected -1/%d",
             result, saved_errno, expected_errno);
    }
}

static fault_region_t allocate_fault_region(void) {
    long configured_size = sysconf(_SC_PAGESIZE);
    fault_region_t region;
    size_t page_size;
    void *mapping;

    if (configured_size <= 0)
        fail("fault-page", "sysconf(_SC_PAGESIZE) returned %ld",
             configured_size);
    page_size = (size_t)configured_size;
    if (page_size > SIZE_MAX / 2)
        fail("fault-page", "page size is too large");
    region.length = page_size * 2;
    mapping = mmap(NULL, region.length, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        fail("fault-page", "mmap failed with errno=%d", errno);
    memset(mapping, 0, region.length);
    region.mapping = mapping;
    region.fault_page = (unsigned char *)mapping + page_size;
    region.control_data_fault =
        (unsigned char *)region.fault_page -
        CMSG_ALIGN(sizeof(struct cmsghdr));
    if (mprotect(region.fault_page, page_size, PROT_NONE) < 0)
        fail("fault-page", "mprotect failed with errno=%d", errno);
    return region;
}

static void require_environment_capacity(void) {
    struct rlimit limit;
    fd_snapshot_t snapshot;
    unsigned int available = 0;

    if (getrlimit(RLIMIT_NOFILE, &limit) < 0)
        fail("environment", "getrlimit failed with errno=%d", errno);
    if (limit.rlim_cur <=
        (rlim_t)(DUPLICATE_MINIMUM +
                 DUPLICATE_THREADS * DUPLICATES_PER_BATCH + 16)) {
        fail("environment", "RLIMIT_NOFILE=%llu is too small",
             (unsigned long long)limit.rlim_cur);
    }

    take_fd_snapshot(&snapshot, "environment");
    for (int descriptor = DUPLICATE_MINIMUM;
         descriptor < FD_SCAN_LIMIT; ++descriptor) {
        if (!snapshot.open[descriptor])
            ++available;
    }
    if (available <
        DUPLICATE_THREADS * DUPLICATES_PER_BATCH + 16) {
        fail("environment",
             "only %u tracked descriptors are free for concurrency",
             available);
    }
}

static void test_pipe2_fault(void *fault_page) {
    fd_snapshot_t before;
    int descriptors[2] = { -1, -1 };
    int first_expected;
    int second_expected;
    int saved_errno;
    long result;

    take_fd_snapshot(&before, "pipe2");
    first_expected = nth_free_descriptor(&before, 0, 0, "pipe2");
    second_expected = nth_free_descriptor(&before, 0, 1, "pipe2");

    errno = 0;
    result = syscall(SYS_pipe2, fault_page, O_CLOEXEC);
    saved_errno = errno;
    require_efault(result, saved_errno, "pipe2 invalid result");
    require_same_snapshot(&before, "pipe2 invalid result rollback");

    result = syscall(SYS_pipe2, descriptors, O_CLOEXEC);
    if (result != 0)
        fail("pipe2 reuse", "pipe2 failed with errno=%d", errno);
    if (descriptors[0] != first_expected ||
        descriptors[1] != second_expected) {
        fail("pipe2 reuse",
             "returned [%d,%d], expected lowest free [%d,%d]",
             descriptors[0], descriptors[1],
             first_expected, second_expected);
    }
    require_cloexec(descriptors[0], 1, "pipe2 CLOEXEC");
    require_cloexec(descriptors[1], 1, "pipe2 CLOEXEC");
    close_checked(descriptors[0], "pipe2 cleanup");
    close_checked(descriptors[1], "pipe2 cleanup");
    require_same_snapshot(&before, "pipe2 cleanup");
}

static void test_socketpair_fault(void *fault_page) {
    fd_snapshot_t before;
    int descriptors[2] = { -1, -1 };
    int *second_word_fault =
        (int *)((unsigned char *)fault_page - sizeof(int));
    int first_expected;
    int second_expected;
    int saved_errno;
    long result;

    take_fd_snapshot(&before, "socketpair");
    first_expected =
        nth_free_descriptor(&before, 0, 0, "socketpair");
    second_expected =
        nth_free_descriptor(&before, 0, 1, "socketpair");

    errno = 0;
    result = syscall(SYS_socketpair, AF_UNIX,
                     SOCK_STREAM | SOCK_CLOEXEC, 0, fault_page);
    saved_errno = errno;
    require_efault(result, saved_errno, "socketpair invalid result");
    require_same_snapshot(&before,
                          "socketpair invalid result rollback");

    errno = 0;
    result = syscall(SYS_socketpair, 0x7fffffff,
                     SOCK_STREAM, 0, fault_page);
    saved_errno = errno;
    require_efault(result, saved_errno,
                   "socketpair invalid family first-word fault");
    require_same_snapshot(
        &before, "socketpair invalid family first-word rollback");

    *second_word_fault = -1;
    errno = 0;
    result = syscall(SYS_socketpair, AF_UNIX,
                     SOCK_STREAM | SOCK_CLOEXEC, 0,
                     second_word_fault);
    saved_errno = errno;
    require_efault(result, saved_errno,
                   "socketpair second-word fault");
    if (*second_word_fault != first_expected) {
        fail("socketpair second-word fault",
             "first word=%d, expected reserved descriptor %d",
             *second_word_fault, first_expected);
    }
    require_same_snapshot(&before,
                          "socketpair second-word rollback");

    *second_word_fault = -2;
    errno = 0;
    result = syscall(SYS_socketpair, 0x7fffffff,
                     SOCK_STREAM, 0, second_word_fault);
    saved_errno = errno;
    require_efault(result, saved_errno,
                   "socketpair invalid family second-word fault");
    if (*second_word_fault != first_expected) {
        fail("socketpair invalid family second-word fault",
             "first word=%d, expected reserved descriptor %d",
             *second_word_fault, first_expected);
    }
    require_same_snapshot(
        &before, "socketpair invalid family second-word rollback");

    *second_word_fault = -3;
    errno = 0;
    result = syscall(SYS_socketpair, AF_UNIX,
                     SOCK_STREAM | 0x400000, 0,
                     second_word_fault);
    saved_errno = errno;
    require_error(result, saved_errno, EINVAL,
                  "socketpair invalid flag before output");
    if (*second_word_fault != -3) {
        fail("socketpair invalid flag before output",
             "first output word changed to %d",
             *second_word_fault);
    }
    require_same_snapshot(
        &before, "socketpair invalid flag before output rollback");

    descriptors[0] = -101;
    descriptors[1] = -102;
    errno = 0;
    result = syscall(SYS_socketpair, 0x7fffffff,
                     SOCK_STREAM, 0, descriptors);
    saved_errno = errno;
    require_error(result, saved_errno, EAFNOSUPPORT,
                  "socketpair invalid family");
    if (descriptors[0] != first_expected ||
        descriptors[1] != second_expected) {
        fail("socketpair invalid family",
             "returned [%d,%d], expected reserved [%d,%d]",
             descriptors[0], descriptors[1],
             first_expected, second_expected);
    }
    require_same_snapshot(&before,
                          "socketpair invalid family rollback");

    descriptors[0] = -103;
    descriptors[1] = -104;
    errno = 0;
    result = syscall(SYS_socketpair, AF_INET,
                     SOCK_STREAM, 0, descriptors);
    saved_errno = errno;
    require_error(result, saved_errno, EOPNOTSUPP,
                  "socketpair unsupported family pair");
    if (descriptors[0] != first_expected ||
        descriptors[1] != second_expected) {
        fail("socketpair unsupported family pair",
             "returned [%d,%d], expected reserved [%d,%d]",
             descriptors[0], descriptors[1],
             first_expected, second_expected);
    }
    require_same_snapshot(
        &before, "socketpair unsupported family pair rollback");

    descriptors[0] = -105;
    descriptors[1] = -106;
    errno = 0;
    result = syscall(SYS_socketpair, AF_UNIX,
                     SOCK_STREAM, 0x7fffffff, descriptors);
    saved_errno = errno;
    require_error(result, saved_errno, EPROTONOSUPPORT,
                  "socketpair invalid protocol");
    if (descriptors[0] != first_expected ||
        descriptors[1] != second_expected) {
        fail("socketpair invalid protocol",
             "returned [%d,%d], expected reserved [%d,%d]",
             descriptors[0], descriptors[1],
             first_expected, second_expected);
    }
    require_same_snapshot(&before,
                          "socketpair invalid protocol rollback");

    descriptors[0] = -107;
    descriptors[1] = -108;
    errno = 0;
    result = syscall(SYS_socketpair, AF_UNIX,
                     SOCK_STREAM | 0x400000, 0, descriptors);
    saved_errno = errno;
    require_error(result, saved_errno, EINVAL,
                  "socketpair invalid flag");
    if (descriptors[0] != -107 || descriptors[1] != -108) {
        fail("socketpair invalid flag",
             "output changed to [%d,%d] before flag rejection",
             descriptors[0], descriptors[1]);
    }
    require_same_snapshot(&before,
                          "socketpair invalid flag rollback");

    result = syscall(SYS_socketpair, AF_UNIX,
                     SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors);
    if (result != 0)
        fail("socketpair reuse",
             "socketpair failed with errno=%d", errno);
    if (descriptors[0] != first_expected ||
        descriptors[1] != second_expected) {
        fail("socketpair reuse",
             "returned [%d,%d], expected lowest free [%d,%d]",
             descriptors[0], descriptors[1],
             first_expected, second_expected);
    }
    require_cloexec(descriptors[0], 1, "socketpair CLOEXEC");
    require_cloexec(descriptors[1], 1, "socketpair CLOEXEC");
    close_checked(descriptors[0], "socketpair cleanup");
    close_checked(descriptors[1], "socketpair cleanup");
    require_same_snapshot(&before, "socketpair cleanup");
}

static int create_connected_client(const struct sockaddr_in *address,
                                   const char *test) {
    int descriptor = socket(AF_INET,
                            SOCK_STREAM | SOCK_CLOEXEC,
                            IPPROTO_TCP);

    if (descriptor < 0)
        fail(test, "socket failed with errno=%d", errno);
    if (connect(descriptor, (const struct sockaddr *)address,
                sizeof(*address)) < 0) {
        fail(test, "connect failed with errno=%d", errno);
    }
    require_cloexec(descriptor, 1, test);
    return descriptor;
}

static void test_accept4_address_fault(void *fault_page) {
    fd_snapshot_t outer;
    fd_snapshot_t before_fault;
    fd_snapshot_t before_success;
    struct sockaddr_in address;
    socklen_t address_length;
    socklen_t peer_length;
    int listener;
    int first_client;
    int second_client;
    int accepted;
    int recycled_expected;
    int accepted_expected;
    int saved_errno;
    long result;

    take_fd_snapshot(&outer, "accept4 setup");
    listener = socket(AF_INET,
                      SOCK_STREAM | SOCK_CLOEXEC,
                      IPPROTO_TCP);
    if (listener < 0)
        fail("accept4 setup", "listener socket failed with errno=%d",
             errno);

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, (const struct sockaddr *)&address,
             sizeof(address)) < 0) {
        fail("accept4 setup", "bind failed with errno=%d", errno);
    }
    if (listen(listener, 8) < 0)
        fail("accept4 setup", "listen failed with errno=%d", errno);
    address_length = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address,
                    &address_length) < 0) {
        fail("accept4 setup", "getsockname failed with errno=%d",
             errno);
    }
    if (address_length != sizeof(address) ||
        address.sin_family != AF_INET ||
        address.sin_port == 0) {
        fail("accept4 setup",
             "getsockname returned an invalid loopback address");
    }

    first_client = create_connected_client(&address, "accept4 queue");
    take_fd_snapshot(&before_fault, "accept4 fault");
    recycled_expected =
        nth_free_descriptor(&before_fault, 0, 0, "accept4 fault");
    peer_length = sizeof(struct sockaddr_storage);
    errno = 0;
    result = syscall(SYS_accept4, listener, fault_page,
                     &peer_length, SOCK_CLOEXEC);
    saved_errno = errno;
    require_efault(result, saved_errno, "accept4 address copy");
    if (peer_length != sizeof(struct sockaddr_in)) {
        fail("accept4 address copy",
             "addrlen=%u after EFAULT, expected %zu",
             (unsigned int)peer_length,
             sizeof(struct sockaddr_in));
    }
    require_same_snapshot(&before_fault, "accept4 rollback");

    second_client =
        create_connected_client(&address, "accept4 second queue");
    if (second_client != recycled_expected) {
        fail("accept4 reuse",
             "socket reused descriptor %d, expected %d",
             second_client, recycled_expected);
    }
    take_fd_snapshot(&before_success, "accept4 success");
    accepted_expected =
        nth_free_descriptor(&before_success, 0, 0, "accept4 success");
    result = syscall(SYS_accept4, listener, NULL, NULL, SOCK_CLOEXEC);
    if (result < 0)
        fail("accept4 success", "accept4 failed with errno=%d", errno);
    accepted = (int)result;
    if (accepted != accepted_expected) {
        fail("accept4 success",
             "accepted descriptor %d, expected lowest free %d",
             accepted, accepted_expected);
    }
    require_cloexec(accepted, 1, "accept4 CLOEXEC");

    close_checked(accepted, "accept4 cleanup");
    close_checked(second_client, "accept4 cleanup");
    close_checked(first_client, "accept4 cleanup");
    close_checked(listener, "accept4 cleanup");
    require_same_snapshot(&outer, "accept4 cleanup");
}

typedef union scm_control_buffer {
    struct cmsghdr alignment;
    unsigned char bytes[CMSG_SPACE(sizeof(int))];
} scm_control_buffer_t;

static void send_one_descriptor(int socket_descriptor,
                                int passed_descriptor,
                                unsigned char payload,
                                size_t payload_length,
                                const char *test) {
    struct iovec vector = {
        .iov_base = &payload,
        .iov_len = sizeof(payload),
    };
    scm_control_buffer_t control;
    struct msghdr message;
    struct cmsghdr *header;
    ssize_t result;

    if (payload_length > sizeof(payload))
        fail(test, "invalid payload length %zu", payload_length);
    memset(&control, 0, sizeof(control));
    memset(&message, 0, sizeof(message));
    if (payload_length) {
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
    }
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    header = CMSG_FIRSTHDR(&message);
    if (!header)
        fail(test, "CMSG_FIRSTHDR returned NULL");
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(passed_descriptor));
    memcpy(CMSG_DATA(header), &passed_descriptor,
           sizeof(passed_descriptor));

    result = sendmsg(socket_descriptor, &message, 0);
    if (result != (ssize_t)payload_length) {
        fail(test, "sendmsg returned %zd with errno=%d",
             result, errno);
    }
}

static int receive_one_descriptor(int socket_descriptor,
                                  unsigned char *payload,
                                  const char *test) {
    struct iovec vector = {
        .iov_base = payload,
        .iov_len = sizeof(*payload),
    };
    scm_control_buffer_t control;
    struct msghdr message;
    struct cmsghdr *header;
    struct cmsghdr *next;
    int descriptor = -1;
    ssize_t result;

    memset(&control, 0, sizeof(control));
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    result = recvmsg(socket_descriptor, &message, MSG_CMSG_CLOEXEC);
    if (result != (ssize_t)sizeof(*payload)) {
        fail(test, "recvmsg returned %zd with errno=%d",
             result, errno);
    }
    if (message.msg_flags & MSG_CTRUNC)
        fail(test, "recvmsg reported MSG_CTRUNC");

    header = CMSG_FIRSTHDR(&message);
    if (!header ||
        header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(descriptor))) {
        fail(test, "recvmsg returned malformed SCM_RIGHTS control data");
    }
    memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
    next = CMSG_NXTHDR(&message, header);
    if (next)
        fail(test, "recvmsg returned unexpected extra control data");
    return descriptor;
}

static void require_control_truncation(const struct msghdr *message,
                                       long result,
                                       long expected_result,
                                       const char *test) {
    if (result != expected_result) {
        fail(test, "recvmsg returned %ld, expected %ld",
             result, expected_result);
    }
    if (!(message->msg_flags & MSG_CTRUNC))
        fail(test, "recvmsg did not report MSG_CTRUNC");
    if (!(message->msg_flags & MSG_CMSG_CLOEXEC)) {
        fail(test,
             "recvmsg did not report the requested MSG_CMSG_CLOEXEC");
    }
    if (message->msg_controllen != 0) {
        fail(test, "recvmsg returned msg_controllen=%zu, expected 0",
             (size_t)message->msg_controllen);
    }
}

static void test_scm_rights_control_faults(
    void *whole_control_fault,
    void *control_data_fault) {
    fd_snapshot_t outer;
    fd_snapshot_t before_whole_fault;
    fd_snapshot_t before_data_fault;
    int sockets[2] = { -1, -1 };
    int source;
    int received;
    int received_expected;
    unsigned char payload = 0;
    unsigned char receive_byte = 0;
    struct iovec vector = {
        .iov_base = &receive_byte,
        .iov_len = sizeof(receive_byte),
    };
    struct msghdr message;
    long result;

    take_fd_snapshot(&outer, "SCM_RIGHTS setup");
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
                   0, sockets) < 0) {
        fail("SCM_RIGHTS setup",
             "socketpair failed with errno=%d", errno);
    }
    source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (source < 0)
        fail("SCM_RIGHTS setup", "open failed with errno=%d", errno);

    /*
     * Linux treats an inaccessible ancillary buffer as discarded control
     * data: recvmsg returns the payload length, reports MSG_CTRUNC, and
     * installs no descriptor.
     */
    send_one_descriptor(sockets[0], source, 'A', 1,
                        "SCM_RIGHTS whole-control fault queue");
    take_fd_snapshot(&before_whole_fault,
                     "SCM_RIGHTS whole-control fault");
    memset(&message, 0, sizeof(message));
    receive_byte = 0;
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = whole_control_fault;
    message.msg_controllen = CMSG_SPACE(sizeof(int));
    result = syscall(SYS_recvmsg, sockets[1], &message,
                     MSG_CMSG_CLOEXEC);
    require_control_truncation(
        &message, result, 1, "SCM_RIGHTS whole-control fault");
    if (receive_byte != 'A') {
        fail("SCM_RIGHTS whole-control fault",
             "recvmsg returned payload 0x%02x, expected 0x41",
             receive_byte);
    }
    require_same_snapshot(&before_whole_fault,
                          "SCM_RIGHTS whole-control rollback");

    /*
     * The cmsghdr itself is writable, while CMSG_DATA starts on a PROT_NONE
     * page.  A zero-payload datagram makes the successful return value
     * unambiguously zero while retaining the same truncation semantics.
     */
    send_one_descriptor(sockets[0], source, 'C', 0,
                        "SCM_RIGHTS data fault queue");
    take_fd_snapshot(&before_data_fault, "SCM_RIGHTS data fault");
    received_expected =
        nth_free_descriptor(&before_data_fault, 0, 0,
                            "SCM_RIGHTS data fault");
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control_data_fault;
    message.msg_controllen = CMSG_SPACE(sizeof(int));
    result = syscall(SYS_recvmsg, sockets[1], &message,
                     MSG_CMSG_CLOEXEC);
    require_control_truncation(
        &message, result, 0, "SCM_RIGHTS data fault");
    require_same_snapshot(&before_data_fault,
                          "SCM_RIGHTS data-fault rollback");

    send_one_descriptor(sockets[0], source, 'B', 1,
                        "SCM_RIGHTS success queue");
    received = receive_one_descriptor(
        sockets[1], &payload, "SCM_RIGHTS success");
    if (received != received_expected) {
        fail("SCM_RIGHTS reuse",
             "received descriptor %d, expected lowest free %d",
             received, received_expected);
    }
    require_cloexec(received, 1, "SCM_RIGHTS CLOEXEC");

    close_checked(received, "SCM_RIGHTS cleanup");
    close_checked(source, "SCM_RIGHTS cleanup");
    close_checked(sockets[0], "SCM_RIGHTS cleanup");
    close_checked(sockets[1], "SCM_RIGHTS cleanup");
    require_same_snapshot(&outer, "SCM_RIGHTS cleanup");
}

enum duplicate_failure {
    DUPLICATE_FAILURE_NONE = 0,
    DUPLICATE_FAILURE_FCNTL,
    DUPLICATE_FAILURE_RANGE,
    DUPLICATE_FAILURE_OWNERSHIP,
    DUPLICATE_FAILURE_GETFD,
    DUPLICATE_FAILURE_CLOEXEC,
    DUPLICATE_FAILURE_CLOSE,
};

typedef struct duplicate_shared {
    int source;
    atomic_int start;
    atomic_uchar *owners;
} duplicate_shared_t;

typedef struct duplicate_worker {
    duplicate_shared_t *shared;
    unsigned int index;
    enum duplicate_failure failure;
    int saved_errno;
    int descriptor;
    int command;
    unsigned int iteration;
} duplicate_worker_t;

static void record_duplicate_failure(duplicate_worker_t *worker,
                                     enum duplicate_failure failure,
                                     int saved_errno,
                                     int descriptor,
                                     int command,
                                     unsigned int iteration) {
    if (worker->failure != DUPLICATE_FAILURE_NONE)
        return;
    worker->failure = failure;
    worker->saved_errno = saved_errno;
    worker->descriptor = descriptor;
    worker->command = command;
    worker->iteration = iteration;
}

static void *duplicate_worker_main(void *opaque) {
    duplicate_worker_t *worker = opaque;
    duplicate_shared_t *shared = worker->shared;

    while (!atomic_load_explicit(&shared->start,
                                 memory_order_acquire))
        sched_yield();

    for (unsigned int iteration = 0;
         iteration < DUPLICATE_ITERATIONS; ++iteration) {
        int descriptors[DUPLICATES_PER_BATCH];
        unsigned char owned[DUPLICATES_PER_BATCH] = { 0 };
        unsigned int allocated = 0;

        for (unsigned int slot = 0;
             slot < DUPLICATES_PER_BATCH; ++slot) {
            int command =
                ((iteration + slot + worker->index) & 1u) ?
                    F_DUPFD_CLOEXEC : F_DUPFD;
            int descriptor;
            int flags;
            unsigned char expected_owner = 0;

            errno = 0;
            descriptor = fcntl(shared->source, command,
                               DUPLICATE_MINIMUM);
            if (descriptor < 0) {
                record_duplicate_failure(
                    worker, DUPLICATE_FAILURE_FCNTL, errno,
                    descriptor, command, iteration);
                break;
            }
            descriptors[allocated++] = descriptor;
            if (descriptor >= FD_SCAN_LIMIT) {
                record_duplicate_failure(
                    worker, DUPLICATE_FAILURE_RANGE, 0,
                    descriptor, command, iteration);
                break;
            }
            if (!atomic_compare_exchange_strong_explicit(
                    &shared->owners[descriptor], &expected_owner, 1,
                    memory_order_acq_rel, memory_order_acquire)) {
                record_duplicate_failure(
                    worker, DUPLICATE_FAILURE_OWNERSHIP, 0,
                    descriptor, command, iteration);
                break;
            }
            owned[allocated - 1] = 1;

            errno = 0;
            flags = fcntl(descriptor, F_GETFD);
            if (flags < 0) {
                record_duplicate_failure(
                    worker, DUPLICATE_FAILURE_GETFD, errno,
                    descriptor, command, iteration);
                break;
            }
            if (!!(flags & FD_CLOEXEC) !=
                (command == F_DUPFD_CLOEXEC)) {
                record_duplicate_failure(
                    worker, DUPLICATE_FAILURE_CLOEXEC, 0,
                    descriptor, command, iteration);
                break;
            }
        }

        sched_yield();
        while (allocated > 0) {
            int descriptor;

            --allocated;
            descriptor = descriptors[allocated];
            if (owned[allocated]) {
                atomic_store_explicit(
                    &shared->owners[descriptor], 0,
                    memory_order_release);
            }
            if (close(descriptor) < 0) {
                record_duplicate_failure(
                    worker, DUPLICATE_FAILURE_CLOSE, errno,
                    descriptor, 0, iteration);
            }
        }
        if (worker->failure != DUPLICATE_FAILURE_NONE)
            break;
    }
    return NULL;
}

static void report_duplicate_failure(
    const duplicate_worker_t *worker) {
    const char *command =
        worker->command == F_DUPFD_CLOEXEC ?
            "F_DUPFD_CLOEXEC" : "F_DUPFD";

    switch (worker->failure) {
    case DUPLICATE_FAILURE_FCNTL:
        fail("concurrent duplicate",
             "worker=%u iteration=%u %s failed with errno=%d%s",
             worker->index, worker->iteration, command,
             worker->saved_errno,
             worker->saved_errno == EBUSY ?
                 " (spurious EBUSY)" : "");
    case DUPLICATE_FAILURE_RANGE:
        fail("concurrent duplicate",
             "worker=%u iteration=%u %s returned untracked fd=%d",
             worker->index, worker->iteration,
             command, worker->descriptor);
    case DUPLICATE_FAILURE_OWNERSHIP:
        fail("concurrent duplicate",
             "worker=%u iteration=%u observed duplicate ownership of fd=%d",
             worker->index, worker->iteration, worker->descriptor);
    case DUPLICATE_FAILURE_GETFD:
        fail("concurrent duplicate",
             "worker=%u iteration=%u F_GETFD(%d) failed with errno=%d",
             worker->index, worker->iteration, worker->descriptor,
             worker->saved_errno);
    case DUPLICATE_FAILURE_CLOEXEC:
        fail("concurrent duplicate",
             "worker=%u iteration=%u %s returned fd=%d with wrong CLOEXEC",
             worker->index, worker->iteration,
             command, worker->descriptor);
    case DUPLICATE_FAILURE_CLOSE:
        fail("concurrent duplicate",
             "worker=%u iteration=%u close(%d) failed with errno=%d",
             worker->index, worker->iteration, worker->descriptor,
             worker->saved_errno);
    case DUPLICATE_FAILURE_NONE:
        return;
    }
    fail("concurrent duplicate", "unknown worker failure");
}

static void test_concurrent_duplicate(void) {
    fd_snapshot_t outer;
    fd_snapshot_t with_source;
    duplicate_shared_t shared;
    duplicate_worker_t workers[DUPLICATE_THREADS];
    pthread_t threads[DUPLICATE_THREADS];
    int source;
    int duplicated;
    int expected;

    take_fd_snapshot(&outer, "duplicate setup");
    source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (source < 0)
        fail("duplicate setup", "open failed with errno=%d", errno);
    require_cloexec(source, 1, "duplicate source CLOEXEC");
    take_fd_snapshot(&with_source, "duplicate serial");

    expected = nth_free_descriptor(
        &with_source, DUPLICATE_MINIMUM, 0, "F_DUPFD lowest");
    duplicated = fcntl(source, F_DUPFD, DUPLICATE_MINIMUM);
    if (duplicated < 0)
        fail("F_DUPFD lowest", "fcntl failed with errno=%d", errno);
    if (duplicated != expected) {
        fail("F_DUPFD lowest", "returned %d, expected %d",
             duplicated, expected);
    }
    require_cloexec(duplicated, 0, "F_DUPFD clears CLOEXEC");
    close_checked(duplicated, "F_DUPFD cleanup");

    expected = nth_free_descriptor(
        &with_source, DUPLICATE_MINIMUM, 0,
        "F_DUPFD_CLOEXEC lowest");
    duplicated =
        fcntl(source, F_DUPFD_CLOEXEC, DUPLICATE_MINIMUM);
    if (duplicated < 0) {
        fail("F_DUPFD_CLOEXEC lowest",
             "fcntl failed with errno=%d", errno);
    }
    if (duplicated != expected) {
        fail("F_DUPFD_CLOEXEC lowest",
             "returned %d, expected %d", duplicated, expected);
    }
    require_cloexec(duplicated, 1, "F_DUPFD_CLOEXEC sets CLOEXEC");
    close_checked(duplicated, "F_DUPFD_CLOEXEC cleanup");
    require_same_snapshot(&with_source, "serial duplicate cleanup");

    shared.source = source;
    atomic_init(&shared.start, 0);
    shared.owners =
        calloc(FD_SCAN_LIMIT, sizeof(*shared.owners));
    if (!shared.owners)
        fail("concurrent duplicate", "owner allocation failed");
    for (int descriptor = 0;
         descriptor < FD_SCAN_LIMIT; ++descriptor)
        atomic_init(&shared.owners[descriptor], 0);

    memset(workers, 0, sizeof(workers));
    for (unsigned int index = 0;
         index < DUPLICATE_THREADS; ++index) {
        int error;

        workers[index].shared = &shared;
        workers[index].index = index;
        error = pthread_create(&threads[index], NULL,
                               duplicate_worker_main,
                               &workers[index]);
        if (error != 0) {
            fail("concurrent duplicate",
                 "pthread_create(%u) failed with error=%d",
                 index, error);
        }
    }
    atomic_store_explicit(&shared.start, 1, memory_order_release);
    for (unsigned int index = 0;
         index < DUPLICATE_THREADS; ++index) {
        int error = pthread_join(threads[index], NULL);

        if (error != 0) {
            fail("concurrent duplicate",
                 "pthread_join(%u) failed with error=%d",
                 index, error);
        }
    }
    for (unsigned int index = 0;
         index < DUPLICATE_THREADS; ++index) {
        if (workers[index].failure != DUPLICATE_FAILURE_NONE)
            report_duplicate_failure(&workers[index]);
    }
    for (int descriptor = 0;
         descriptor < FD_SCAN_LIMIT; ++descriptor) {
        if (atomic_load_explicit(
                &shared.owners[descriptor],
                memory_order_acquire) != 0) {
            fail("concurrent duplicate",
                 "descriptor %d retained an ownership marker",
                 descriptor);
        }
    }
    free(shared.owners);
    require_same_snapshot(&with_source,
                          "concurrent duplicate cleanup");
    close_checked(source, "duplicate source cleanup");
    require_same_snapshot(&outer, "duplicate final cleanup");
}

int main(void) {
    fault_region_t fault_region;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    require_environment_capacity();
    fault_region = allocate_fault_region();

    test_pipe2_fault(fault_region.fault_page);
    test_socketpair_fault(fault_region.fault_page);
    test_accept4_address_fault(fault_region.fault_page);
    test_scm_rights_control_faults(
        fault_region.fault_page,
        fault_region.control_data_fault);
    test_concurrent_duplicate();

    if (munmap(fault_region.mapping, fault_region.length) < 0)
        fail("fault-page cleanup", "munmap failed with errno=%d", errno);
    puts("FD_PUBLICATION_ABI_PROBE_PASS");
    return 0;
}
