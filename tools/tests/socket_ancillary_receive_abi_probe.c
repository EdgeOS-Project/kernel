/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux recvmsg ancillary-output truncation and fault regression probe.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_close_range
#if defined(__x86_64__) || defined(__aarch64__)
#define SYS_close_range 436
#else
#error "SYS_close_range is required by this probe"
#endif
#endif

enum {
    RIGHTS_COUNT = 3,
    FIRST_RECEIVED_FD = 5,
    FD_CHECK_MAX = 64,
    CONTROL_PATTERN = 0xa5,
};

enum ancillary_kind {
    ANCILLARY_CREDENTIALS,
    ANCILLARY_TIMESTAMPNS,
};

enum fault_layout {
    FAULT_WHOLE_CONTROL,
    FAULT_CMSG_DATA,
};

struct rights_capacity_case {
    const char *name;
    size_t capacity;
    unsigned int expected_count;
    size_t expected_controllen;
    int expected_truncated;
};

struct ancillary_description {
    enum ancillary_kind kind;
    const char *name;
    int socket_option;
    int control_type;
    size_t data_size;
};

struct ancillary_fault_case {
    const char *name;
    const struct ancillary_description *ancillary;
    enum fault_layout layout;
};

struct ancillary_partial_case {
    const char *name;
    const struct ancillary_description *ancillary;
    size_t capacity;
    size_t copied_data;
};

struct fault_region {
    void *mapping;
    size_t mapping_size;
    void *fault_page;
    void *data_fault_control;
};

typedef void (*isolated_test_fn)(const void *argument);

union rights_control {
    struct cmsghdr alignment;
    unsigned char bytes[CMSG_SPACE(RIGHTS_COUNT * sizeof(int))];
};

union metadata_control {
    struct cmsghdr alignment;
    unsigned char bytes[64];
};

static const struct ancillary_description credentials_description = {
    ANCILLARY_CREDENTIALS,
    "credentials",
    SO_PASSCRED,
    SCM_CREDENTIALS,
    sizeof(struct ucred),
};

static const struct ancillary_description timestamp_description = {
    ANCILLARY_TIMESTAMPNS,
    "timestampns",
    SO_TIMESTAMPNS,
    SCM_TIMESTAMPNS,
    sizeof(struct timespec),
};

static _Noreturn void fail(const char *format, ...)
{
    va_list arguments;

    dprintf(STDERR_FILENO, "SOCKET_ANCILLARY_RECEIVE_ABI_PROBE_FAIL ");
    va_start(arguments, format);
    vdprintf(STDERR_FILENO, format, arguments);
    va_end(arguments);
    dprintf(STDERR_FILENO, "\n");
    _exit(EXIT_FAILURE);
}

static void expect_long(const char *name, long actual, long expected)
{
    if (actual != expected) {
        fail("%s actual=%ld expected=%ld", name, actual, expected);
    }
}

static void expect_errno_result(const char *name,
                                long actual,
                                int actual_errno,
                                long expected,
                                int expected_errno)
{
    if (actual != expected || actual_errno != expected_errno) {
        fail("%s result=%ld errno=%d expected_result=%ld expected_errno=%d",
             name,
             actual,
             actual_errno,
             expected,
             expected_errno);
    }
}

static int descriptor_flags(int descriptor)
{
    int result;

    errno = 0;
    result = fcntl(descriptor, F_GETFD);
    if (result < 0 && errno != EBADF) {
        fail("fcntl(F_GETFD, %d) errno=%d", descriptor, errno);
    }
    return result;
}

static void expect_descriptor_open(int descriptor, int expected_cloexec)
{
    int flags = descriptor_flags(descriptor);

    if (flags < 0) {
        fail("descriptor %d is closed", descriptor);
    }
    if (!!(flags & FD_CLOEXEC) != !!expected_cloexec) {
        fail("descriptor %d CLOEXEC=%d expected=%d",
             descriptor,
             !!(flags & FD_CLOEXEC),
             !!expected_cloexec);
    }
}

static void expect_descriptor_closed(int descriptor)
{
    int flags;
    int saved_errno;

    errno = 0;
    flags = fcntl(descriptor, F_GETFD);
    saved_errno = errno;
    if (flags != -1 || saved_errno != EBADF) {
        fail("descriptor %d result=%d errno=%d expected=-1/EBADF",
             descriptor,
             flags,
             saved_errno);
    }
}

static void ensure_standard_descriptors(void)
{
    int descriptor;

    for (descriptor = STDIN_FILENO; descriptor <= STDERR_FILENO; descriptor++) {
        int flags;

        errno = 0;
        flags = fcntl(descriptor, F_GETFD);
        if (flags >= 0) {
            continue;
        }
        if (errno != EBADF) {
            fail("standard descriptor %d inspection errno=%d",
                 descriptor,
                 errno);
        }

        flags = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (flags < 0) {
            fail("open(/dev/null) for standard descriptor errno=%d", errno);
        }
        if (flags != descriptor) {
            if (dup2(flags, descriptor) != descriptor) {
                fail("dup2 standard descriptor %d errno=%d",
                     descriptor,
                     errno);
            }
            if (close(flags) != 0) {
                fail("close standard temporary descriptor errno=%d", errno);
            }
        }
    }
}

static void prepare_isolated_descriptor_table(void)
{
    int descriptor;

    ensure_standard_descriptors();
    errno = 0;
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) != 0) {
        fail("close_range errno=%d", errno);
    }
    for (descriptor = 3; descriptor < FD_CHECK_MAX; descriptor++) {
        expect_descriptor_closed(descriptor);
    }
}

static void expect_no_descriptors_from(int first)
{
    int descriptor;

    for (descriptor = first; descriptor < FD_CHECK_MAX; descriptor++) {
        expect_descriptor_closed(descriptor);
    }
}

static void close_checked(int descriptor)
{
    if (close(descriptor) != 0) {
        fail("close(%d) errno=%d", descriptor, errno);
    }
}

static void create_exact_socket_pair(int sockets[2])
{
    if (socketpair(AF_UNIX,
                   SOCK_DGRAM | SOCK_CLOEXEC,
                   0,
                   sockets) != 0) {
        fail("socketpair errno=%d", errno);
    }
    expect_long("socketpair sender", sockets[0], 3);
    expect_long("socketpair receiver", sockets[1], 4);
}

static void expect_queue_empty(int receiver, const char *name)
{
    unsigned char byte = 0;
    ssize_t result;
    int saved_errno;

    errno = 0;
    result = recv(receiver, &byte, sizeof(byte), MSG_DONTWAIT);
    saved_errno = errno;
    expect_errno_result(name, result, saved_errno, -1, EAGAIN);
    dprintf(STDOUT_FILENO,
            "OBS name=%s result=%zd errno=%d consumed=1\n",
            name,
            result,
            saved_errno);
}

static void close_socket_pair_and_verify(int sockets[2])
{
    close_checked(sockets[0]);
    close_checked(sockets[1]);
    expect_no_descriptors_from(3);
}

static void send_three_rights(int sender)
{
    int sources[RIGHTS_COUNT];
    union rights_control control;
    struct cmsghdr *header;
    struct iovec vector;
    struct msghdr message;
    unsigned char payload = 'R';
    ssize_t result;
    unsigned int index;

    for (index = 0; index < RIGHTS_COUNT; index++) {
        sources[index] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (sources[index] < 0) {
            fail("open rights source %u errno=%d", index, errno);
        }
        expect_long("rights source descriptor",
                    sources[index],
                    FIRST_RECEIVED_FD + (int)index);
    }

    memset(&control, 0, sizeof(control));
    memset(&message, 0, sizeof(message));
    vector.iov_base = &payload;
    vector.iov_len = sizeof(payload);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    header = CMSG_FIRSTHDR(&message);
    if (header == NULL) {
        fail("CMSG_FIRSTHDR returned NULL while sending rights");
    }
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(sources));
    memcpy(CMSG_DATA(header), sources, sizeof(sources));

    errno = 0;
    result = sendmsg(sender, &message, 0);
    expect_errno_result("sendmsg three rights", result, errno, 1, 0);

    for (index = 0; index < RIGHTS_COUNT; index++) {
        close_checked(sources[index]);
    }
    expect_no_descriptors_from(FIRST_RECEIVED_FD);
}

static void test_rights_capacity(const void *argument)
{
    const struct rights_capacity_case *test = argument;
    int sockets[2];
    union rights_control control;
    struct iovec vector;
    struct msghdr message;
    struct cmsghdr *header;
    unsigned char payload = 0;
    ssize_t result;
    int saved_errno;
    unsigned int index;
    unsigned int observed_count = 0;
    unsigned int observed_cloexec_count = 0;
    int observed_lowest = -1;
    int expected_flags = MSG_CMSG_CLOEXEC;

    prepare_isolated_descriptor_table();
    create_exact_socket_pair(sockets);
    send_three_rights(sockets[0]);

    memset(&control, CONTROL_PATTERN, sizeof(control));
    memset(&message, 0, sizeof(message));
    vector.iov_base = &payload;
    vector.iov_len = sizeof(payload);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = test->capacity;

    errno = 0;
    result = recvmsg(sockets[1], &message, MSG_CMSG_CLOEXEC);
    saved_errno = errno;
    if (test->expected_truncated) {
        expected_flags |= MSG_CTRUNC;
    }
    for (index = FIRST_RECEIVED_FD; index < FD_CHECK_MAX; index++) {
        int flags = descriptor_flags((int)index);

        if (flags < 0) {
            continue;
        }
        if (observed_lowest < 0) {
            observed_lowest = (int)index;
        }
        observed_count++;
        if (flags & FD_CLOEXEC) {
            observed_cloexec_count++;
        }
    }

    dprintf(STDOUT_FILENO,
            "OBS name=%s result=%zd errno=%d flags=0x%x controllen=%zu "
            "installed=%u lowest=%d cloexec=%u\n",
            test->name,
            result,
            saved_errno,
            message.msg_flags,
            (size_t)message.msg_controllen,
            observed_count,
            observed_lowest,
            observed_cloexec_count);

    expect_errno_result(test->name, result, saved_errno, 1, 0);
    expect_long("SCM_RIGHTS payload", payload, 'R');
    expect_long("SCM_RIGHTS msg_flags",
                message.msg_flags,
                expected_flags);
    expect_long("SCM_RIGHTS msg_controllen",
                (long)message.msg_controllen,
                (long)test->expected_controllen);
    expect_long("SCM_RIGHTS installed count",
                observed_count,
                test->expected_count);
    expect_long("SCM_RIGHTS CLOEXEC count",
                observed_cloexec_count,
                test->expected_count);
    expect_long("SCM_RIGHTS lowest installed descriptor",
                observed_lowest,
                test->expected_count == 0 ? -1 : FIRST_RECEIVED_FD);

    header = CMSG_FIRSTHDR(&message);
    if (test->expected_count == 0) {
        if (header != NULL) {
            fail("%s unexpectedly returned a cmsghdr", test->name);
        }
    } else {
        int received[RIGHTS_COUNT] = {-1, -1, -1};

        if (header == NULL) {
            fail("%s did not return a cmsghdr", test->name);
        }
        expect_long("SCM_RIGHTS cmsg_level", header->cmsg_level, SOL_SOCKET);
        expect_long("SCM_RIGHTS cmsg_type", header->cmsg_type, SCM_RIGHTS);
        expect_long("SCM_RIGHTS cmsg_len",
                    (long)header->cmsg_len,
                    (long)CMSG_LEN(test->expected_count * sizeof(int)));
        memcpy(received,
               CMSG_DATA(header),
               test->expected_count * sizeof(int));
        for (index = 0; index < test->expected_count; index++) {
            expect_long("SCM_RIGHTS received descriptor",
                        received[index],
                        FIRST_RECEIVED_FD + (int)index);
        }
        if (CMSG_NXTHDR(&message, header) != NULL) {
            fail("%s returned an unexpected second cmsghdr", test->name);
        }
    }

    for (index = 0; index < RIGHTS_COUNT; index++) {
        int descriptor = FIRST_RECEIVED_FD + (int)index;

        if (index < test->expected_count) {
            expect_descriptor_open(descriptor, 1);
        } else {
            expect_descriptor_closed(descriptor);
        }
    }
    expect_queue_empty(sockets[1], "SCM_RIGHTS message consumed");

    for (index = 0; index < test->expected_count; index++) {
        close_checked(FIRST_RECEIVED_FD + (int)index);
    }
    expect_no_descriptors_from(FIRST_RECEIVED_FD);
    close_socket_pair_and_verify(sockets);
}

static struct fault_region allocate_fault_region(void)
{
    struct fault_region region;
    long configured_page_size = sysconf(_SC_PAGESIZE);
    size_t page_size;

    if (configured_page_size <= 0) {
        fail("sysconf(_SC_PAGESIZE) returned %ld", configured_page_size);
    }
    page_size = (size_t)configured_page_size;
    if (page_size > SIZE_MAX / 2) {
        fail("page size is too large");
    }

    region.mapping_size = page_size * 2;
    region.mapping = mmap(NULL,
                          region.mapping_size,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1,
                          0);
    if (region.mapping == MAP_FAILED) {
        fail("mmap fault region errno=%d", errno);
    }
    memset(region.mapping, CONTROL_PATTERN, region.mapping_size);
    region.fault_page = (unsigned char *)region.mapping + page_size;
    region.data_fault_control =
        (unsigned char *)region.fault_page - CMSG_ALIGN(sizeof(struct cmsghdr));
    if (mprotect(region.fault_page, page_size, PROT_NONE) != 0) {
        fail("mprotect fault page errno=%d", errno);
    }
    return region;
}

static void free_fault_region(struct fault_region *region)
{
    if (munmap(region->mapping, region->mapping_size) != 0) {
        fail("munmap fault region errno=%d", errno);
    }
}

static void enable_ancillary_option(
    int receiver,
    const struct ancillary_description *ancillary)
{
    int enabled = 1;

    if (setsockopt(receiver,
                   SOL_SOCKET,
                   ancillary->socket_option,
                   &enabled,
                   sizeof(enabled)) != 0) {
        fail("setsockopt(%s) errno=%d", ancillary->name, errno);
    }
}

static void send_metadata_payload(int sender, unsigned char payload)
{
    ssize_t result;
    int saved_errno;

    errno = 0;
    result = send(sender, &payload, sizeof(payload), 0);
    saved_errno = errno;
    expect_errno_result("send metadata payload", result, saved_errno, 1, 0);
}

static void validate_metadata_header(
    const struct cmsghdr *header,
    const struct ancillary_description *ancillary)
{
    expect_long("metadata cmsg_level", header->cmsg_level, SOL_SOCKET);
    expect_long("metadata cmsg_type",
                header->cmsg_type,
                ancillary->control_type);
    expect_long("metadata cmsg_len",
                (long)header->cmsg_len,
                (long)CMSG_LEN(ancillary->data_size));
}

static void test_ancillary_fault(const void *argument)
{
    const struct ancillary_fault_case *test = argument;
    const struct ancillary_description *ancillary = test->ancillary;
    struct fault_region region;
    int sockets[2];
    struct iovec vector;
    struct msghdr message;
    unsigned char payload = 0;
    void *control;
    ssize_t result;
    int saved_errno;

    prepare_isolated_descriptor_table();
    create_exact_socket_pair(sockets);
    enable_ancillary_option(sockets[1], ancillary);
    send_metadata_payload(sockets[0], 'F');
    region = allocate_fault_region();
    control = test->layout == FAULT_WHOLE_CONTROL
                  ? region.fault_page
                  : region.data_fault_control;

    memset(&message, 0, sizeof(message));
    vector.iov_base = &payload;
    vector.iov_len = sizeof(payload);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = CMSG_SPACE(ancillary->data_size);

    errno = 0;
    result = recvmsg(sockets[1], &message, 0);
    saved_errno = errno;

    dprintf(STDOUT_FILENO,
            "OBS name=%s result=%zd errno=%d flags=0x%x controllen=%zu "
            "payload=0x%02x\n",
            test->name,
            result,
            saved_errno,
            message.msg_flags,
            (size_t)message.msg_controllen,
            payload);

    expect_errno_result(test->name, result, saved_errno, 1, 0);
    expect_long("faulted ancillary msg_flags", message.msg_flags, 0);
    expect_long("faulted ancillary msg_controllen",
                (long)message.msg_controllen,
                0);
    expect_long("faulted ancillary payload", payload, 'F');
    if (test->layout == FAULT_CMSG_DATA) {
        validate_metadata_header(control, ancillary);
    }
    expect_queue_empty(sockets[1], "faulted ancillary message consumed");

    free_fault_region(&region);
    close_socket_pair_and_verify(sockets);
}

static void test_ancillary_partial(const void *argument)
{
    const struct ancillary_partial_case *test = argument;
    const struct ancillary_description *ancillary = test->ancillary;
    int sockets[2];
    union metadata_control control;
    struct cmsghdr *header;
    struct iovec vector;
    struct msghdr message;
    struct timespec before;
    struct timespec after;
    unsigned char payload = 0;
    ssize_t result;
    int saved_errno;
    size_t index;

    prepare_isolated_descriptor_table();
    create_exact_socket_pair(sockets);
    enable_ancillary_option(sockets[1], ancillary);
    if (clock_gettime(CLOCK_REALTIME, &before) != 0) {
        fail("clock_gettime before send errno=%d", errno);
    }
    send_metadata_payload(sockets[0], 'P');

    memset(&control, CONTROL_PATTERN, sizeof(control));
    memset(&message, 0, sizeof(message));
    vector.iov_base = &payload;
    vector.iov_len = sizeof(payload);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = test->capacity;

    errno = 0;
    result = recvmsg(sockets[1], &message, 0);
    saved_errno = errno;
    if (clock_gettime(CLOCK_REALTIME, &after) != 0) {
        fail("clock_gettime after receive errno=%d", errno);
    }

    dprintf(STDOUT_FILENO,
            "OBS name=%s result=%zd errno=%d flags=0x%x controllen=%zu "
            "copied_data=%zu\n",
            test->name,
            result,
            saved_errno,
            message.msg_flags,
            (size_t)message.msg_controllen,
            test->copied_data);

    expect_errno_result(test->name, result, saved_errno, 1, 0);
    expect_long("partial ancillary msg_flags",
                message.msg_flags,
                MSG_CTRUNC);
    expect_long("partial ancillary msg_controllen",
                (long)message.msg_controllen,
                (long)test->capacity);
    expect_long("partial ancillary payload", payload, 'P');

    header = CMSG_FIRSTHDR(&message);
    if (header == NULL) {
        fail("%s did not return a partial cmsghdr", test->name);
    }
    expect_long("partial metadata cmsg_level",
                header->cmsg_level,
                SOL_SOCKET);
    expect_long("partial metadata cmsg_type",
                header->cmsg_type,
                ancillary->control_type);
    expect_long("partial metadata cmsg_len",
                (long)header->cmsg_len,
                (long)test->capacity);

    for (index = test->capacity; index < sizeof(control.bytes); index++) {
        if (control.bytes[index] != CONTROL_PATTERN) {
            fail("%s wrote beyond capacity at offset=%zu value=0x%02x",
                 test->name,
                 index,
                 control.bytes[index]);
        }
    }

    if (ancillary->kind == ANCILLARY_CREDENTIALS &&
        test->copied_data >= sizeof(pid_t)) {
        pid_t observed_pid;

        memcpy(&observed_pid, CMSG_DATA(header), sizeof(observed_pid));
        expect_long("partial credentials pid", observed_pid, getpid());
    }
    if (ancillary->kind == ANCILLARY_TIMESTAMPNS &&
        test->copied_data >= sizeof(time_t)) {
        time_t observed_seconds;

        memcpy(&observed_seconds, CMSG_DATA(header), sizeof(observed_seconds));
        if (observed_seconds < before.tv_sec ||
            observed_seconds > after.tv_sec) {
            fail("partial timestamp seconds=%lld outside [%lld,%lld]",
                 (long long)observed_seconds,
                 (long long)before.tv_sec,
                 (long long)after.tv_sec);
        }
    }

    expect_queue_empty(sockets[1], "partial ancillary message consumed");
    close_socket_pair_and_verify(sockets);
}

static int run_isolated(const char *name,
                        isolated_test_fn function,
                        const void *argument)
{
    pid_t child;
    int status;
    pid_t waited;

    dprintf(STDOUT_FILENO, "CASE name=%s state=begin\n", name);
    child = fork();
    if (child < 0) {
        dprintf(STDERR_FILENO, "fork errno=%d\n", errno);
        return 1;
    }
    if (child == 0) {
        function(argument);
        dprintf(STDOUT_FILENO, "CASE name=%s state=pass\n", name);
        _exit(EXIT_SUCCESS);
    }

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        dprintf(STDERR_FILENO, "waitpid errno=%d\n", errno);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
        dprintf(STDERR_FILENO,
                "CASE name=%s state=fail wait_status=%d\n",
                name,
                status);
        return 1;
    }
    return 0;
}

int main(void)
{
    static const struct rights_capacity_case rights_cases[] = {
        {
            "rights_header_only",
            sizeof(struct cmsghdr),
            0,
            0,
            1,
        },
        {
            "rights_header_plus_one_fd",
            CMSG_LEN(sizeof(int)),
            1,
            CMSG_LEN(sizeof(int)),
            1,
        },
        {
            "rights_header_plus_two_fds",
            CMSG_LEN(2 * sizeof(int)),
            2,
            CMSG_LEN(2 * sizeof(int)),
            1,
        },
        {
            "rights_full",
            CMSG_SPACE(RIGHTS_COUNT * sizeof(int)),
            3,
            CMSG_SPACE(RIGHTS_COUNT * sizeof(int)),
            0,
        },
    };
    static const struct ancillary_fault_case fault_cases[] = {
        {
            "credentials_whole_control_fault",
            &credentials_description,
            FAULT_WHOLE_CONTROL,
        },
        {
            "credentials_data_fault",
            &credentials_description,
            FAULT_CMSG_DATA,
        },
        {
            "timestampns_whole_control_fault",
            &timestamp_description,
            FAULT_WHOLE_CONTROL,
        },
        {
            "timestampns_data_fault",
            &timestamp_description,
            FAULT_CMSG_DATA,
        },
    };
    static const struct ancillary_partial_case partial_cases[] = {
        {
            "credentials_header_only",
            &credentials_description,
            sizeof(struct cmsghdr),
            0,
        },
        {
            "credentials_header_plus_pid",
            &credentials_description,
            CMSG_LEN(sizeof(pid_t)),
            sizeof(pid_t),
        },
        {
            "timestampns_header_only",
            &timestamp_description,
            sizeof(struct cmsghdr),
            0,
        },
        {
            "timestampns_header_plus_seconds",
            &timestamp_description,
            CMSG_LEN(sizeof(time_t)),
            sizeof(time_t),
        },
    };
    size_t index;
    unsigned int passed = 0;

    for (index = 0;
         index < sizeof(rights_cases) / sizeof(rights_cases[0]);
         index++) {
        if (run_isolated(rights_cases[index].name,
                         test_rights_capacity,
                         &rights_cases[index]) != 0) {
            return EXIT_FAILURE;
        }
        passed++;
    }
    for (index = 0;
         index < sizeof(fault_cases) / sizeof(fault_cases[0]);
         index++) {
        if (run_isolated(fault_cases[index].name,
                         test_ancillary_fault,
                         &fault_cases[index]) != 0) {
            return EXIT_FAILURE;
        }
        passed++;
    }
    for (index = 0;
         index < sizeof(partial_cases) / sizeof(partial_cases[0]);
         index++) {
        if (run_isolated(partial_cases[index].name,
                         test_ancillary_partial,
                         &partial_cases[index]) != 0) {
            return EXIT_FAILURE;
        }
        passed++;
    }

    dprintf(STDOUT_FILENO,
            "SOCKET_ANCILLARY_RECEIVE_ABI_PROBE_PASS cases=%u\n",
            passed);
    return EXIT_SUCCESS;
}
