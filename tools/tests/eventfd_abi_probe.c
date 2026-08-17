/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux eventfd counter, readiness, lifetime, and blocking ABI probe.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>

static int g_failures;
static atomic_int g_reader_started;
static atomic_int g_reader_done;
static atomic_int g_writer_started;
static atomic_int g_writer_done;
static int g_blocking_read_fd;
static int g_blocking_write_fd;
static ssize_t g_reader_result;
static ssize_t g_writer_result;
static int g_reader_errno;
static int g_writer_errno;
static uint64_t g_reader_value;

static void fail(const char *name) {
    dprintf(STDOUT_FILENO, "%s:FAIL errno:%d\n", name, errno);
    ++g_failures;
}

static void expect_errno(const char *name, long result, int expected) {
    int saved_errno = errno;
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != -1 || saved_errno != expected) ++g_failures;
}

static int expect_poll(const char *name, int descriptor, short expected,
                       short forbidden) {
    struct pollfd poll_descriptor;
    int result;
    memset(&poll_descriptor, 0, sizeof(poll_descriptor));
    poll_descriptor.fd = descriptor;
    poll_descriptor.events = POLLIN | POLLOUT;
    errno = 0;
    result = poll(&poll_descriptor, 1, 0);
    dprintf(STDOUT_FILENO, "%s_rc:%d errno:%d revents:0x%x\n",
            name, result, errno, (unsigned)poll_descriptor.revents);
    if (result != 1 ||
        (poll_descriptor.revents & expected) != expected ||
        (poll_descriptor.revents & forbidden) != 0) {
        ++g_failures;
        return -1;
    }
    return 0;
}

static void *blocking_reader(void *unused) {
    (void)unused;
    atomic_store_explicit(&g_reader_started, 1, memory_order_release);
    errno = 0;
    g_reader_result = read(g_blocking_read_fd, &g_reader_value,
                           sizeof(g_reader_value));
    g_reader_errno = errno;
    atomic_store_explicit(&g_reader_done, 1, memory_order_release);
    return 0;
}

static void *blocking_writer(void *unused) {
    uint64_t value = 1;
    (void)unused;
    atomic_store_explicit(&g_writer_started, 1, memory_order_release);
    errno = 0;
    g_writer_result = write(g_blocking_write_fd, &value, sizeof(value));
    g_writer_errno = errno;
    atomic_store_explicit(&g_writer_done, 1, memory_order_release);
    return 0;
}

static void wait_for_start(atomic_int *started) {
    for (int attempt = 0; attempt < 1000; ++attempt) {
        if (atomic_load_explicit(started, memory_order_acquire)) return;
        sched_yield();
    }
}

static void test_flags_and_errors(void) {
    uint64_t values[2] = {UINT64_C(0x1122334455667788),
                          UINT64_C(0xa5a5a5a5a5a5a5a5)};
    int descriptor;
    int flags;
    ssize_t result;

    errno = 0;
    descriptor = eventfd(0, 2);
    expect_errno("bad_flags", descriptor, EINVAL);

    descriptor = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (descriptor < 0) {
        fail("create_flags");
        return;
    }
    flags = fcntl(descriptor, F_GETFD);
    dprintf(STDOUT_FILENO, "descriptor_flags:0x%x\n", flags);
    if (flags != FD_CLOEXEC) ++g_failures;
    flags = fcntl(descriptor, F_GETFL);
    dprintf(STDOUT_FILENO, "status_flags:0x%x\n", flags);
    if (flags < 0 || (flags & (O_ACCMODE | O_NONBLOCK)) !=
                     (O_RDWR | O_NONBLOCK))
        ++g_failures;

    errno = 0;
    result = read(descriptor, values, sizeof(uint64_t));
    expect_errno("empty_nonblock_read", result, EAGAIN);
    errno = 0;
    result = read(descriptor, values, sizeof(uint32_t));
    expect_errno("short_read", result, EINVAL);
    errno = 0;
    result = write(descriptor, values, sizeof(uint32_t));
    expect_errno("short_write", result, EINVAL);
    values[0] = UINT64_MAX;
    errno = 0;
    result = write(descriptor, values, sizeof(uint64_t));
    expect_errno("invalid_write_value", result, EINVAL);
    close(descriptor);
}

static void test_counter_and_readiness(void) {
    uint64_t values[2] = {5, UINT64_C(0xfeedfacefeedface)};
    int descriptor = eventfd(0, EFD_NONBLOCK);
    ssize_t result;
    if (descriptor < 0) {
        fail("counter_create");
        return;
    }
    expect_poll("empty_poll", descriptor, POLLOUT, POLLIN);
    errno = 0;
    result = write(descriptor, values, sizeof(values));
    expect_errno("wide_write", result, EINVAL);
    result = write(descriptor, values, sizeof(uint64_t));
    if (result != (ssize_t)sizeof(uint64_t)) ++g_failures;
    expect_poll("ready_poll", descriptor, POLLIN | POLLOUT, 0);
    values[0] = 0;
    result = read(descriptor, values, sizeof(values));
    dprintf(STDOUT_FILENO, "wide_read_rc:%ld value:%llu tail:%llx\n",
            (long)result, (unsigned long long)values[0],
            (unsigned long long)values[1]);
    if (result != (ssize_t)sizeof(uint64_t) || values[0] != 5 ||
        values[1] != UINT64_C(0xfeedfacefeedface))
        ++g_failures;
    expect_poll("drained_poll", descriptor, POLLOUT, POLLIN);
    close(descriptor);
}

static void test_semaphore_and_duplicate(void) {
    uint64_t value = 0;
    int descriptor = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    int duplicate;
    if (descriptor < 0) {
        fail("semaphore_create");
        return;
    }
    if (read(descriptor, &value, sizeof(value)) != (ssize_t)sizeof(value) ||
        value != 1)
        ++g_failures;
    value = 0;
    if (read(descriptor, &value, sizeof(value)) != (ssize_t)sizeof(value) ||
        value != 1)
        ++g_failures;
    errno = 0;
    expect_errno("semaphore_empty", read(descriptor, &value, sizeof(value)),
                 EAGAIN);
    close(descriptor);

    descriptor = eventfd(7, 0);
    duplicate = descriptor >= 0 ? dup(descriptor) : -1;
    if (descriptor < 0 || duplicate < 0) {
        fail("duplicate_create");
        if (descriptor >= 0) close(descriptor);
        return;
    }
    close(descriptor);
    value = 0;
    if (read(duplicate, &value, sizeof(value)) != (ssize_t)sizeof(value) ||
        value != 7)
        ++g_failures;
    dprintf(STDOUT_FILENO, "duplicate_value:%llu\n",
            (unsigned long long)value);
    close(duplicate);
}

static void test_fault_consumes_counter(void) {
    uint64_t value = 0;
    int descriptor = eventfd(9, EFD_NONBLOCK);
    long result;
    if (descriptor < 0) {
        fail("fault_create");
        return;
    }
    errno = 0;
    result = syscall(SYS_read, descriptor, (void *)(uintptr_t)1,
                     sizeof(value));
    expect_errno("fault_read", result, EFAULT);
    errno = 0;
    expect_errno("fault_consumed_read",
                 read(descriptor, &value, sizeof(value)), EAGAIN);
    dprintf(STDOUT_FILENO, "fault_consumed_value:%llu\n",
            (unsigned long long)value);
    close(descriptor);
}

static void test_overflow(void) {
    uint64_t value = UINT64_MAX - 1u;
    int descriptor = eventfd(0, EFD_NONBLOCK);
    ssize_t result;
    if (descriptor < 0) {
        fail("overflow_create");
        return;
    }
    if (write(descriptor, &value, sizeof(value)) != (ssize_t)sizeof(value))
        ++g_failures;
    expect_poll("full_poll", descriptor, POLLIN, POLLOUT);
    value = 1;
    errno = 0;
    result = write(descriptor, &value, sizeof(value));
    expect_errno("overflow_nonblock", result, EAGAIN);
    value = 0;
    if (read(descriptor, &value, sizeof(value)) != (ssize_t)sizeof(value) ||
        value != UINT64_MAX - 1u)
        ++g_failures;
    close(descriptor);
}

static void test_blocking_read(void) {
    pthread_t thread;
    uint64_t value = 11;
    g_blocking_read_fd = eventfd(0, 0);
    g_reader_result = -2;
    g_reader_errno = 0;
    g_reader_value = 0;
    atomic_store(&g_reader_started, 0);
    atomic_store(&g_reader_done, 0);
    if (g_blocking_read_fd < 0 ||
        pthread_create(&thread, 0, blocking_reader, 0) != 0) {
        fail("blocking_reader_create");
        if (g_blocking_read_fd >= 0) close(g_blocking_read_fd);
        return;
    }
    wait_for_start(&g_reader_started);
    usleep(20000);
    if (atomic_load_explicit(&g_reader_done, memory_order_acquire))
        ++g_failures;
    if (write(g_blocking_read_fd, &value, sizeof(value)) !=
        (ssize_t)sizeof(value))
        ++g_failures;
    if (pthread_join(thread, 0) != 0) ++g_failures;
    dprintf(STDOUT_FILENO,
            "blocking_read_rc:%ld errno:%d value:%llu\n",
            (long)g_reader_result, g_reader_errno,
            (unsigned long long)g_reader_value);
    if (g_reader_result != (ssize_t)sizeof(uint64_t) ||
        g_reader_errno != 0 || g_reader_value != 11)
        ++g_failures;
    close(g_blocking_read_fd);
}

static void test_blocking_write(void) {
    pthread_t thread;
    uint64_t value = UINT64_MAX - 1u;
    g_blocking_write_fd = eventfd(0, 0);
    g_writer_result = -2;
    g_writer_errno = 0;
    atomic_store(&g_writer_started, 0);
    atomic_store(&g_writer_done, 0);
    if (g_blocking_write_fd < 0 ||
        write(g_blocking_write_fd, &value, sizeof(value)) !=
            (ssize_t)sizeof(value) ||
        pthread_create(&thread, 0, blocking_writer, 0) != 0) {
        fail("blocking_writer_create");
        if (g_blocking_write_fd >= 0) close(g_blocking_write_fd);
        return;
    }
    wait_for_start(&g_writer_started);
    usleep(20000);
    if (atomic_load_explicit(&g_writer_done, memory_order_acquire))
        ++g_failures;
    value = 0;
    if (read(g_blocking_write_fd, &value, sizeof(value)) !=
            (ssize_t)sizeof(value) ||
        value != UINT64_MAX - 1u)
        ++g_failures;
    if (pthread_join(thread, 0) != 0) ++g_failures;
    dprintf(STDOUT_FILENO, "blocking_write_rc:%ld errno:%d\n",
            (long)g_writer_result, g_writer_errno);
    if (g_writer_result != (ssize_t)sizeof(uint64_t) ||
        g_writer_errno != 0)
        ++g_failures;
    value = 0;
    if (read(g_blocking_write_fd, &value, sizeof(value)) !=
            (ssize_t)sizeof(value) ||
        value != 1)
        ++g_failures;
    dprintf(STDOUT_FILENO, "blocking_write_value:%llu\n",
            (unsigned long long)value);
    close(g_blocking_write_fd);
}

static void test_legacy_x86_entry(void) {
#if defined(__x86_64__) && defined(SYS_eventfd)
    uint64_t value = 0;
    int descriptor;
    errno = 0;
    descriptor = (int)syscall(SYS_eventfd, 3u);
    dprintf(STDOUT_FILENO, "legacy_eventfd_rc:%d errno:%d\n",
            descriptor, errno);
    if (descriptor < 0 ||
        read(descriptor, &value, sizeof(value)) != (ssize_t)sizeof(value) ||
        value != 3)
        ++g_failures;
    if (descriptor >= 0) close(descriptor);
#else
    dprintf(STDOUT_FILENO, "legacy_eventfd:ARCH_NOT_DEFINED\n");
#endif
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    test_flags_and_errors();
    test_counter_and_readiness();
    test_semaphore_and_duplicate();
    test_fault_consumes_counter();
    test_overflow();
    test_blocking_read();
    test_blocking_write();
    test_legacy_x86_entry();
    dprintf(STDOUT_FILENO, "eventfd_abi:%s failures:%d\n",
            g_failures ? "FAIL" : "OK", g_failures);
    return g_failures ? 1 : 0;
}
