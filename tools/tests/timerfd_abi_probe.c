/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux timerfd clock, expiration, readiness, lifetime, and blocking probe.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static int g_failures;
static int g_blocking_fd;
static atomic_int g_reader_started;
static atomic_int g_reader_done;
static ssize_t g_reader_result;
static int g_reader_errno;
static uint64_t g_reader_expirations;

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

static uint64_t timespec_to_ns(const struct timespec *value) {
    return (uint64_t)value->tv_sec * UINT64_C(1000000000) +
           (uint64_t)value->tv_nsec;
}

static int arm_timer(int descriptor, int flags, int64_t first_ns,
                     int64_t interval_ns, struct itimerspec *old_value) {
    struct itimerspec value;
    memset(&value, 0, sizeof(value));
    value.it_value.tv_sec = first_ns / 1000000000;
    value.it_value.tv_nsec = first_ns % 1000000000;
    value.it_interval.tv_sec = interval_ns / 1000000000;
    value.it_interval.tv_nsec = interval_ns % 1000000000;
    return timerfd_settime(descriptor, flags, &value, old_value);
}

static void test_create_and_flags(void) {
    static const int clocks[] = {
        CLOCK_REALTIME,
        CLOCK_MONOTONIC,
#ifdef CLOCK_BOOTTIME
        CLOCK_BOOTTIME,
#endif
#ifdef CLOCK_REALTIME_ALARM
        CLOCK_REALTIME_ALARM,
#endif
#ifdef CLOCK_BOOTTIME_ALARM
        CLOCK_BOOTTIME_ALARM,
#endif
    };
    int descriptor;
    int flags;

    errno = 0;
    expect_errno("bad_clock", timerfd_create(12345, 0), EINVAL);
    errno = 0;
    expect_errno("bad_create_flags", timerfd_create(CLOCK_MONOTONIC, 2),
                 EINVAL);

    for (size_t index = 0; index < sizeof(clocks) / sizeof(clocks[0]);
         ++index) {
        errno = 0;
        descriptor = timerfd_create(clocks[index], TFD_NONBLOCK);
        dprintf(STDOUT_FILENO, "clock_%d_rc:%d errno:%d\n", clocks[index],
                descriptor, errno);
        if (descriptor < 0) {
            if ((clocks[index] == CLOCK_REALTIME_ALARM ||
                 clocks[index] == CLOCK_BOOTTIME_ALARM) && errno == EPERM)
                continue;
            ++g_failures;
            continue;
        }
        close(descriptor);
    }

    descriptor = timerfd_create(CLOCK_MONOTONIC,
                                TFD_NONBLOCK | TFD_CLOEXEC);
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
    close(descriptor);
}

static void test_validation(void) {
    struct itimerspec value;
    int descriptor = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (descriptor < 0) {
        fail("validation_create");
        return;
    }
    memset(&value, 0, sizeof(value));
    value.it_value.tv_nsec = 1;

    errno = 0;
    expect_errno("bad_set_flags",
                 timerfd_settime(descriptor, 0x4000, &value, 0), EINVAL);
    value.it_value.tv_nsec = 1000000000L;
    errno = 0;
    expect_errno("bad_value_nsec",
                 timerfd_settime(descriptor, 0, &value, 0), EINVAL);
    value.it_value.tv_nsec = 1;
    value.it_interval.tv_sec = -1;
    errno = 0;
    expect_errno("bad_interval_sec",
                 timerfd_settime(descriptor, 0, &value, 0), EINVAL);
    value.it_interval.tv_sec = 0;

    errno = 0;
    expect_errno("null_set_value",
                 timerfd_settime(descriptor, 0, 0, 0), EFAULT);
    errno = 0;
    expect_errno("null_get_value", timerfd_gettime(descriptor, 0), EFAULT);

    errno = 0;
    long invalid_fd_null_set = timerfd_settime(-1, 0, 0, 0);
    dprintf(STDOUT_FILENO, "invalid_fd_null_set_rc:%ld errno:%d\n",
            invalid_fd_null_set, errno);
    if (invalid_fd_null_set != -1 || errno != EFAULT) ++g_failures;
    errno = 0;
    long invalid_fd_null_get = timerfd_gettime(-1, 0);
    dprintf(STDOUT_FILENO, "invalid_fd_null_get_rc:%ld errno:%d\n",
            invalid_fd_null_get, errno);
    if (invalid_fd_null_get != -1 || errno != EBADF) ++g_failures;
    errno = 0;
    long wrong_type_set = timerfd_settime(STDIN_FILENO, 0, &value, 0);
    dprintf(STDOUT_FILENO, "wrong_type_set_rc:%ld errno:%d\n",
            wrong_type_set, errno);
    if (wrong_type_set != -1 || errno != EINVAL) ++g_failures;
    errno = 0;
    long wrong_type_get = timerfd_gettime(STDIN_FILENO, &value);
    dprintf(STDOUT_FILENO, "wrong_type_get_rc:%ld errno:%d\n",
            wrong_type_get, errno);
    if (wrong_type_get != -1 || errno != EINVAL) ++g_failures;

    errno = 0;
    long cancel_without_absolute = timerfd_settime(
        descriptor, TFD_TIMER_CANCEL_ON_SET, &value, 0);
    dprintf(STDOUT_FILENO,
            "cancel_monotonic_relative_rc:%ld errno:%d\n",
            cancel_without_absolute, errno);
    if (cancel_without_absolute != 0) ++g_failures;
    errno = 0;
    long cancel_absolute = timerfd_settime(
        descriptor, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &value, 0);
    dprintf(STDOUT_FILENO,
            "cancel_monotonic_absolute_rc:%ld errno:%d\n",
            cancel_absolute, errno);
    if (cancel_absolute != 0) ++g_failures;
    close(descriptor);
}

static void test_nonblocking_and_wide_read(void) {
    uint64_t values[2] = {0, UINT64_C(0xfeedfacefeedface)};
    struct pollfd poll_descriptor;
    int descriptor = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    ssize_t result;
    if (descriptor < 0) {
        fail("nonblock_create");
        return;
    }
    errno = 0;
    expect_errno("disarmed_read",
                 read(descriptor, values, sizeof(values[0])), EAGAIN);
    errno = 0;
    expect_errno("short_read", read(descriptor, values, 4), EINVAL);
    errno = 0;
    expect_errno("timerfd_write", write(descriptor, values, 8), EINVAL);

    if (arm_timer(descriptor, 0, 1000000, 0, 0) < 0) {
        fail("wide_arm");
        close(descriptor);
        return;
    }
    memset(&poll_descriptor, 0, sizeof(poll_descriptor));
    poll_descriptor.fd = descriptor;
    poll_descriptor.events = POLLIN | POLLOUT;
    result = poll(&poll_descriptor, 1, 1000);
    dprintf(STDOUT_FILENO, "oneshot_poll_rc:%ld revents:0x%x\n",
            (long)result, (unsigned)poll_descriptor.revents);
    if (result != 1 || !(poll_descriptor.revents & POLLIN) ||
        (poll_descriptor.revents & POLLOUT))
        ++g_failures;
    result = read(descriptor, values, sizeof(values));
    dprintf(STDOUT_FILENO,
            "wide_read_rc:%ld expirations:%llu tail:%llx\n",
            (long)result, (unsigned long long)values[0],
            (unsigned long long)values[1]);
    if (result != 8 || values[0] != 1 ||
        values[1] != UINT64_C(0xfeedfacefeedface))
        ++g_failures;
    close(descriptor);
}

static void test_periodic_and_gettime(void) {
    struct itimerspec current;
    struct itimerspec old_value;
    uint64_t expirations = 0;
    int descriptor = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (descriptor < 0) {
        fail("periodic_create");
        return;
    }
    memset(&current, 0, sizeof(current));
    if (timerfd_gettime(descriptor, &current) < 0) {
        fail("disarmed_gettime");
    } else {
        dprintf(STDOUT_FILENO,
                "disarmed_gettime_value_ns:%llu interval_ns:%llu\n",
                (unsigned long long)timespec_to_ns(&current.it_value),
                (unsigned long long)timespec_to_ns(&current.it_interval));
        if (timespec_to_ns(&current.it_value) != 0 ||
            timespec_to_ns(&current.it_interval) != 0)
            ++g_failures;
    }
    if (arm_timer(descriptor, 0, 10000000, 10000000, 0) < 0) {
        fail("periodic_arm");
        close(descriptor);
        return;
    }
    usleep(65000);
    if (read(descriptor, &expirations, sizeof(expirations)) != 8) {
        fail("periodic_read");
    }
    dprintf(STDOUT_FILENO, "periodic_expirations:%llu\n",
            (unsigned long long)expirations);
    if (expirations < 5) ++g_failures;

    memset(&old_value, 0, sizeof(old_value));
    if (arm_timer(descriptor, 0, 200000000, 0, &old_value) < 0) {
        fail("replace_timer");
    } else {
        uint64_t old_interval = timespec_to_ns(&old_value.it_interval);
        dprintf(STDOUT_FILENO,
                "replace_old_value_ns:%llu interval_ns:%llu\n",
                (unsigned long long)timespec_to_ns(&old_value.it_value),
                (unsigned long long)old_interval);
        if (old_interval != 10000000) ++g_failures;
    }
    if (timerfd_gettime(descriptor, &current) < 0) {
        fail("armed_gettime");
    } else {
        uint64_t remaining = timespec_to_ns(&current.it_value);
        dprintf(STDOUT_FILENO, "armed_remaining_ns:%llu\n",
                (unsigned long long)remaining);
        if (!remaining || remaining > 200000000) ++g_failures;
    }
    if (arm_timer(descriptor, 0, 0, 0, 0) < 0) fail("disarm");
    errno = 0;
    expect_errno("disarmed_pending_read",
                 read(descriptor, &expirations, sizeof(expirations)), EAGAIN);
    close(descriptor);
}

static void test_absolute_past(void) {
    struct timespec now;
    struct itimerspec value;
    uint64_t expirations = 0;
    int descriptor = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (descriptor < 0 || clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        fail("absolute_create");
        if (descriptor >= 0) close(descriptor);
        return;
    }
    memset(&value, 0, sizeof(value));
    value.it_value = now;
    value.it_value.tv_sec -= 1;
    value.it_interval.tv_nsec = 10000000;
    if (timerfd_settime(descriptor, TFD_TIMER_ABSTIME, &value, 0) < 0 ||
        read(descriptor, &expirations, sizeof(expirations)) != 8) {
        fail("absolute_past_read");
    }
    dprintf(STDOUT_FILENO, "absolute_past_expirations:%llu\n",
            (unsigned long long)expirations);
    if (expirations < 100) ++g_failures;
    close(descriptor);
}

static void test_far_future_cancel_on_set(void) {
    struct itimerspec value;
    struct itimerspec current;
    int descriptor = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    int result;

    if (descriptor < 0) {
        fail("far_future_create");
        return;
    }
    memset(&value, 0, sizeof(value));
    value.it_value.tv_sec = INT64_MAX;
    errno = 0;
    result = timerfd_settime(
        descriptor, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
        &value, 0);
    dprintf(STDOUT_FILENO, "far_future_set_rc:%d errno:%d\n",
            result, errno);
    if (result != 0 || timerfd_gettime(descriptor, &current) < 0 ||
        current.it_value.tv_sec <= 0)
        ++g_failures;
    close(descriptor);
}

static void test_fault_consumption(void) {
    uint64_t expirations = 0;
    int descriptor = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    long result;
    if (descriptor < 0 || arm_timer(descriptor, 0, 1000000, 0, 0) < 0) {
        fail("fault_create");
        if (descriptor >= 0) close(descriptor);
        return;
    }
    usleep(5000);
    errno = 0;
    result = syscall(SYS_read, descriptor, (void *)(uintptr_t)1,
                     sizeof(expirations));
    expect_errno("fault_read", result, EFAULT);
    errno = 0;
    result = read(descriptor, &expirations, sizeof(expirations));
    dprintf(STDOUT_FILENO,
            "fault_followup_rc:%ld errno:%d expirations:%llu\n",
            result, errno, (unsigned long long)expirations);
    if (result != -1 || errno != EAGAIN || expirations != 0)
        ++g_failures;
    close(descriptor);
}

static void test_duplicate_lifetime(void) {
    uint64_t expirations = 0;
    int descriptor = timerfd_create(CLOCK_MONOTONIC, 0);
    int duplicate = descriptor >= 0 ? dup(descriptor) : -1;
    if (descriptor < 0 || duplicate < 0 ||
        arm_timer(descriptor, 0, 1000000, 0, 0) < 0) {
        fail("duplicate_create");
        if (descriptor >= 0) close(descriptor);
        if (duplicate >= 0) close(duplicate);
        return;
    }
    close(descriptor);
    if (read(duplicate, &expirations, sizeof(expirations)) != 8 ||
        expirations != 1)
        fail("duplicate_read");
    dprintf(STDOUT_FILENO, "duplicate_expirations:%llu\n",
            (unsigned long long)expirations);
    close(duplicate);
}

static void *blocking_reader(void *unused) {
    (void)unused;
    atomic_store_explicit(&g_reader_started, 1, memory_order_release);
    errno = 0;
    g_reader_result = read(g_blocking_fd, &g_reader_expirations,
                           sizeof(g_reader_expirations));
    g_reader_errno = errno;
    atomic_store_explicit(&g_reader_done, 1, memory_order_release);
    return 0;
}

static void test_blocking_read(void) {
    pthread_t thread;
    g_blocking_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    g_reader_result = -2;
    g_reader_errno = 0;
    g_reader_expirations = 0;
    atomic_store(&g_reader_started, 0);
    atomic_store(&g_reader_done, 0);
    if (g_blocking_fd < 0 ||
        pthread_create(&thread, 0, blocking_reader, 0) != 0) {
        fail("blocking_create");
        if (g_blocking_fd >= 0) close(g_blocking_fd);
        return;
    }
    while (!atomic_load_explicit(&g_reader_started, memory_order_acquire))
        sched_yield();
    usleep(10000);
    if (atomic_load_explicit(&g_reader_done, memory_order_acquire))
        ++g_failures;
    if (arm_timer(g_blocking_fd, 0, 20000000, 0, 0) < 0)
        fail("blocking_arm");
    if (pthread_join(thread, 0) != 0) ++g_failures;
    dprintf(STDOUT_FILENO,
            "blocking_read_rc:%ld errno:%d expirations:%llu\n",
            (long)g_reader_result, g_reader_errno,
            (unsigned long long)g_reader_expirations);
    if (g_reader_result != 8 || g_reader_errno != 0 ||
        g_reader_expirations != 1)
        ++g_failures;
    close(g_blocking_fd);
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    test_create_and_flags();
    test_validation();
    test_nonblocking_and_wide_read();
    test_periodic_and_gettime();
    test_absolute_past();
    test_far_future_cancel_on_set();
    test_fault_consumption();
    test_duplicate_lifetime();
    test_blocking_read();
    dprintf(STDOUT_FILENO, "timerfd_abi:%s failures:%d\n",
            g_failures ? "FAIL" : "OK", g_failures);
    return g_failures ? 1 : 0;
}
