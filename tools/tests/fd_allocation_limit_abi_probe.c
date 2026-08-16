#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_close_range
#if defined(__x86_64__) || defined(__aarch64__)
#define SYS_close_range 436
#else
#error "SYS_close_range is required by this probe"
#endif
#endif

enum {
    SOFT_LIMIT = 64,
    HIGH_FD = 96,
    CLEAN_FD_CHECK_MAX = 128,
};

typedef void (*test_case_fn)(void);

struct test_case {
    const char *name;
    test_case_fn run;
};

static _Noreturn void fail_errno(const char *operation)
{
    int saved_errno = errno;

    dprintf(STDERR_FILENO, "FAIL operation=%s errno=%d\n", operation, saved_errno);
    _exit(1);
}

static _Noreturn void fail_value(const char *operation, long actual, long expected)
{
    dprintf(STDERR_FILENO,
            "FAIL operation=%s actual=%ld expected=%ld\n",
            operation,
            actual,
            expected);
    _exit(1);
}

static void expect_observation(const char *name,
                               long actual,
                               int actual_errno,
                               long expected,
                               int expected_errno)
{
    bool matches = actual == expected && actual_errno == expected_errno;

    dprintf(STDOUT_FILENO,
            "OBS name=%s result=%ld errno=%d expected_result=%ld expected_errno=%d\n",
            name,
            actual,
            actual_errno,
            expected,
            expected_errno);
    if (!matches) {
        dprintf(STDERR_FILENO, "FAIL observation=%s\n", name);
        _exit(1);
    }
}

static void ensure_standard_descriptors(void)
{
    int descriptor;

    for (descriptor = STDIN_FILENO; descriptor <= STDERR_FILENO; descriptor++) {
        int result;

        errno = 0;
        result = fcntl(descriptor, F_GETFD);
        if (result >= 0) {
            continue;
        }
        if (errno != EBADF) {
            fail_errno("fcntl(F_GETFD) while normalizing standard descriptors");
        }

        result = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (result < 0) {
            fail_errno("open(/dev/null) while normalizing standard descriptors");
        }
        if (result != descriptor) {
            if (dup2(result, descriptor) != descriptor) {
                fail_errno("dup2 while normalizing standard descriptors");
            }
            if (close(result) != 0) {
                fail_errno("close temporary standard descriptor");
            }
        }
    }
}

static void close_inherited_descriptors(void)
{
    int descriptor;

    errno = 0;
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) != 0) {
        fail_errno("close_range inherited descriptors");
    }

    for (descriptor = 3; descriptor <= CLEAN_FD_CHECK_MAX; descriptor++) {
        int result;
        int saved_errno;

        errno = 0;
        result = fcntl(descriptor, F_GETFD);
        saved_errno = errno;
        if (result != -1 || saved_errno != EBADF) {
            dprintf(STDERR_FILENO,
                    "FAIL inherited_descriptor=%d result=%d errno=%d\n",
                    descriptor,
                    result,
                    saved_errno);
            _exit(1);
        }
    }
}

static int prepare_clean_source(void)
{
    int source;

    ensure_standard_descriptors();
    close_inherited_descriptors();

    source = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (source < 0) {
        fail_errno("open source descriptor");
    }
    if (source != 3) {
        fail_value("source descriptor number", source, 3);
    }
    return source;
}

static void ensure_soft_limit_at_least(rlim_t required)
{
    struct rlimit limits;

    if (getrlimit(RLIMIT_NOFILE, &limits) != 0) {
        fail_errno("getrlimit(RLIMIT_NOFILE)");
    }
    if (limits.rlim_max != RLIM_INFINITY && limits.rlim_max < required) {
        dprintf(STDERR_FILENO,
                "FAIL RLIMIT_NOFILE hard=%" PRIuMAX " required=%" PRIuMAX "\n",
                (uintmax_t)limits.rlim_max,
                (uintmax_t)required);
        _exit(1);
    }
    if (limits.rlim_cur >= required) {
        return;
    }

    limits.rlim_cur = required;
    if (setrlimit(RLIMIT_NOFILE, &limits) != 0) {
        fail_errno("raise soft RLIMIT_NOFILE for probe setup");
    }
}

static void lower_soft_limit(void)
{
    struct rlimit limits;
    struct rlimit observed;

    if (getrlimit(RLIMIT_NOFILE, &limits) != 0) {
        fail_errno("getrlimit before lowering RLIMIT_NOFILE");
    }
    if (limits.rlim_max != RLIM_INFINITY &&
        limits.rlim_max < (rlim_t)SOFT_LIMIT) {
        dprintf(STDERR_FILENO,
                "FAIL RLIMIT_NOFILE hard=%" PRIuMAX " required=%d\n",
                (uintmax_t)limits.rlim_max,
                SOFT_LIMIT);
        _exit(1);
    }

    limits.rlim_cur = (rlim_t)SOFT_LIMIT;
    if (setrlimit(RLIMIT_NOFILE, &limits) != 0) {
        fail_errno("lower soft RLIMIT_NOFILE");
    }
    if (getrlimit(RLIMIT_NOFILE, &observed) != 0) {
        fail_errno("getrlimit after lowering RLIMIT_NOFILE");
    }
    if (observed.rlim_cur != (rlim_t)SOFT_LIMIT) {
        fail_value("observed soft RLIMIT_NOFILE",
                   (long)observed.rlim_cur,
                   SOFT_LIMIT);
    }
}

static void test_open_above_lowered_limit(void)
{
    static const char byte = 'x';
    int source = prepare_clean_source();
    int result;
    int saved_errno;

    ensure_soft_limit_at_least((rlim_t)HIGH_FD + 1);

    errno = 0;
    result = dup3(source, HIGH_FD, O_CLOEXEC);
    saved_errno = errno;
    expect_observation("setup_high_fd", result, saved_errno, HIGH_FD, 0);

    lower_soft_limit();

    errno = 0;
    result = fcntl(HIGH_FD, F_GETFD);
    saved_errno = errno;
    expect_observation("high_fd_getfd_after_lower",
                       result,
                       saved_errno,
                       FD_CLOEXEC,
                       0);

    errno = 0;
    result = (int)write(HIGH_FD, &byte, sizeof(byte));
    saved_errno = errno;
    expect_observation("high_fd_write_after_lower",
                       result,
                       saved_errno,
                       (long)sizeof(byte),
                       0);

    errno = 0;
    result = close(HIGH_FD);
    saved_errno = errno;
    expect_observation("high_fd_close_after_lower", result, saved_errno, 0, 0);

    errno = 0;
    result = fcntl(HIGH_FD, F_GETFD);
    saved_errno = errno;
    expect_observation("high_fd_closed_state",
                       result,
                       saved_errno,
                       -1,
                       EBADF);
}

static void test_out_of_range_errors(void)
{
    int source = prepare_clean_source();
    int result;
    int saved_errno;

    ensure_soft_limit_at_least((rlim_t)SOFT_LIMIT + 2);
    lower_soft_limit();

    errno = 0;
    result = fcntl(source, F_DUPFD, SOFT_LIMIT);
    saved_errno = errno;
    expect_observation("f_dupfd_at_soft_limit",
                       result,
                       saved_errno,
                       -1,
                       EINVAL);

    errno = 0;
    result = fcntl(source, F_DUPFD, SOFT_LIMIT + 1);
    saved_errno = errno;
    expect_observation("f_dupfd_above_soft_limit",
                       result,
                       saved_errno,
                       -1,
                       EINVAL);

    errno = 0;
    result = fcntl(source, F_DUPFD_CLOEXEC, SOFT_LIMIT);
    saved_errno = errno;
    expect_observation("f_dupfd_cloexec_at_soft_limit",
                       result,
                       saved_errno,
                       -1,
                       EINVAL);

    errno = 0;
    result = fcntl(source, F_DUPFD_CLOEXEC, SOFT_LIMIT + 1);
    saved_errno = errno;
    expect_observation("f_dupfd_cloexec_above_soft_limit",
                       result,
                       saved_errno,
                       -1,
                       EINVAL);

    errno = 0;
    result = dup2(source, SOFT_LIMIT);
    saved_errno = errno;
    expect_observation("dup2_at_soft_limit",
                       result,
                       saved_errno,
                       -1,
                       EBADF);

    errno = 0;
    result = dup2(source, SOFT_LIMIT + 1);
    saved_errno = errno;
    expect_observation("dup2_above_soft_limit",
                       result,
                       saved_errno,
                       -1,
                       EBADF);

    errno = 0;
    result = dup3(source, SOFT_LIMIT, O_CLOEXEC);
    saved_errno = errno;
    expect_observation("dup3_at_soft_limit",
                       result,
                       saved_errno,
                       -1,
                       EBADF);

    errno = 0;
    result = dup3(source, SOFT_LIMIT + 1, O_CLOEXEC);
    saved_errno = errno;
    expect_observation("dup3_above_soft_limit",
                       result,
                       saved_errno,
                       -1,
                       EBADF);
}

static void test_lowest_free_and_cloexec(void)
{
    int source = prepare_clean_source();
    int result;
    int saved_errno;

    ensure_soft_limit_at_least((rlim_t)SOFT_LIMIT);

    errno = 0;
    result = dup3(source, 10, O_CLOEXEC);
    saved_errno = errno;
    expect_observation("setup_occupied_fd_10", result, saved_errno, 10, 0);

    errno = 0;
    result = dup3(source, 12, 0);
    saved_errno = errno;
    expect_observation("setup_occupied_fd_12", result, saved_errno, 12, 0);

    lower_soft_limit();

    errno = 0;
    result = dup(source);
    saved_errno = errno;
    expect_observation("dup_lowest_free", result, saved_errno, 4, 0);

    errno = 0;
    result = fcntl(4, F_GETFD);
    saved_errno = errno;
    expect_observation("dup_clears_cloexec", result, saved_errno, 0, 0);
    if (close(4) != 0) {
        fail_errno("close dup lowest-free result");
    }

    errno = 0;
    result = fcntl(source, F_DUPFD, 10);
    saved_errno = errno;
    expect_observation("f_dupfd_lowest_free", result, saved_errno, 11, 0);

    errno = 0;
    result = fcntl(11, F_GETFD);
    saved_errno = errno;
    expect_observation("f_dupfd_clears_cloexec", result, saved_errno, 0, 0);
    if (close(11) != 0) {
        fail_errno("close F_DUPFD lowest-free result");
    }

    errno = 0;
    result = fcntl(source, F_DUPFD_CLOEXEC, 10);
    saved_errno = errno;
    expect_observation("f_dupfd_cloexec_lowest_free",
                       result,
                       saved_errno,
                       11,
                       0);

    errno = 0;
    result = fcntl(11, F_GETFD);
    saved_errno = errno;
    expect_observation("f_dupfd_cloexec_sets_flag",
                       result,
                       saved_errno,
                       FD_CLOEXEC,
                       0);
}

static void test_low_range_exhaustion(void)
{
    int source = prepare_clean_source();
    int descriptor;
    int result;
    int saved_errno;

    ensure_soft_limit_at_least((rlim_t)HIGH_FD + 1);

    errno = 0;
    result = dup3(source, HIGH_FD, O_CLOEXEC);
    saved_errno = errno;
    expect_observation("setup_physical_high_fd",
                       result,
                       saved_errno,
                       HIGH_FD,
                       0);

    lower_soft_limit();

    errno = 0;
    result = close(HIGH_FD);
    saved_errno = errno;
    expect_observation("release_physical_high_fd",
                       result,
                       saved_errno,
                       0,
                       0);

    errno = 0;
    result = fcntl(HIGH_FD, F_GETFD);
    saved_errno = errno;
    expect_observation("free_physical_slot_above_limit",
                       result,
                       saved_errno,
                       -1,
                       EBADF);

    for (descriptor = 4; descriptor < SOFT_LIMIT; descriptor++) {
        int opened = open("/dev/null", O_RDONLY | O_CLOEXEC);

        if (opened < 0) {
            fail_errno("open while filling descriptors below soft limit");
        }
        if (opened != descriptor) {
            fail_value("sequential descriptor while filling below soft limit",
                       opened,
                       descriptor);
        }
    }

    errno = 0;
    result = open("/dev/null", O_RDONLY | O_CLOEXEC);
    saved_errno = errno;
    expect_observation("open_with_low_range_full",
                       result,
                       saved_errno,
                       -1,
                       EMFILE);

    errno = 0;
    result = dup(source);
    saved_errno = errno;
    expect_observation("dup_with_low_range_full",
                       result,
                       saved_errno,
                       -1,
                       EMFILE);

    errno = 0;
    result = fcntl(source, F_DUPFD, 0);
    saved_errno = errno;
    expect_observation("f_dupfd_with_low_range_full",
                       result,
                       saved_errno,
                       -1,
                       EMFILE);

    errno = 0;
    result = fcntl(source, F_DUPFD, SOFT_LIMIT / 2);
    saved_errno = errno;
    expect_observation("f_dupfd_minimum_with_low_range_full",
                       result,
                       saved_errno,
                       -1,
                       EMFILE);

    errno = 0;
    result = fcntl(source, F_DUPFD_CLOEXEC, 0);
    saved_errno = errno;
    expect_observation("f_dupfd_cloexec_with_low_range_full",
                       result,
                       saved_errno,
                       -1,
                       EMFILE);
}

static int run_case(const struct test_case *test)
{
    pid_t child;
    int status;

    dprintf(STDOUT_FILENO, "CASE name=%s state=begin\n", test->name);
    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        test->run();
        dprintf(STDOUT_FILENO, "CASE name=%s state=pass\n", test->name);
        _exit(0);
    }

    do {
        errno = 0;
        if (waitpid(child, &status, 0) >= 0) {
            break;
        }
    } while (errno == EINTR);

    if (errno != 0) {
        perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        dprintf(STDERR_FILENO,
                "CASE name=%s state=fail wait_status=%d\n",
                test->name,
                status);
        return 1;
    }
    return 0;
}

int main(void)
{
    static const struct test_case cases[] = {
        {"open_above_lowered_limit", test_open_above_lowered_limit},
        {"out_of_range_errors", test_out_of_range_errors},
        {"lowest_free_and_cloexec", test_lowest_free_and_cloexec},
        {"low_range_exhaustion", test_low_range_exhaustion},
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        if (run_case(&cases[index]) != 0) {
            return EXIT_FAILURE;
        }
    }

    dprintf(STDOUT_FILENO,
            "FD_ALLOCATION_LIMIT_ABI_PROBE_PASS cases=%zu soft_limit=%d high_fd=%d\n",
            sizeof(cases) / sizeof(cases[0]),
            SOFT_LIMIT,
            HIGH_FD);
    return EXIT_SUCCESS;
}
