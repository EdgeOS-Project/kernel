/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux time syscall null-pointer ABI probe for Alpine rootfs validation.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_clock_gettime
#define SYS_clock_gettime 228
#endif

#ifndef SYS_clock_getres
#define SYS_clock_getres 229
#endif

#ifndef SYS_gettimeofday
#define SYS_gettimeofday 96
#endif

static struct timespec g_ts;
static struct timeval g_tv;
static struct timezone g_tz;

static __attribute__((no_stack_protector)) int expect_errno(const char *name, long rc, int saved_errno, int expected) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, rc, saved_errno);
    if (rc != -1) return 1;
    if (saved_errno != expected) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int expect_success(const char *name, long rc, int saved_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, rc, saved_errno);
    if (rc != 0) return 1;
    if (saved_errno != 0) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_clock_gettime_null(void) {
    errno = 0;
    long rc = syscall(SYS_clock_gettime, CLOCK_MONOTONIC, (void *)0);
    return expect_errno("clock_gettime_null", rc, errno, EFAULT);
}

static __attribute__((no_stack_protector)) int test_clock_getres_null(void) {
    errno = 0;
    long rc = syscall(SYS_clock_getres, CLOCK_MONOTONIC, (void *)0);
    return expect_success("clock_getres_null", rc, errno);
}

static __attribute__((no_stack_protector)) int test_gettimeofday_nulls(void) {
    errno = 0;
    long rc = syscall(SYS_gettimeofday, (void *)0, (void *)0);
    return expect_success("gettimeofday_nulls", rc, errno);
}

static __attribute__((no_stack_protector)) int test_gettimeofday_timezone(void) {
    memset(&g_tz, 0x5a, sizeof(g_tz));
    errno = 0;
    long rc = syscall(SYS_gettimeofday, (void *)0, &g_tz);
    dprintf(STDOUT_FILENO, "gettimeofday_tz_rc:%ld errno:%d minuteswest:%d dsttime:%d\n",
            rc, errno, g_tz.tz_minuteswest, g_tz.tz_dsttime);
    if (rc != 0) return 1;
    if (errno != 0) return 1;
    if (g_tz.tz_minuteswest != 0 || g_tz.tz_dsttime != 0) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_gettimeofday_bad_tz(void) {
    errno = 0;
    long rc = syscall(SYS_gettimeofday, (void *)0, (void *)1);
    return expect_errno("gettimeofday_bad_tz", rc, errno, EFAULT);
}

static __attribute__((no_stack_protector)) int test_valid_time_calls(void) {
    memset(&g_ts, 0, sizeof(g_ts));
    errno = 0;
    long rc = syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &g_ts);
    dprintf(STDOUT_FILENO, "clock_gettime_valid_rc:%ld errno:%d sec:%lld nsec:%lld\n",
            rc, errno, (long long)g_ts.tv_sec, (long long)g_ts.tv_nsec);
    if (rc != 0 || errno != 0) return 1;
    if (g_ts.tv_nsec < 0 || g_ts.tv_nsec >= 1000000000L) return 1;

    memset(&g_ts, 0, sizeof(g_ts));
    errno = 0;
    rc = syscall(SYS_clock_getres, CLOCK_MONOTONIC, &g_ts);
    dprintf(STDOUT_FILENO, "clock_getres_valid_rc:%ld errno:%d sec:%lld nsec:%lld\n",
            rc, errno, (long long)g_ts.tv_sec, (long long)g_ts.tv_nsec);
    if (rc != 0 || errno != 0) return 1;
    if (g_ts.tv_sec != 0 || g_ts.tv_nsec <= 0 || g_ts.tv_nsec >= 1000000000L) return 1;

    memset(&g_tv, 0, sizeof(g_tv));
    errno = 0;
    rc = syscall(SYS_gettimeofday, &g_tv, (void *)0);
    dprintf(STDOUT_FILENO, "gettimeofday_valid_rc:%ld errno:%d sec:%lld usec:%lld\n",
            rc, errno, (long long)g_tv.tv_sec, (long long)g_tv.tv_usec);
    if (rc != 0 || errno != 0) return 1;
    if (g_tv.tv_usec < 0 || g_tv.tv_usec >= 1000000L) return 1;
    return 0;
}

int main(void) {
    if (test_clock_gettime_null() != 0) _exit(1);
    if (test_clock_getres_null() != 0) _exit(1);
    if (test_gettimeofday_nulls() != 0) _exit(1);
    if (test_gettimeofday_timezone() != 0) _exit(1);
    if (test_gettimeofday_bad_tz() != 0) _exit(1);
    if (test_valid_time_calls() != 0) _exit(1);
    dprintf(STDOUT_FILENO, "TIME_NULL_ABI_PROBE_PASS\n");
    _exit(0);
}
