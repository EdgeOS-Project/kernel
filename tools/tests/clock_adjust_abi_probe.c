/* SPDX-License-Identifier: MPL-2.0 */
/* Runtime probe for Linux adjtimex and clock_adjtime query behavior. */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define EDGE_SYS_ADJTIMEX 159
#define EDGE_SYS_CLOCK_ADJTIME 305
#elif defined(__aarch64__)
#define EDGE_SYS_ADJTIMEX 171
#define EDGE_SYS_CLOCK_ADJTIME 266
#else
#error "clock_adjust_abi_probe requires a supported 64-bit architecture"
#endif

#define EDGE_CLOCK_REALTIME 0
#define EDGE_CLOCK_MONOTONIC 1
#define EDGE_EOPNOTSUPP 95

struct edge_timex_timeval {
    int64_t tv_sec;
    int64_t tv_usec;
};

struct edge_timex {
    uint32_t modes;
    uint32_t padding0;
    int64_t offset;
    int64_t frequency;
    int64_t maximum_error;
    int64_t estimated_error;
    int32_t status;
    uint32_t padding1;
    int64_t constant;
    int64_t precision;
    int64_t tolerance;
    struct edge_timex_timeval time;
    int64_t tick;
    int64_t pps_frequency;
    int64_t jitter;
    int32_t shift;
    uint32_t padding2;
    int64_t stability;
    int64_t jitter_count;
    int64_t calibration_count;
    int64_t error_count;
    int64_t stability_count;
    int32_t tai;
    uint32_t padding3[11];
};

_Static_assert(sizeof(struct edge_timex) == 208u, "timex ABI size");

static int query_clock(long syscall_number, long clock_id, int has_clock) {
    struct edge_timex value;
    long result;

    memset(&value, 0, sizeof(value));
    errno = 0;
    result = has_clock ? syscall(syscall_number, clock_id, &value) :
                         syscall(syscall_number, &value);
    if (result < 0 || result > 5 || value.precision <= 0 ||
        value.tolerance <= 0 || value.tick <= 0 || value.time.tv_sec <= 0) {
        fprintf(stderr,
                "clock query: syscall=%ld result=%ld errno=%d precision=%lld "
                "tolerance=%lld tick=%lld sec=%lld\n",
                syscall_number, result, errno,
                (long long)value.precision, (long long)value.tolerance,
                (long long)value.tick, (long long)value.time.tv_sec);
        return 1;
    }
    return 0;
}

int main(void) {
    struct edge_timex value;
    long result;

    memset(&value, 0, sizeof(value));
    if (query_clock(EDGE_SYS_ADJTIMEX, 0, 0)) return 1;
    if (query_clock(
            EDGE_SYS_CLOCK_ADJTIME, EDGE_CLOCK_REALTIME, 1)) return 2;
    errno = 0;
    result = syscall(
        EDGE_SYS_CLOCK_ADJTIME, EDGE_CLOCK_MONOTONIC, &value);
    if (result != -1 || errno != EDGE_EOPNOTSUPP) {
        fprintf(stderr, "non-adjustable clock: result=%ld errno=%d\n",
                result, errno);
        return 3;
    }
    return 0;
}
