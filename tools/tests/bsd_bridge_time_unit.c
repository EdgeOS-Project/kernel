/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for BSD bridge timeval-to-tick conversion. */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#include <sys/time.h>

#include "compat/freebsd/sys/syscallsubr.h"
#include "compat/freebsd/sys/timetc.h"

int hz = 1000;
volatile int ticks;
extern volatile time_t time_second;
static uint64_t realtime_microseconds = UINT64_C(5000000);

int tvtohz(struct timeval *value);
uint64_t cpu_ticks(void);
uint64_t cputick2usec(uint64_t tick);

uint64_t
boottime_monotonic_us(void)
{
    return UINT64_C(2000000);
}

uint64_t
boottime_realtime_us(void)
{
    return realtime_microseconds;
}

int
boottime_set_realtime_us(uint64_t value)
{
    realtime_microseconds = value;
    return 0;
}

int
main(void)
{
    struct timecounter slow_counter;
    struct timecounter fast_counter;
    struct timespec timestamp;
    struct timeval value;

    value = (struct timeval){ .tv_sec = 0, .tv_usec = 0 };
    assert(tvtohz(&value) == 1);
    value = (struct timeval){ .tv_sec = 0, .tv_usec = 1000 };
    assert(tvtohz(&value) == 2);
    value = (struct timeval){ .tv_sec = 1, .tv_usec = 0 };
    assert(tvtohz(&value) == 1001);

    value = (struct timeval){ .tv_sec = 1, .tv_usec = 1000000 };
    assert(tvtohz(&value) == 2001);
    assert(value.tv_sec == 2);
    assert(value.tv_usec == 0);

    value = (struct timeval){ .tv_sec = 1, .tv_usec = -1 };
    assert(tvtohz(&value) == 1000);
    assert(value.tv_sec == 0);
    assert(value.tv_usec == 999999);

    value = (struct timeval){ .tv_sec = -1, .tv_usec = 0 };
    assert(tvtohz(&value) == 1);
    value = (struct timeval){ .tv_sec = INT_MAX, .tv_usec = 0 };
    assert(tvtohz(&value) == INT_MAX);
    assert(tvtohz(NULL) == 1);

    hz = 100;
    value = (struct timeval){ .tv_sec = 0, .tv_usec = 10000 };
    assert(tvtohz(&value) == 2);
    assert(cpu_ticks() == UINT64_C(2000000));
    assert(cputick2usec(UINT64_C(123456789)) == UINT64_C(123456789));

    slow_counter = (struct timecounter){
        .tc_get_timecount = (timecounter_get_t *)(uintptr_t)1,
        .tc_frequency = UINT64_C(10000000),
        .tc_quality = 100,
    };
    fast_counter = (struct timecounter){
        .tc_get_timecount = (timecounter_get_t *)(uintptr_t)1,
        .tc_frequency = UINT64_C(25000000),
        .tc_quality = 200,
    };
    tc_init(&slow_counter);
    assert(tc_getfrequency() == UINT64_C(10000000));
    tc_init(&fast_counter);
    assert(tc_getfrequency() == UINT64_C(25000000));

    timestamp = (struct timespec){0};
    assert(kern_clock_gettime(NULL, CLOCK_MONOTONIC, &timestamp) == 0);
    assert(timestamp.tv_sec == 2);
    assert(timestamp.tv_nsec == 0);
    assert(kern_clock_gettime(NULL, CLOCK_MONOTONIC_FAST, &timestamp) == 0);
    assert(timestamp.tv_sec == 2);
    assert(timestamp.tv_nsec == 0);
    assert(kern_clock_gettime(NULL, CLOCK_REALTIME, &timestamp) == 0);
    assert(timestamp.tv_sec == 5);
    assert(timestamp.tv_nsec == 0);
    assert(kern_clock_gettime(NULL, (clockid_t)-1, &timestamp) == EINVAL);
    assert(kern_clock_gettime(NULL, CLOCK_REALTIME, NULL) == EINVAL);

    timestamp = (struct timespec){ .tv_sec = 12, .tv_nsec = 345000000 };
    tc_setclock(&timestamp);
    assert(realtime_microseconds == UINT64_C(12345000));
    assert(time_second == 12);
    return 0;
}
