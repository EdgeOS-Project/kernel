/* SPDX-License-Identifier: MPL-2.0 */
/* Shared FreeBSD time policy backed by the EdgeOS boot clock. */

#include <limits.h>
#include <stdint.h>

#include <sys/time.h>
#ifndef BSD_BRIDGE_HOST_TEST
#include <sys/syscallsubr.h>
#include <sys/timetc.h>
#endif
#ifdef BSD_BRIDGE_HOST_TEST
#include <errno.h>
#include "compat/freebsd/sys/timetc.h"
#define POSIX_BASE_YEAR 1970
#define SECDAY 86400
struct thread;
struct bintime {
    time_t sec;
    uint64_t frac;
};
struct clocktime {
    int sec;
    int min;
    int hour;
    int day;
    int mon;
    int year;
    int dow;
    long nsec;
};
#else
#include <sys/clock.h>
#if defined(__x86_64__)
#include <machine/md_var.h>
#endif
#endif
#include "sys/boottime.h"

extern int hz;
extern volatile int ticks;

volatile time_t time_second;
volatile time_t time_uptime;
int tc_precexp = 4;
int tc_min_ticktock_freq;
struct timecounter *timecounter;

void bsd_compat_time_tick(uint64_t monotonic_microseconds);

int
kern_clock_gettime(struct thread *thread, clockid_t clock_id,
    struct timespec *value)
{
    uint64_t microseconds;

    (void)thread;
    if (!value)
        return EINVAL;
    if (clock_id == CLOCK_REALTIME)
        microseconds = boottime_realtime_us();
    else if (clock_id == CLOCK_MONOTONIC ||
        clock_id == CLOCK_MONOTONIC_FAST)
        microseconds = boottime_monotonic_us();
    else
        return EINVAL;
    value->tv_sec = (time_t)(microseconds / UINT64_C(1000000));
    value->tv_nsec = (long)(microseconds % UINT64_C(1000000)) * 1000L;
    return 0;
}

int
kern_clock_settime(struct thread *thread, clockid_t clock_id,
    const struct timespec *value)
{
    uint64_t realtime_microseconds;

    (void)thread;
    if (clock_id != CLOCK_REALTIME || !value || value->tv_sec < 0 ||
        value->tv_nsec < 0 || value->tv_nsec >= 1000000000l ||
        (uint64_t)value->tv_sec >
        (UINT64_MAX - (uint64_t)value->tv_nsec / 1000u) /
        UINT64_C(1000000))
        return EINVAL;
    realtime_microseconds =
        (uint64_t)value->tv_sec * UINT64_C(1000000) +
        (uint64_t)value->tv_nsec / 1000u;
    if (boottime_set_realtime_us(realtime_microseconds) < 0)
        return EINVAL;
    __atomic_store_n(&time_second, value->tv_sec, __ATOMIC_RELEASE);
    return 0;
}

uint64_t
tc_getfrequency(void)
{
    struct timecounter *current;

    current = __atomic_load_n(&timecounter, __ATOMIC_ACQUIRE);
    return current && current->tc_frequency ? current->tc_frequency :
        UINT64_C(1000000);
}

void
tc_init(struct timecounter *counter)
{
    struct timecounter *current;

    if (!counter || !counter->tc_get_timecount ||
        counter->tc_frequency == 0)
        return;
    current = __atomic_load_n(&timecounter, __ATOMIC_ACQUIRE);
    if (!current || counter->tc_quality > current->tc_quality)
        __atomic_store_n(&timecounter, counter, __ATOMIC_RELEASE);
}

void
tc_setclock(struct timespec *value)
{
    (void)kern_clock_settime(NULL, CLOCK_REALTIME, value);
}

void
tc_ticktock(long count)
{
    (void)count;
    bsd_compat_time_tick(boottime_monotonic_us());
}

void
cpu_tick_calibration(void)
{
}

uint64_t
clockcalib(uint64_t (*read_counter)(void), const char *name)
{
    uint64_t start_counter;
    uint64_t start_time;
    uint64_t current_time;
    uint64_t elapsed;

    (void)name;
    if (!read_counter)
        return 0;
    start_counter = read_counter();
    start_time = boottime_monotonic_us();
    do {
        current_time = boottime_monotonic_us();
    } while (current_time - start_time < 1000u);
    elapsed = read_counter() - start_counter;
    return elapsed > UINT64_MAX / UINT64_C(1000000) ? 0 :
        elapsed * UINT64_C(1000000) / (current_time - start_time);
}

int
utc_offset(void)
{
    return 0;
}

void
inittodr(time_t base)
{
    time_t current = (time_t)(boottime_realtime_us() /
        UINT64_C(1000000));

    __atomic_store_n(&time_second,
        current > base ? current : base, __ATOMIC_RELEASE);
}

#if !defined(__x86_64__) || defined(BSD_BRIDGE_HOST_TEST)
uint64_t
cpu_ticks(void)
{
    return boottime_monotonic_us();
}
#endif

uint64_t
cputick2usec(uint64_t tick)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    uint64_t frequency;

    frequency = cpu_tickrate();
    if (frequency == 0)
        return tick;
    return (tick / frequency) * UINT64_C(1000000) +
        ((tick % frequency) * UINT64_C(1000000)) / frequency;
#else
    return tick;
#endif
}

int
tvtohz(struct timeval *value)
{
    int64_t seconds;
    int64_t microseconds;
    int64_t adjustment;
    uint64_t ticks_value;

    if (!value || hz <= 0)
        return 1;

    seconds = (int64_t)value->tv_sec;
    microseconds = (int64_t)value->tv_usec;
    adjustment = microseconds / INT64_C(1000000);
    microseconds %= INT64_C(1000000);
    if (adjustment > 0 && seconds > INT64_MAX - adjustment)
        return INT_MAX;
    if (adjustment < 0 && seconds < INT64_MIN - adjustment)
        return 1;
    seconds += adjustment;
    if (microseconds < 0) {
        if (seconds == INT64_MIN)
            return 1;
        microseconds += INT64_C(1000000);
        seconds--;
    }

    value->tv_sec = (time_t)seconds;
    value->tv_usec = (suseconds_t)microseconds;
    if (seconds < 0)
        return 1;
    if ((uint64_t)seconds >
        ((uint64_t)INT_MAX - 1u) / (unsigned int)hz)
        return INT_MAX;

    ticks_value = (uint64_t)seconds * (unsigned int)hz;
    ticks_value += ((uint64_t)microseconds * (unsigned int)hz) /
        UINT64_C(1000000);
    if (ticks_value >= (uint64_t)INT_MAX)
        return INT_MAX;
    return (int)ticks_value + 1;
}

void
clock_ts_to_ct(const struct timespec *timestamp, struct clocktime *calendar)
{
    int64_t seconds;
    int64_t days;
    int64_t remainder;
    int64_t era;
    unsigned int day_of_era;
    unsigned int year_of_era;
    int64_t year;
    unsigned int day_of_year;
    unsigned int month_prime;
    int month;

    if (!timestamp || !calendar)
        return;
    seconds = timestamp->tv_sec;
    days = seconds / SECDAY;
    remainder = seconds % SECDAY;
    if (remainder < 0) {
        remainder += SECDAY;
        days--;
    }

    era = (days + 719468 >= 0 ? days + 719468 :
        days + 719468 - 146096) / 146097;
    day_of_era = (unsigned int)(days + 719468 - era * 146097);
    year_of_era = (day_of_era - day_of_era / 1460 +
        day_of_era / 36524 - day_of_era / 146096) / 365;
    year = (int64_t)year_of_era + era * 400;
    day_of_year = day_of_era -
        (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    month_prime = (5 * day_of_year + 2) / 153;
    calendar->day =
        (int)(day_of_year - (153 * month_prime + 2) / 5 + 1);
    month = (int)month_prime + (month_prime < 10 ? 3 : -9);
    year += month <= 2;

    calendar->year = (int)year;
    calendar->mon = (int)month;
    calendar->hour = (int)(remainder / 3600);
    remainder %= 3600;
    calendar->min = (int)(remainder / 60);
    calendar->sec = (int)(remainder % 60);
    calendar->dow = (int)((days + 4) % 7);
    if (calendar->dow < 0)
        calendar->dow += 7;
    calendar->nsec = timestamp->tv_nsec;
}

static int
bsd_clock_is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

static int
bsd_clock_days_in_month(int year, int month)
{
    static const uint8_t days[] = {
        31, 28, 31, 30, 31, 30,
        31, 31, 30, 31, 30, 31,
    };

    if (month == 2 && bsd_clock_is_leap_year(year))
        return 29;
    return days[month - 1];
}

int
clock_ct_to_ts(const struct clocktime *calendar, struct timespec *timestamp)
{
    int year;
    int month;
    int64_t days = 0;

    if (!calendar || !timestamp)
        return EINVAL;
    year = calendar->year;
    if (year < 70)
        year += 2000;
    else if (year < 200)
        year += 1900;
    if (year < POSIX_BASE_YEAR || calendar->mon < 1 ||
        calendar->mon > 12 || calendar->day < 1 ||
        calendar->day > bsd_clock_days_in_month(year, calendar->mon) ||
        calendar->hour < 0 || calendar->hour > 23 ||
        calendar->min < 0 || calendar->min > 59 ||
        calendar->sec < 0 || calendar->sec > 59 ||
        calendar->nsec < 0 || calendar->nsec >= 1000000000l)
        return EINVAL;

    for (int current = POSIX_BASE_YEAR; current < year; current++)
        days += bsd_clock_is_leap_year(current) ? 366 : 365;
    for (month = 1; month < calendar->mon; month++)
        days += bsd_clock_days_in_month(year, month);
    days += calendar->day - 1;
    timestamp->tv_sec = (((time_t)days * 24 + calendar->hour) * 60 +
        calendar->min) * 60 + calendar->sec;
    timestamp->tv_nsec = calendar->nsec;
    return 0;
}

static void
bsd_timeval_from_microseconds(struct timeval *value, uint64_t microseconds)
{
    if (!value)
        return;
    value->tv_sec = (time_t)(microseconds / UINT64_C(1000000));
    value->tv_usec =
        (suseconds_t)(microseconds % UINT64_C(1000000));
}

static void
bsd_timespec_from_microseconds(struct timespec *value, uint64_t microseconds)
{
    if (!value)
        return;
    value->tv_sec = (time_t)(microseconds / UINT64_C(1000000));
    value->tv_nsec =
        (long)(microseconds % UINT64_C(1000000)) * 1000l;
}

static void
bsd_bintime_from_microseconds(struct bintime *value, uint64_t microseconds)
{
    const uint64_t quotient = UINT64_MAX / UINT64_C(1000000);
    const uint64_t remainder_scale = UINT64_MAX % UINT64_C(1000000);
    uint64_t remainder;

    if (!value)
        return;
    value->sec = (time_t)(microseconds / UINT64_C(1000000));
    remainder = microseconds % UINT64_C(1000000);
    value->frac = remainder * quotient +
        (remainder * remainder_scale) / UINT64_C(1000000);
}

void
bsd_compat_time_tick(uint64_t monotonic_microseconds)
{
    uint64_t realtime_microseconds = boottime_realtime_us();

    __atomic_store_n(&time_uptime,
        (time_t)(monotonic_microseconds / UINT64_C(1000000)),
        __ATOMIC_RELEASE);
    __atomic_store_n(&time_second,
        (time_t)(realtime_microseconds / UINT64_C(1000000)),
        __ATOMIC_RELEASE);
}

void
getmicrouptime(struct timeval *value)
{
    uint64_t microseconds;

    if (!value)
        return;
    microseconds = boottime_monotonic_us();
    bsd_timeval_from_microseconds(value, microseconds);
    __atomic_store_n(&time_uptime, value->tv_sec, __ATOMIC_RELEASE);
}

void
microuptime(struct timeval *value)
{
    getmicrouptime(value);
}

void
getnanouptime(struct timespec *value)
{
    uint64_t microseconds = boottime_monotonic_us();

    bsd_timespec_from_microseconds(value, microseconds);
    if (value)
        __atomic_store_n(&time_uptime, value->tv_sec, __ATOMIC_RELEASE);
}

void
nanouptime(struct timespec *value)
{
    getnanouptime(value);
}

void
getbinuptime(struct bintime *value)
{
    uint64_t microseconds = boottime_monotonic_us();

    bsd_bintime_from_microseconds(value, microseconds);
    if (value)
        __atomic_store_n(&time_uptime, value->sec, __ATOMIC_RELEASE);
}

void
binuptime(struct bintime *value)
{
    getbinuptime(value);
}

void
getmicrotime(struct timeval *value)
{
    uint64_t microseconds = boottime_realtime_us();

    bsd_timeval_from_microseconds(value, microseconds);
    if (value)
        __atomic_store_n(&time_second, value->tv_sec, __ATOMIC_RELEASE);
}

void
microtime(struct timeval *value)
{
    getmicrotime(value);
}

void
getnanotime(struct timespec *value)
{
    uint64_t microseconds = boottime_realtime_us();

    bsd_timespec_from_microseconds(value, microseconds);
    if (value)
        __atomic_store_n(&time_second, value->tv_sec, __ATOMIC_RELEASE);
}

void
nanotime(struct timespec *value)
{
    getnanotime(value);
}

void
getbintime(struct bintime *value)
{
    uint64_t microseconds = boottime_realtime_us();

    bsd_bintime_from_microseconds(value, microseconds);
    if (value)
        __atomic_store_n(&time_second, value->sec, __ATOMIC_RELEASE);
}

void
bintime(struct bintime *value)
{
    getbintime(value);
}

void
getboottime(struct timeval *value)
{
    uint64_t realtime = boottime_realtime_us();
    uint64_t monotonic = boottime_monotonic_us();

    bsd_timeval_from_microseconds(
        value, realtime >= monotonic ? realtime - monotonic : 0);
}

void
getboottimebin(struct bintime *value)
{
    uint64_t realtime = boottime_realtime_us();
    uint64_t monotonic = boottime_monotonic_us();

    bsd_bintime_from_microseconds(
        value, realtime >= monotonic ? realtime - monotonic : 0);
}

void
timevaladd(struct timeval *left, const struct timeval *right)
{
    if (!left || !right)
        return;
    left->tv_sec += right->tv_sec;
    left->tv_usec += right->tv_usec;
    if (left->tv_usec >= 1000000) {
        left->tv_sec++;
        left->tv_usec -= 1000000;
    }
}

void
timevalsub(struct timeval *left, const struct timeval *right)
{
    if (!left || !right)
        return;
    left->tv_sec -= right->tv_sec;
    left->tv_usec -= right->tv_usec;
    if (left->tv_usec < 0) {
        left->tv_sec--;
        left->tv_usec += 1000000;
    }
}

int
ratecheck(struct timeval *last_time, const struct timeval *minimum_interval)
{
    struct timeval now;
    struct timeval delta;

    if (!last_time || !minimum_interval)
        return 0;
    getmicrouptime(&now);
    delta.tv_sec = now.tv_sec - last_time->tv_sec;
    delta.tv_usec = now.tv_usec - last_time->tv_usec;
    if (delta.tv_usec < 0) {
        delta.tv_sec--;
        delta.tv_usec += 1000000;
    }
    if ((delta.tv_sec > minimum_interval->tv_sec) ||
        (delta.tv_sec == minimum_interval->tv_sec &&
        delta.tv_usec >= minimum_interval->tv_usec) ||
        (last_time->tv_sec == 0 && last_time->tv_usec == 0)) {
        *last_time = now;
        return 1;
    }
    return 0;
}

int
eventratecheck(struct timeval *last_time, int *current_events,
    int maximum_events)
{
    int now;

    if (!last_time || !current_events)
        return 0;
    now = __atomic_load_n(&ticks, __ATOMIC_RELAXED);
    if (last_time->tv_sec == 0 ||
        (uint32_t)(now - (int)last_time->tv_sec) >= (uint32_t)hz) {
        last_time->tv_sec = now;
        *current_events = 1;
        return maximum_events != 0;
    }
    (*current_events)++;
    return maximum_events < 0 || *current_events <= maximum_events;
}
