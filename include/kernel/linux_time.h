/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_LINUX_TIME_H
#define EDGEOS_KERNEL_LINUX_TIME_H

#include <stddef.h>
#include <stdint.h>

#define LINUX_CLOCK_REALTIME 0
#define LINUX_CLOCK_MONOTONIC 1
#define LINUX_CLOCK_PROCESS_CPUTIME_ID 2
#define LINUX_CLOCK_THREAD_CPUTIME_ID 3
#define LINUX_CLOCK_MONOTONIC_RAW 4
#define LINUX_CLOCK_REALTIME_COARSE 5
#define LINUX_CLOCK_MONOTONIC_COARSE 6
#define LINUX_CLOCK_BOOTTIME 7
#define LINUX_CLOCK_REALTIME_ALARM 8
#define LINUX_CLOCK_BOOTTIME_ALARM 9
#define LINUX_CLOCK_TAI 11

typedef struct linux_timespec64 {
    int64_t tv_sec;
    int64_t tv_nsec;
} linux_timespec64_t;

typedef struct linux_timeval64 {
    int64_t tv_sec;
    int64_t tv_usec;
} linux_timeval64_t;

typedef struct linux_itimerspec64 {
    linux_timespec64_t it_interval;
    linux_timespec64_t it_value;
} linux_itimerspec64_t;

typedef struct linux_itimerval64 {
    linux_timeval64_t it_interval;
    linux_timeval64_t it_value;
} linux_itimerval64_t;

typedef struct linux_sigevent64 {
    uint64_t sigev_value;
    int32_t sigev_signo;
    int32_t sigev_notify;
    union {
        int32_t thread_id;
        uint8_t padding[48];
    } fields;
} linux_sigevent64_t;

typedef struct linux_timezone {
    int32_t minutes_west;
    int32_t dst_time;
} linux_timezone_t;

_Static_assert(sizeof(linux_timespec64_t) == 16,
               "Linux 64-bit timespec ABI layout");
_Static_assert(sizeof(linux_timeval64_t) == 16,
               "Linux 64-bit timeval ABI layout");
_Static_assert(sizeof(linux_itimerspec64_t) == 32,
               "Linux 64-bit itimerspec ABI layout");
_Static_assert(sizeof(linux_itimerval64_t) == 32,
               "Linux 64-bit itimerval ABI layout");
_Static_assert(sizeof(linux_sigevent64_t) == 64,
               "Linux 64-bit sigevent ABI layout");
_Static_assert(offsetof(linux_itimerval64_t, it_interval) == 0,
               "Linux 64-bit itimerval interval offset");
_Static_assert(offsetof(linux_itimerval64_t, it_value) == 16,
               "Linux 64-bit itimerval value offset");
_Static_assert(offsetof(linux_sigevent64_t, sigev_signo) == 8,
               "Linux 64-bit sigevent signal offset");
_Static_assert(offsetof(linux_sigevent64_t, sigev_notify) == 12,
               "Linux 64-bit sigevent notification offset");
_Static_assert(offsetof(linux_sigevent64_t, fields) == 16,
               "Linux 64-bit sigevent payload offset");
_Static_assert(sizeof(linux_timezone_t) == 8,
               "Linux timezone ABI layout");

int linux_clock_gettime_value(int clock_id, linux_timespec64_t *value);
int linux_clock_getres_value(int clock_id, linux_timespec64_t *value);
void linux_gettimeofday_value(linux_timeval64_t *value);
void linux_get_timezone_value(linux_timezone_t *value);
int linux_set_timezone_value(const linux_timezone_t *value);
void linux_timespec_from_microseconds(uint64_t microseconds,
                                     linux_timespec64_t *value);
void linux_timeval_from_microseconds(uint64_t microseconds,
                                    linux_timeval64_t *value);
int linux_evdev_clock_supported(int clock_id);
uint64_t linux_evdev_timestamp_us(int clock_id, uint64_t realtime_us,
                                  uint64_t monotonic_us);

#endif
