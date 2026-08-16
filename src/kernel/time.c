/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral Linux clock ABI policy for EdgeOS. */

#include "kernel/linux_time.h"
#include "kernel/linux_abi.h"
#include "kernel/process_runtime.h"
#include "sys/boottime.h"

static linux_timezone_t linux_system_timezone;

static int linux_clock_source(int clock_id, uint64_t *usec, int *coarse) {
    kernel_process_usage_t usage;
    if (!usec || !coarse) return -1;
    *coarse = 0;
    switch (clock_id) {
        case LINUX_CLOCK_REALTIME:
            *usec = boottime_realtime_us();
            return 0;
        case LINUX_CLOCK_REALTIME_COARSE:
            *usec = boottime_realtime_us();
            *coarse = 1;
            return 0;
        case LINUX_CLOCK_MONOTONIC:
        case LINUX_CLOCK_MONOTONIC_RAW:
        case LINUX_CLOCK_BOOTTIME:
            *usec = boottime_monotonic_us();
            return 0;
        case LINUX_CLOCK_MONOTONIC_COARSE:
            *usec = boottime_monotonic_us();
            *coarse = 1;
            return 0;
        case LINUX_CLOCK_PROCESS_CPUTIME_ID:
        case LINUX_CLOCK_THREAD_CPUTIME_ID:
            if (kernel_process_usage(
                    clock_id == LINUX_CLOCK_PROCESS_CPUTIME_ID ?
                        EDGE_LINUX_RUSAGE_SELF : EDGE_LINUX_RUSAGE_THREAD,
                    &usage) < 0)
                return -1;
            *usec = usage.sys_time_us > UINT64_MAX - usage.user_time_us ?
                UINT64_MAX : usage.user_time_us + usage.sys_time_us;
            return 0;
        default:
            return -1;
    }
}

int linux_clock_gettime_value(int clock_id, linux_timespec64_t *value) {
    uint64_t usec;
    int coarse;
    if (!value || linux_clock_source(clock_id, &usec, &coarse) < 0) return -1;
    if (coarse) usec -= usec % 1000u;
    value->tv_sec = (int64_t)(usec / 1000000u);
    value->tv_nsec = (int64_t)((usec % 1000000u) * 1000u);
    return 0;
}

int linux_clock_getres_value(int clock_id, linux_timespec64_t *value) {
    uint64_t ignored;
    int coarse;
    if (!value || linux_clock_source(clock_id, &ignored, &coarse) < 0) return -1;
    value->tv_sec = 0;
    value->tv_nsec = coarse ? 1000000 : 1000;
    return 0;
}

void linux_gettimeofday_value(linux_timeval64_t *value) {
    uint64_t usec;
    if (!value) return;
    usec = boottime_realtime_us();
    value->tv_sec = (int64_t)(usec / 1000000u);
    value->tv_usec = (int64_t)(usec % 1000000u);
}

void linux_get_timezone_value(linux_timezone_t *value) {
    if (value) *value = linux_system_timezone;
}

int linux_set_timezone_value(const linux_timezone_t *value) {
    if (!value || value->minutes_west < -1440 ||
        value->minutes_west > 1440 || value->dst_time < 0 ||
        value->dst_time > 6)
        return -1;
    linux_system_timezone = *value;
    return 0;
}

void linux_timespec_from_microseconds(uint64_t microseconds,
                                     linux_timespec64_t *value) {
    if (!value) return;
    value->tv_sec = (int64_t)(microseconds / 1000000u);
    value->tv_nsec = (int64_t)((microseconds % 1000000u) * 1000u);
}

void linux_timeval_from_microseconds(uint64_t microseconds,
                                    linux_timeval64_t *value) {
    if (!value) return;
    value->tv_sec = (int64_t)(microseconds / 1000000u);
    value->tv_usec = (int64_t)(microseconds % 1000000u);
}

int linux_evdev_clock_supported(int clock_id) {
    return clock_id == LINUX_CLOCK_REALTIME ||
           clock_id == LINUX_CLOCK_MONOTONIC ||
           clock_id == LINUX_CLOCK_BOOTTIME;
}

uint64_t linux_evdev_timestamp_us(int clock_id, uint64_t realtime_us,
                                  uint64_t monotonic_us) {
    return clock_id == LINUX_CLOCK_REALTIME ? realtime_us : monotonic_us;
}
