/* SPDX-License-Identifier: BSD-2-Clause */
/* Calendar conversion interface used by imported FreeBSD drivers. */

#ifndef _SYS_CLOCK_H_
#define _SYS_CLOCK_H_

#include <sys/bus.h>
#include <sys/libkern.h>
#include <sys/time.h>

struct clocktime {
    int year;
    int mon;
    int day;
    int hour;
    int min;
    int sec;
    int dow;
    long nsec;
};

int utc_offset(void);
void inittodr(time_t base);
int clock_ct_to_ts(const struct clocktime *calendar,
    struct timespec *timestamp);
void clock_ts_to_ct(const struct timespec *timestamp,
    struct clocktime *calendar);

#define CLOCKF_SETTIME_NO_TS 0x00000001
#define CLOCKF_SETTIME_NO_ADJ 0x00000002
#define CLOCKF_GETTIME_NO_ADJ 0x00000004

void clock_register(device_t device, long resolution_us);
void clock_register_flags(device_t device, long resolution_us, int flags);
void clock_schedule(device_t device, u_int offset_ns);
void clock_unregister(device_t device);

#define CLOCK_DBG_READ 0x01
#define CLOCK_DBG_WRITE 0x02

void clock_dbgprint_ct(device_t device, int operation,
    const struct clocktime *calendar);

#define SECDAY (24 * 60 * 60)
#define SECYR (SECDAY * 365)
#define POSIX_BASE_YEAR 1970

#endif
