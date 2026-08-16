/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS x86 RTC/CMOS driver interface.
 *
 * Copyright (c) EdgeOS Contributors.
 */
#ifndef DRIVERS_RTC_H
#define DRIVERS_RTC_H

#include <stdint.h>

struct edge_rtc_time {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

void rtc_init(void);
int rtc_read_time(struct edge_rtc_time *tm);
int rtc_unix_seconds(uint64_t *seconds_out);
int rtc_irq_rate(void);
int rtc_epoch(void);
int rtc_voltage_low_flags(void);

#endif
