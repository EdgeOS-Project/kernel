/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS x86 RTC/CMOS driver.
 *
 * Copyright (c) EdgeOS Contributors.
 */
#include "drivers/rtc.h"
#include "arch/x86_64/io_ports.h"
#include "stdio.h"

#define CMOS_ADDR_PORT 0x70u
#define CMOS_DATA_PORT 0x71u
#define CMOS_REG_SECONDS 0x00u
#define CMOS_REG_MINUTES 0x02u
#define CMOS_REG_HOURS   0x04u
#define CMOS_REG_WDAY    0x06u
#define CMOS_REG_MDAY    0x07u
#define CMOS_REG_MONTH   0x08u
#define CMOS_REG_YEAR    0x09u
#define CMOS_REG_STATUS_A 0x0Au
#define CMOS_REG_STATUS_B 0x0Bu
#define CMOS_REG_STATUS_D 0x0Du

#define CMOS_STATUS_A_UIP 0x80u
#define CMOS_STATUS_B_24H 0x02u
#define CMOS_STATUS_B_BINARY 0x04u
#define CMOS_STATUS_D_VRT 0x80u

#define RTC_MAX_STABLE_READ_SPINS 1000000u

static int g_rtc_ready;
static int g_rtc_voltage_low;

static uint8_t cmos_read(uint8_t reg) {
    /*
     * Keep NMI enabled state stable by setting bit 7.  EdgeOS does not yet have
     * an NMI dispatcher, and Linux-compatible RTC reads must not accidentally
     * toggle platform interrupt state while sampling CMOS.
     */
    outportb(CMOS_ADDR_PORT, (uint8_t)(reg | 0x80u));
    return inportb(CMOS_DATA_PORT);
}

static int rtc_update_in_progress(void) {
    return (cmos_read(CMOS_REG_STATUS_A) & CMOS_STATUS_A_UIP) != 0;
}

static uint8_t rtc_bcd_to_bin(uint8_t v) {
    return (uint8_t)((v & 0x0Fu) + ((v >> 4) * 10u));
}

static int rtc_is_leap(int year) {
    return ((year % 4) == 0 && (year % 100) != 0) || ((year % 400) == 0);
}

static int rtc_days_before_month(int year, int mon_one_based) {
    static const int days_before[12] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    int m = mon_one_based;
    if (m < 1) m = 1;
    if (m > 12) m = 12;
    return days_before[m - 1] + ((m > 2 && rtc_is_leap(year)) ? 1 : 0);
}

static int rtc_validate_tm(const struct edge_rtc_time *tm) {
    if (!tm) return -1;
    if (tm->tm_sec < 0 || tm->tm_sec > 59) return -1;
    if (tm->tm_min < 0 || tm->tm_min > 59) return -1;
    if (tm->tm_hour < 0 || tm->tm_hour > 23) return -1;
    if (tm->tm_mday < 1 || tm->tm_mday > 31) return -1;
    if (tm->tm_mon < 0 || tm->tm_mon > 11) return -1;
    if (tm->tm_year < 70 || tm->tm_year > 199) return -1;
    return 0;
}

static int rtc_sample_raw(uint8_t raw[7], uint8_t *status_b) {
    uint32_t spins = 0;
    if (!raw || !status_b) return -1;

    while (rtc_update_in_progress()) {
        if (++spins > RTC_MAX_STABLE_READ_SPINS) return -1;
        __asm__ __volatile__("pause");
    }

    raw[0] = cmos_read(CMOS_REG_SECONDS);
    raw[1] = cmos_read(CMOS_REG_MINUTES);
    raw[2] = cmos_read(CMOS_REG_HOURS);
    raw[3] = cmos_read(CMOS_REG_WDAY);
    raw[4] = cmos_read(CMOS_REG_MDAY);
    raw[5] = cmos_read(CMOS_REG_MONTH);
    raw[6] = cmos_read(CMOS_REG_YEAR);
    *status_b = cmos_read(CMOS_REG_STATUS_B);
    return 0;
}

int rtc_read_time(struct edge_rtc_time *tm) {
    uint8_t a[7];
    uint8_t b[7];
    uint8_t status_b;
    uint8_t status_b2;
    uint8_t hour_pm;
    int year;
    int month;
    int mday;

    if (!tm) return -1;
    if (rtc_sample_raw(a, &status_b) < 0) return -1;
    if (rtc_sample_raw(b, &status_b2) < 0) return -1;
    for (int i = 0; i < 7; ++i) {
        if (a[i] != b[i]) return -1;
    }

    hour_pm = (uint8_t)(a[2] & 0x80u);
    if ((status_b & CMOS_STATUS_B_BINARY) == 0) {
        a[0] = rtc_bcd_to_bin(a[0]);
        a[1] = rtc_bcd_to_bin(a[1]);
        a[2] = rtc_bcd_to_bin((uint8_t)(a[2] & 0x7Fu));
        a[3] = rtc_bcd_to_bin(a[3]);
        a[4] = rtc_bcd_to_bin(a[4]);
        a[5] = rtc_bcd_to_bin(a[5]);
        a[6] = rtc_bcd_to_bin(a[6]);
    } else {
        a[2] &= 0x7Fu;
    }

    if ((status_b & CMOS_STATUS_B_24H) == 0 && hour_pm && a[2] < 12) {
        a[2] = (uint8_t)(a[2] + 12u);
    }
    if ((status_b & CMOS_STATUS_B_24H) == 0 && !hour_pm && a[2] == 12) {
        a[2] = 0;
    }

    /*
     * PC CMOS traditionally stores only a two-digit year.  Linux's mc146818
     * path uses a configurable epoch; expose the common 2000 epoch here and
     * keep the ABI result as years since 1900.
     */
    year = 2000 + (int)a[6];
    month = (int)a[5];
    mday = (int)a[4];

    tm->tm_sec = (int)a[0];
    tm->tm_min = (int)a[1];
    tm->tm_hour = (int)a[2];
    tm->tm_mday = mday;
    tm->tm_mon = month - 1;
    tm->tm_year = year - 1900;
    tm->tm_wday = a[3] ? ((int)a[3] - 1) : 0;
    tm->tm_yday = rtc_days_before_month(year, month) + mday - 1;
    tm->tm_isdst = 0;
    return rtc_validate_tm(tm);
}

int rtc_unix_seconds(uint64_t *seconds_out) {
    struct edge_rtc_time tm;
    uint64_t days = 0;
    int year;

    if (!seconds_out) return -1;
    if (rtc_read_time(&tm) < 0) return -1;

    year = tm.tm_year + 1900;
    for (int y = 1970; y < year; ++y) {
        days += rtc_is_leap(y) ? 366ull : 365ull;
    }
    days += (uint64_t)tm.tm_yday;
    *seconds_out = days * 86400ull +
                   (uint64_t)tm.tm_hour * 3600ull +
                   (uint64_t)tm.tm_min * 60ull +
                   (uint64_t)tm.tm_sec;
    return 0;
}

int rtc_irq_rate(void) {
    return 1;
}

int rtc_epoch(void) {
    return 2000;
}

int rtc_voltage_low_flags(void) {
    return g_rtc_voltage_low ? 1 : 0;
}

void rtc_init(void) {
    struct edge_rtc_time tm;
    uint8_t status_d = cmos_read(CMOS_REG_STATUS_D);
    g_rtc_voltage_low = (status_d & CMOS_STATUS_D_VRT) ? 0 : 1;
    if (rtc_read_time(&tm) == 0) {
        g_rtc_ready = 1;
        printf("[rtc] cmos clock ready %04d-%02d-%02d %02d:%02d:%02d UTC%s\n",
               tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
               tm.tm_hour, tm.tm_min, tm.tm_sec,
               g_rtc_voltage_low ? " voltage-low" : "");
    } else {
        g_rtc_ready = 0;
        printf("[rtc] cmos clock present but unreadable%s\n",
               g_rtc_voltage_low ? " voltage-low" : "");
    }
    (void)g_rtc_ready;
}
