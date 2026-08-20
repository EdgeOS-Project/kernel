/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for the Linux timex policy. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/time_discipline.h"
#include "sys/boottime.h"

static int64_t g_frequency;
static int64_t g_pending = 123;
static int64_t g_last_adjustment;
static int g_last_immediate;

void arch_cpu_relax(void) {}
uint64_t boottime_realtime_us(void) { return 1700000000123456ull; }
int64_t boottime_frequency_scaled_ppm(void) { return g_frequency; }
int64_t boottime_pending_adjustment_us(void) { return g_pending; }
int boottime_set_frequency_scaled_ppm(int64_t value) {
    g_frequency = value;
    return 0;
}
int boottime_adjust_realtime_us(int64_t value, int immediate) {
    g_last_adjustment = value;
    g_last_immediate = immediate;
    return 0;
}
int boottime_set_pending_adjustment_us(int64_t value) {
    g_pending = value;
    return 0;
}

static edge_linux_timex_t blank_timex(uint32_t modes) {
    edge_linux_timex_t value;

    memset(&value, 0, sizeof(value));
    value.modes = modes;
    return value;
}

int main(void) {
    edge_linux_timex_t value;
    int result;

    value = blank_timex(0);
    result = kernel_time_discipline_adjust(
        LINUX_CLOCK_REALTIME, &value, 0);
    assert(result == EDGE_LINUX_TIME_ERROR);
    assert(value.status == EDGE_LINUX_STA_UNSYNC);
    assert(value.maximum_error == 16000000);
    assert(value.estimated_error == 16000000);
    assert(value.time.tv_sec == 1700000000);
    assert(value.time.tv_usec == 123456);

    value = blank_timex(0);
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_MONOTONIC, &value, 0) ==
           -EDGE_LINUX_EOPNOTSUPP);
    assert(kernel_time_discipline_adjust(10, &value, 0) ==
           -EDGE_LINUX_EINVAL);

    value = blank_timex(EDGE_LINUX_ADJ_TICK);
    value.tick = 899;
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_REALTIME, &value, 0) ==
           -EDGE_LINUX_EPERM);
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_REALTIME, &value, 1) ==
           -EDGE_LINUX_EINVAL);

    value = blank_timex(EDGE_LINUX_ADJ_FREQUENCY);
    value.frequency = 1000000000ll;
    result = kernel_time_discipline_adjust(
        LINUX_CLOCK_REALTIME, &value, 1);
    assert(result == EDGE_LINUX_TIME_ERROR);
    assert(value.frequency == 32768000ll);
    assert(g_frequency == 32768000ll);

    value = blank_timex(
        EDGE_LINUX_ADJ_STATUS | EDGE_LINUX_ADJ_OFFSET);
    value.status = EDGE_LINUX_STA_PLL;
    value.offset = 700000;
    result = kernel_time_discipline_adjust(
        LINUX_CLOCK_REALTIME, &value, 1);
    assert(result == EDGE_LINUX_TIME_OK);
    assert(g_last_adjustment == 500000);
    assert(g_last_immediate == 0);

    value = blank_timex(EDGE_LINUX_ADJ_NANO | EDGE_LINUX_ADJ_OFFSET);
    value.offset = 500000000;
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_REALTIME, &value, 1) == EDGE_LINUX_TIME_OK);
    assert(g_last_adjustment == 500000);

    value = blank_timex(EDGE_LINUX_ADJ_MAXERROR);
    value.maximum_error = -1;
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_REALTIME, &value, 1) == EDGE_LINUX_TIME_OK);
    assert(value.maximum_error == 0);

    value = blank_timex(EDGE_LINUX_ADJ_OFFSET_SINGLESHOT);
    value.offset = 999;
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_REALTIME, &value, 1) == EDGE_LINUX_TIME_OK);
    assert(value.offset == 123);
    assert(g_pending == 999);

    value = blank_timex(EDGE_LINUX_ADJ_OFFSET_SS_READ);
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_REALTIME, &value, 0) == EDGE_LINUX_TIME_OK);
    assert(value.offset == 999);

    value = blank_timex(EDGE_LINUX_ADJ_ADJTIME);
    value.offset = 555;
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_REALTIME, &value, 1) == EDGE_LINUX_TIME_OK);
    assert(value.offset == 999);
    assert(g_pending == 555);

    value = blank_timex(EDGE_LINUX_ADJ_SETOFFSET);
    value.time.tv_usec = -1;
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_REALTIME, &value, 1) ==
           -EDGE_LINUX_EINVAL);

    value = blank_timex(0x400000u);
    assert(kernel_time_discipline_adjust(
               LINUX_CLOCK_REALTIME, &value, 1) == EDGE_LINUX_TIME_OK);

    puts("time_discipline_unit: PASS");
    return 0;
}
