/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side regression tests for realtime clock jumps and timerfd state. */

#include "kernel/linux_errno.h"
#include "kernel/timerfd.h"
#include "sys/boottime.h"

#include <assert.h>
#include <stdio.h>

static uint64_t g_monotonic_us = 1000000u;
static int g_notifications[8];
static int g_notification_count;

uint64_t kernel_arch_boottime_initialize(void) {
    return 5000000u;
}
uint64_t kernel_arch_boottime_monotonic_us(void) {
    return g_monotonic_us;
}
void kernel_arch_boottime_timer_tick(uint32_t hz) { (void)hz; }
int kernel_arch_boottime_refine(uint64_t hz, uint64_t floor_us) {
    (void)hz;
    (void)floor_us;
    return 0;
}
uint64_t kernel_arch_boottime_source_hz(void) {
    return 1000000u;
}
const char *kernel_arch_boottime_source_name(void) {
    return "test";
}
void kernel_timerfd_state_changed(int timer_id) {
    assert(g_notification_count < 8);
    g_notifications[g_notification_count++] = timer_id;
}
static linux_itimerspec64_t absolute_timer(int64_t seconds) {
    linux_itimerspec64_t value = {0};
    value.it_value.tv_sec = seconds;
    return value;
}

static linux_itimerspec64_t relative_timer(int64_t seconds) {
    return absolute_timer(seconds);
}

int main(void) {
    kernel_timerfd_state_t state;
    linux_itimerspec64_t current;
    linux_itimerspec64_t value;
    uint64_t deadline;
    uint64_t sequence;
    int cancel_timer, realtime_timer, alarm_timer, monotonic_timer;
    int relative_timerfd, relative_alarm_timerfd;

    boottime_init();
    cancel_timer = kernel_timerfd_create(LINUX_CLOCK_REALTIME);
    realtime_timer = kernel_timerfd_create(LINUX_CLOCK_REALTIME);
    alarm_timer = kernel_timerfd_create(LINUX_CLOCK_REALTIME_ALARM);
    monotonic_timer = kernel_timerfd_create(LINUX_CLOCK_MONOTONIC);
    relative_timerfd = kernel_timerfd_create(LINUX_CLOCK_REALTIME);
    relative_alarm_timerfd =
        kernel_timerfd_create(LINUX_CLOCK_REALTIME_ALARM);
    assert(cancel_timer >= 0 && realtime_timer >= 0 &&
           alarm_timer >= 0 && monotonic_timer >= 0 &&
           relative_timerfd >= 0 && relative_alarm_timerfd >= 0);
    assert(kernel_timerfd_query(cancel_timer, &state) == 0);
    assert(state.readiness_sequence != 0);
    sequence = state.readiness_sequence;

    value = absolute_timer(8);
    assert(kernel_timerfd_settime(
               cancel_timer, KERNEL_TIMERFD_TIMER_ABSTIME |
                                 KERNEL_TIMERFD_TIMER_CANCEL_ON_SET,
               &value, 0) == 0);
    assert(kernel_timerfd_query(cancel_timer, &state) == 0);
    assert(state.readiness_sequence == sequence);
    assert(kernel_timerfd_settime(
               realtime_timer, KERNEL_TIMERFD_TIMER_ABSTIME,
               &value, 0) == 0);
    value = absolute_timer(9);
    assert(kernel_timerfd_settime(
               alarm_timer, KERNEL_TIMERFD_TIMER_ABSTIME,
               &value, 0) == 0);
    value = absolute_timer(4);
    assert(kernel_timerfd_settime(
               monotonic_timer, KERNEL_TIMERFD_TIMER_ABSTIME,
               &value, 0) == 0);
    value = relative_timer(10);
    assert(kernel_timerfd_settime(relative_timerfd, 0, &value, 0) == 0);
    assert(kernel_timerfd_settime(
               relative_alarm_timerfd, 0, &value, 0) == 0);
    assert(kernel_timerfd_query(relative_timerfd, &state) == 0);
    assert(state.deadline_is_monotonic);
    assert(kernel_timerfd_monotonic_deadline(&state, &deadline) == 0);
    assert(deadline == 11000000u);

    assert(boottime_set_realtime_us(7000000u) == 0);
    assert(g_notification_count == 3);
    assert(g_notifications[0] == cancel_timer);
    assert(g_notifications[1] == realtime_timer);
    assert(g_notifications[2] == alarm_timer);
    assert(kernel_timerfd_query(cancel_timer, &state) == 0);
    assert(state.canceled && state.expirations == 0);
    assert(state.readiness_sequence == sequence + 1u);
    sequence = state.readiness_sequence;
    assert(kernel_timerfd_read(cancel_timer, 0, 0, 0) ==
           -EDGE_LINUX_ECANCELED);
    assert(kernel_timerfd_read(cancel_timer, 0, 0, 0) ==
           -EDGE_LINUX_EAGAIN);
    assert(kernel_timerfd_query(cancel_timer, &state) == 0);
    assert(!state.canceled);
    assert(state.readiness_sequence == sequence);
    assert(kernel_timerfd_gettime(relative_timerfd, &current) == 0);
    assert(current.it_value.tv_sec == 10 && current.it_value.tv_nsec == 0);
    assert(kernel_timerfd_gettime(relative_alarm_timerfd, &current) == 0);
    assert(current.it_value.tv_sec == 10 && current.it_value.tv_nsec == 0);

    assert(kernel_timerfd_gettime(realtime_timer, &current) == 0);
    assert(current.it_value.tv_sec == 1 && current.it_value.tv_nsec == 0);
    g_notification_count = 0;
    assert(boottime_set_realtime_us(6000000u) == 0);
    assert(g_notification_count == 2);
    assert(kernel_timerfd_gettime(realtime_timer, &current) == 0);
    assert(current.it_value.tv_sec == 2 && current.it_value.tv_nsec == 0);
    assert(kernel_timerfd_gettime(relative_timerfd, &current) == 0);
    assert(current.it_value.tv_sec == 10 && current.it_value.tv_nsec == 0);

    g_notification_count = 0;
    assert(boottime_set_realtime_us(10000000u) == 0);
    assert(g_notification_count == 2);
    assert(kernel_timerfd_query(realtime_timer, &state) == 0);
    assert(state.expirations == 1 && !state.canceled);
    assert(state.readiness_sequence > 1u);
    assert(kernel_timerfd_query(alarm_timer, &state) == 0);
    assert(state.expirations == 1 && !state.canceled);
    assert(kernel_timerfd_gettime(relative_alarm_timerfd, &current) == 0);
    assert(current.it_value.tv_sec == 10 && current.it_value.tv_nsec == 0);
    g_monotonic_us = 11000000u;
    assert(kernel_timerfd_query(relative_timerfd, &state) == 0);
    assert(state.expirations == 1 && !state.canceled);
    sequence = state.readiness_sequence;
    value = relative_timer(0);
    assert(kernel_timerfd_settime(relative_timerfd, 0, &value, 0) == 0);
    assert(kernel_timerfd_query(relative_timerfd, &state) == 0);
    assert(state.expirations == 0 && !state.canceled);
    assert(state.readiness_sequence == sequence + 1u);
    assert(kernel_timerfd_query(relative_alarm_timerfd, &state) == 0);
    assert(state.expirations == 1 && !state.canceled);

    printf("timerfd_realtime_jump_unit: PASS\n");
    return 0;
}
