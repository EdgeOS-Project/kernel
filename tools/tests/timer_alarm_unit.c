/* SPDX-License-Identifier: MPL-2.0 */
/* Deadline arbitration, tick phase, and deferred display publication tests. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "kernel/deferred_work.h"
#include "kernel/timer_alarm.h"
#include "kernel/timer_policy.h"

static kernel_timer_alarm_t cpus[2];
static unsigned int current_cpu, hook_calls;

void kernel_arch_display_deadline_request(uint64_t deadline_us) {
    ++hook_calls;
    kernel_timer_alarm_display(&cpus[current_cpu], deadline_us);
}

static void check_ordering(void) {
    kernel_timer_alarm_t alarm;
    kernel_timer_alarm_init(&alarm, 0u, 10000u, 0u);
    kernel_timer_alarm_display(&alarm, 4000u);
    kernel_timer_alarm_rseq(&alarm, 4005u);
    kernel_timer_alarm_display(&alarm, 7000u);
    assert(kernel_timer_alarm_next(&alarm) == 4000u);
    assert(kernel_timer_alarm_expire(&alarm, 3999u) == 0u);
    assert(kernel_timer_alarm_expire(&alarm, 4000u) == KERNEL_TIMER_ALARM_DISPLAY);
    assert(kernel_timer_alarm_next(&alarm) == 4005u);
    assert(alarm.periodic_deadline_us == 10000u);
    assert(kernel_timer_alarm_expire(&alarm, 4005u) == KERNEL_TIMER_ALARM_RSEQ);
    assert(kernel_timer_alarm_next(&alarm) == 10000u);

    kernel_timer_alarm_display(&alarm, 10000u);
    kernel_timer_alarm_rseq(&alarm, 10000u);
    assert(kernel_timer_alarm_expire(&alarm, 10000u) ==
           (KERNEL_TIMER_ALARM_PERIODIC | KERNEL_TIMER_ALARM_RSEQ |
            KERNEL_TIMER_ALARM_DISPLAY));
    assert(kernel_timer_alarm_next(&alarm) == 20000u);
    assert(kernel_timer_alarm_expire(&alarm, 10000u) == 0u);

    kernel_timer_alarm_rseq(&alarm, 12000u);
    kernel_timer_alarm_display(&alarm, 15000u);
    kernel_timer_alarm_rseq(&alarm, 0u);
    assert(kernel_timer_alarm_next(&alarm) == 15000u);
    assert(alarm.periodic_deadline_us == 20000u);
    kernel_timer_alarm_display(&alarm, 13000u);
    assert(kernel_timer_alarm_next(&alarm) == 13000u);
}

static void check_idle_and_phase(void) {
    kernel_timer_alarm_t alarm;
    kernel_timer_alarm_init(&alarm, 0u, 10000u, 2500u);
    kernel_timer_alarm_display(&alarm, 6000u);
    kernel_timer_alarm_rseq(&alarm, 5000u);
    kernel_timer_alarm_pause(&alarm);
    assert(kernel_timer_alarm_next(&alarm) == 5000u);
    assert(kernel_timer_alarm_expire(&alarm, 5000u) == KERNEL_TIMER_ALARM_RSEQ);
    assert(kernel_timer_alarm_next(&alarm) == 6000u);
    assert(kernel_timer_alarm_expire(&alarm, 6000u) == KERNEL_TIMER_ALARM_DISPLAY);
    assert(kernel_timer_alarm_next(&alarm) == 0u);
    kernel_timer_alarm_resume(&alarm, 30000u);
    assert(kernel_timer_alarm_next(&alarm) == 32500u);
    kernel_timer_alarm_resume(&alarm, 31000u);
    assert(kernel_timer_alarm_next(&alarm) == 32500u);
    assert(kernel_timer_alarm_expire(&alarm, 64500u) == KERNEL_TIMER_ALARM_PERIODIC);
    assert(kernel_timer_alarm_next(&alarm) == 72500u);
    assert(kernel_timer_alarm_expire(&alarm, 64500u) == 0u);

    /* The BSP's independent PIT is not duplicated by its APIC alarm source. */
    kernel_timer_alarm_init(&alarm, 0u, 0u, 0u);
    kernel_timer_alarm_resume(&alarm, 50000u);
    assert(kernel_timer_alarm_next(&alarm) == 0u);
    kernel_timer_alarm_display(&alarm, 50001u);
    assert(kernel_timer_alarm_expire(&alarm, 50001u) == KERNEL_TIMER_ALARM_DISPLAY);
    assert(kernel_timer_alarm_next(&alarm) == 0u);
}

static void check_periodic_accounting(void) {
    kernel_timer_alarm_t alarm;
    unsigned int accounting_ticks = 0u, watchdog_kicks = 0u;
    kernel_timer_alarm_init(&alarm, 0u, EDGE_KERNEL_TIMER_TICK_US, 0u);
    for (uint64_t time = 1000u; time <= 160000u; time += 1000u) {
        uint32_t events;
        kernel_timer_alarm_display(&alarm, time);
        kernel_timer_alarm_rseq(&alarm, time + 5u);
        events = kernel_timer_alarm_expire(&alarm, time);
        assert(events & KERNEL_TIMER_ALARM_DISPLAY);
        assert(!(events & KERNEL_TIMER_ALARM_RSEQ));
        if (events & KERNEL_TIMER_ALARM_PERIODIC) {
            ++accounting_ticks;
            if (accounting_ticks % 16u == 0u) ++watchdog_kicks;
        }
        assert(kernel_timer_alarm_expire(&alarm, time + 5u) == KERNEL_TIMER_ALARM_RSEQ);
    }
    assert(accounting_ticks == 16u && watchdog_kicks == 1u);
    assert(alarm.periodic_deadline_us == 170000u);
}

static void check_smp_publication(void) {
    kernel_timer_alarm_init(&cpus[0], 0u, 0u, 0u);
    kernel_timer_alarm_init(&cpus[1], 0u, 10000u, 2500u);
    current_cpu = 0u;
    kernel_display_deadline_request(8000u);
    assert(hook_calls == 1u && kernel_timer_alarm_next(&cpus[0]) == 8000u);
    current_cpu = 1u;
    kernel_display_deadline_request(4000u);
    kernel_display_deadline_request(9000u);
    assert(hook_calls == 2u && kernel_display_deadline() == 4000u);
    kernel_timer_alarm_pause(&cpus[1]);
    assert(kernel_timer_alarm_next(&cpus[1]) == 4000u);
    assert(!kernel_display_deadline_poll(3999u));
    assert(!kernel_display_work_pending());
    assert(kernel_timer_alarm_expire(&cpus[1], 4000u) == KERNEL_TIMER_ALARM_DISPLAY);
    assert(kernel_display_deadline_poll(4000u));
    assert(kernel_display_work_take());
    assert(!kernel_display_work_take());
    kernel_display_deadline_request(12000u);
    assert(kernel_timer_alarm_next(&cpus[1]) == 12000u);

    /* Another CPU's stale local alarm must not publish an early/fake frame. */
    assert(kernel_timer_alarm_expire(&cpus[0], 8000u) == KERNEL_TIMER_ALARM_DISPLAY);
    assert(!kernel_display_deadline_poll(8000u));
    assert(!kernel_display_work_pending());
    assert(kernel_display_deadline() == 12000u);
    assert(kernel_timer_alarm_expire(&cpus[1], 12000u) == KERNEL_TIMER_ALARM_DISPLAY);
    assert(kernel_display_deadline_poll(12000u));
    kernel_display_deadline_request(13000u);
    assert(kernel_display_work_take());
    assert(kernel_display_deadline() == 13000u);
    assert(kernel_display_deadline_poll(13000u));
    assert(kernel_display_work_take());
}

static void check_counts_and_overflow(void) {
    kernel_timer_alarm_t alarm;
    uint64_t random = 1u;
    assert(kernel_timer_alarm_counts(5u, 62500000u, UINT32_MAX) == 313u);
    assert(kernel_timer_alarm_counts(1u, 100000000u, UINT64_MAX) == 100u);
    assert(kernel_timer_alarm_counts(0u, 100000000u, UINT32_MAX) == 1u);
    assert(kernel_timer_alarm_counts(UINT64_MAX, UINT64_MAX, UINT32_MAX) == UINT32_MAX);
    for (unsigned int i = 0; i < 10000u; ++i) {
        uint64_t delta, frequency, limit, expected;
        __uint128_t wide;
        random = random * 6364136223846793005ull + 1u;
        delta = random;
        random = random * 6364136223846793005ull + 1u;
        frequency = random;
        limit = i & 1u ? UINT32_MAX : UINT64_MAX;
        wide = (__uint128_t)delta * frequency;
        wide = wide / 1000000u + (wide % 1000000u != 0u);
        expected = wide > limit ? limit : (uint64_t)wide;
        if (!expected && frequency) expected = 1u;
        assert(kernel_timer_alarm_counts(delta, frequency, limit) == expected);
    }
    kernel_timer_alarm_init(&alarm, UINT64_MAX - 5u, 10u, 0u);
    assert(kernel_timer_alarm_next(&alarm) == UINT64_MAX);
    assert(kernel_timer_alarm_expire(&alarm, UINT64_MAX) == KERNEL_TIMER_ALARM_PERIODIC);
    assert(kernel_timer_alarm_next(&alarm) == 0u);
}

static void check_wait_deadlines(void) {
    kernel_timer_alarm_t alarm;
    kernel_timer_alarm_init(&alarm, 0u, 10000u, 0u);
    kernel_timer_alarm_wait(&alarm, 500u);
    kernel_timer_alarm_wait(&alarm, 900u);
    kernel_timer_alarm_display(&alarm, 700u);
    kernel_timer_alarm_pause(&alarm);
    assert(kernel_timer_alarm_next(&alarm) == 500u);
    assert(kernel_timer_alarm_expire(&alarm, 499u) == 0u);
    assert(kernel_timer_alarm_expire(&alarm, 500u) == KERNEL_TIMER_ALARM_WAIT);
    assert(alarm.periodic_deadline_us == 10000u);
    assert(kernel_timer_alarm_next(&alarm) == 700u);
    kernel_timer_alarm_wait(&alarm, 900u);
    assert(kernel_timer_alarm_expire(&alarm, 700u) == KERNEL_TIMER_ALARM_DISPLAY);
    assert(kernel_timer_alarm_next(&alarm) == 900u);
    assert(kernel_timer_alarm_expire(&alarm, 900u) == KERNEL_TIMER_ALARM_WAIT);
    assert(kernel_timer_alarm_next(&alarm) == 0u);
    kernel_timer_alarm_resume(&alarm, 950u);
    assert(kernel_timer_alarm_next(&alarm) == 10000u);
}

int main(void) {
    check_wait_deadlines();
    check_ordering();
    check_idle_and_phase();
    check_periodic_accounting();
    check_smp_publication();
    check_counts_and_overflow();
    puts("timer_alarm_unit: PASS");
    return 0;
}
