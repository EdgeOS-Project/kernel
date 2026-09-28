/* SPDX-License-Identifier: MPL-2.0 */
/* Per-CPU clock-event arbitration. Callers serialize with local IRQ masking. */
#ifndef EDGEOS_KERNEL_TIMER_ALARM_H
#define EDGEOS_KERNEL_TIMER_ALARM_H

#include <stdint.h>

#define KERNEL_TIMER_ALARM_PERIODIC (1u << 0)
#define KERNEL_TIMER_ALARM_RSEQ (1u << 1)
#define KERNEL_TIMER_ALARM_DISPLAY (1u << 2)
#define KERNEL_TIMER_ALARM_WAIT (1u << 3)

typedef struct kernel_timer_alarm {
    uint64_t period_us;
    uint64_t periodic_deadline_us;
    uint64_t rseq_deadline_us;
    uint64_t display_deadline_us;
    uint64_t wait_deadline_us;
    uint8_t periodic_enabled;
} kernel_timer_alarm_t;

static inline uint64_t kernel_timer_alarm_add(uint64_t base, uint64_t delta) {
    return delta > UINT64_MAX - base ? UINT64_MAX : base + delta;
}

static inline uint64_t kernel_timer_alarm_min(uint64_t first, uint64_t second) {
    if (!first) return second;
    if (!second) return first;
    return first < second ? first : second;
}

static inline void kernel_timer_alarm_init(kernel_timer_alarm_t *alarm,
                                           uint64_t now_us, uint64_t period_us,
                                           uint64_t phase_us) {
    alarm->period_us = period_us;
    alarm->periodic_deadline_us = period_us ? kernel_timer_alarm_add(
        kernel_timer_alarm_add(now_us, period_us), phase_us) : 0u;
    alarm->periodic_enabled = period_us != 0u;
    alarm->rseq_deadline_us = 0u;
    alarm->display_deadline_us = 0u;
    alarm->wait_deadline_us = 0u;
}

static inline uint64_t kernel_timer_alarm_next(const kernel_timer_alarm_t *alarm) {
    return kernel_timer_alarm_min(
        alarm->periodic_enabled ? alarm->periodic_deadline_us : 0u,
        kernel_timer_alarm_min(alarm->rseq_deadline_us,
            kernel_timer_alarm_min(alarm->display_deadline_us,
                alarm->wait_deadline_us)));
}

static inline void kernel_timer_alarm_display(kernel_timer_alarm_t *alarm,
                                              uint64_t deadline_us) {
    alarm->display_deadline_us = kernel_timer_alarm_min(
        alarm->display_deadline_us, deadline_us);
}

static inline void kernel_timer_alarm_wait(kernel_timer_alarm_t *alarm,
                                           uint64_t deadline_us) {
    alarm->wait_deadline_us = kernel_timer_alarm_min(
        alarm->wait_deadline_us, deadline_us);
}

static inline void kernel_timer_alarm_rseq(kernel_timer_alarm_t *alarm,
                                           uint64_t deadline_us) {
    alarm->rseq_deadline_us = deadline_us;
}

static inline void kernel_timer_alarm_pause(kernel_timer_alarm_t *alarm) {
    /* Idle may suppress accounting ticks, never a display, wait, or rseq alarm. */
    alarm->periodic_enabled = 0u;
}

static inline void kernel_timer_alarm_forward_period(kernel_timer_alarm_t *alarm,
                                                     uint64_t now_us) {
    uint64_t delta;
    if (!alarm->period_us || !alarm->periodic_deadline_us ||
        alarm->periodic_deadline_us > now_us)
        return;
    /* Keep the original phase instead of moving the next tick after an IRQ. */
    delta = alarm->period_us -
        (now_us - alarm->periodic_deadline_us) % alarm->period_us;
    alarm->periodic_deadline_us = kernel_timer_alarm_add(now_us, delta);
    if (alarm->periodic_deadline_us <= now_us) {
        alarm->periodic_deadline_us = 0u;
        alarm->periodic_enabled = 0u;
    }
}

static inline void kernel_timer_alarm_resume(kernel_timer_alarm_t *alarm,
                                             uint64_t now_us) {
    if (alarm->periodic_enabled || !alarm->period_us) return;
    /* No catch-up accounting for time spent in tickless secondary idle. */
    kernel_timer_alarm_forward_period(alarm, now_us);
    alarm->periodic_enabled = alarm->periodic_deadline_us != 0u;
}

static inline uint32_t kernel_timer_alarm_expire(kernel_timer_alarm_t *alarm,
                                                uint64_t now_us) {
    uint32_t events = 0u;
    if (alarm->periodic_enabled && alarm->periodic_deadline_us &&
        now_us >= alarm->periodic_deadline_us) {
        events |= KERNEL_TIMER_ALARM_PERIODIC;
        kernel_timer_alarm_forward_period(alarm, now_us);
    }
    if (alarm->rseq_deadline_us && now_us >= alarm->rseq_deadline_us) {
        events |= KERNEL_TIMER_ALARM_RSEQ;
        alarm->rseq_deadline_us = 0u;
    }
    if (alarm->display_deadline_us && now_us >= alarm->display_deadline_us) {
        events |= KERNEL_TIMER_ALARM_DISPLAY;
        alarm->display_deadline_us = 0u;
    }
    if (alarm->wait_deadline_us && now_us >= alarm->wait_deadline_us) {
        events |= KERNEL_TIMER_ALARM_WAIT;
        alarm->wait_deadline_us = 0u;
    }
    return events;
}

/* Round up and saturate without overflowing a 64-bit intermediate product. */
static inline uint64_t kernel_timer_alarm_counts(uint64_t delta_us,
                                                uint64_t frequency,
                                                uint64_t limit) {
    uint64_t seconds = delta_us / 1000000u;
    uint64_t fraction = delta_us % 1000000u;
    uint64_t whole;
    uint64_t tail;
    uint64_t remainder;
    if (!frequency || !limit) return 0u;
    if (seconds > limit / frequency) return limit;
    whole = seconds * frequency;
    tail = fraction * (frequency / 1000000u);
    remainder = (fraction * (frequency % 1000000u) + 999999u) / 1000000u;
    if (tail > limit - whole) return limit;
    whole += tail;
    if (remainder > limit - whole) return limit;
    whole += remainder;
    return whole ? whole : 1u;
}

#endif
