/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux clock discipline policy. */

#include <stdint.h>

#include "kernel/arch_cpu.h"
#include "kernel/linux_errno.h"
#include "kernel/time_discipline.h"
#include "string.h"
#include "sys/boottime.h"

#define KERNEL_TIMEX_MAX_FREQUENCY 32768000ll
#define KERNEL_TIMEX_MAX_FREQUENCY_INPUT 140737488355ll
#define KERNEL_TIMEX_MAX_PHASE_US 500000ll
#define KERNEL_TIMEX_MAX_ERROR_US 16000000ll
#define KERNEL_TIMEX_MAX_CONSTANT 10ll
#define KERNEL_TIMEX_MAX_TAI 100000ll
#define KERNEL_TIMEX_NOMINAL_TICK_US 1000ll
#define KERNEL_TIMEX_MIN_TICK_US 900ll
#define KERNEL_TIMEX_MAX_TICK_US 1100ll

typedef struct kernel_time_discipline_state {
    int64_t frequency;
    int64_t maximum_error;
    int64_t estimated_error;
    int64_t constant;
    int64_t tick;
    int32_t status;
    int32_t tai;
} kernel_time_discipline_state_t;

static kernel_time_discipline_state_t g_time_discipline = {
    .maximum_error = KERNEL_TIMEX_MAX_ERROR_US,
    .estimated_error = KERNEL_TIMEX_MAX_ERROR_US,
    .tick = KERNEL_TIMEX_NOMINAL_TICK_US,
    .status = EDGE_LINUX_STA_UNSYNC,
};
static volatile uint32_t g_time_discipline_transaction;

static int64_t kernel_time_discipline_clamp(
    int64_t value, int64_t minimum, int64_t maximum) {
    if (value < minimum) return minimum;
    if (value > maximum) return maximum;
    return value;
}

static void kernel_time_discipline_lock(void) {
    while (__atomic_exchange_n(
               &g_time_discipline_transaction, 1u, __ATOMIC_ACQUIRE) != 0u)
        arch_cpu_relax();
}

static void kernel_time_discipline_unlock(void) {
    __atomic_store_n(
        &g_time_discipline_transaction, 0u, __ATOMIC_RELEASE);
}

static int kernel_time_discipline_clock_status(int32_t clock_id) {
    if (clock_id == LINUX_CLOCK_REALTIME) return 0;
    if (clock_id < 0 ||
        (clock_id >= LINUX_CLOCK_REALTIME &&
         clock_id <= LINUX_CLOCK_BOOTTIME_ALARM) ||
        clock_id == LINUX_CLOCK_TAI)
        return -EDGE_LINUX_EOPNOTSUPP;
    return -EDGE_LINUX_EINVAL;
}

static int kernel_time_discipline_state_code(int32_t status) {
    if (status & (EDGE_LINUX_STA_UNSYNC | EDGE_LINUX_STA_CLOCKERR))
        return EDGE_LINUX_TIME_ERROR;
    if (status & EDGE_LINUX_STA_INS) return EDGE_LINUX_TIME_INS;
    if (status & EDGE_LINUX_STA_DEL) return EDGE_LINUX_TIME_DEL;
    return EDGE_LINUX_TIME_OK;
}

static int kernel_time_discipline_setoffset(
    const edge_linux_timex_t *timex, int64_t *adjustment_us) {
    int64_t unit;
    int64_t seconds;
    int64_t fraction;

    if (!timex || !adjustment_us) return -EDGE_LINUX_EINVAL;
    unit = (timex->modes & EDGE_LINUX_ADJ_NANO) ? 1000000000ll : 1000000ll;
    seconds = timex->time.tv_sec;
    fraction = timex->time.tv_usec;
    if (fraction < 0 || fraction >= unit ||
        seconds > INT64_MAX / 1000000ll ||
        seconds < INT64_MIN / 1000000ll)
        return -EDGE_LINUX_EINVAL;
    *adjustment_us = seconds * 1000000ll +
        ((timex->modes & EDGE_LINUX_ADJ_NANO) ?
         fraction / 1000ll : fraction);
    return 0;
}

static void kernel_time_discipline_fill(
    edge_linux_timex_t *timex,
    const kernel_time_discipline_state_t *state) {
    uint64_t realtime = boottime_realtime_us();
    uint32_t modes = timex->modes;

    memset(timex, 0, sizeof(*timex));
    timex->modes = modes;
    timex->offset = boottime_pending_adjustment_us();
    timex->frequency = state->frequency;
    timex->maximum_error = state->maximum_error;
    timex->estimated_error = state->estimated_error;
    timex->status = state->status;
    timex->constant = state->constant;
    timex->precision = 1;
    timex->tolerance = KERNEL_TIMEX_MAX_FREQUENCY;
    timex->time.tv_sec = (int64_t)(realtime / 1000000u);
    timex->time.tv_usec = (int64_t)(realtime % 1000000u);
    if (state->status & EDGE_LINUX_STA_NANO)
        timex->time.tv_usec *= 1000ll;
    timex->tick = state->tick;
    timex->tai = state->tai;
}

static int64_t kernel_time_discipline_effective_frequency(void) {
    int64_t tick_frequency =
        (g_time_discipline.tick - KERNEL_TIMEX_NOMINAL_TICK_US) *
        65536000ll;

    return g_time_discipline.frequency + tick_frequency;
}

int kernel_time_discipline_adjust(
    int32_t clock_id, edge_linux_timex_t *timex, int privileged) {
    uint32_t modes;
    int64_t adjustment = 0;
    int64_t effective_frequency;
    int64_t previous_adjustment = 0;
    int clock_status;
    int old_adjustment_mode;
    int read_only_adjustment;
    int state_code;

    if (!timex) return -EDGE_LINUX_EFAULT;
    clock_status = kernel_time_discipline_clock_status(clock_id);
    if (clock_status < 0) return clock_status;
    modes = timex->modes;
    old_adjustment_mode = (modes & EDGE_LINUX_ADJ_ADJTIME) != 0;
    read_only_adjustment = old_adjustment_mode &&
        (modes & EDGE_LINUX_ADJ_OFFSET_READONLY) != 0;
    if (old_adjustment_mode) {
        if (!read_only_adjustment && !privileged)
            return -EDGE_LINUX_EPERM;
        adjustment = timex->offset;
    } else {
        if (modes && !privileged) return -EDGE_LINUX_EPERM;
        if ((modes & EDGE_LINUX_ADJ_FREQUENCY) &&
            (timex->frequency < -KERNEL_TIMEX_MAX_FREQUENCY_INPUT ||
             timex->frequency > KERNEL_TIMEX_MAX_FREQUENCY_INPUT))
            return -EDGE_LINUX_EINVAL;
        if ((modes & EDGE_LINUX_ADJ_TICK) &&
            (timex->tick < KERNEL_TIMEX_MIN_TICK_US ||
             timex->tick > KERNEL_TIMEX_MAX_TICK_US))
            return -EDGE_LINUX_EINVAL;
        if (modes & EDGE_LINUX_ADJ_SETOFFSET) {
            int status = kernel_time_discipline_setoffset(
                timex, &adjustment);
            if (status < 0) return status;
        }
    }

    kernel_time_discipline_lock();
    if (old_adjustment_mode) {
        previous_adjustment = boottime_pending_adjustment_us();
        if (!read_only_adjustment &&
            boottime_set_pending_adjustment_us(adjustment) < 0) {
            kernel_time_discipline_unlock();
            return -EDGE_LINUX_EINVAL;
        }
    } else {
        if ((modes & EDGE_LINUX_ADJ_SETOFFSET) &&
            boottime_adjust_realtime_us(adjustment, 1) < 0) {
            kernel_time_discipline_unlock();
            return -EDGE_LINUX_EINVAL;
        }
        if (modes & EDGE_LINUX_ADJ_MAXERROR)
            g_time_discipline.maximum_error =
                kernel_time_discipline_clamp(
                    timex->maximum_error, 0,
                    KERNEL_TIMEX_MAX_ERROR_US);
        if (modes & EDGE_LINUX_ADJ_ESTERROR)
            g_time_discipline.estimated_error =
                kernel_time_discipline_clamp(
                    timex->estimated_error, 0,
                    KERNEL_TIMEX_MAX_ERROR_US);
        if (modes & EDGE_LINUX_ADJ_STATUS)
            g_time_discipline.status =
                (g_time_discipline.status & EDGE_LINUX_STA_READONLY) |
                (timex->status & ~EDGE_LINUX_STA_READONLY);
        if (modes & EDGE_LINUX_ADJ_NANO)
            g_time_discipline.status |= EDGE_LINUX_STA_NANO;
        if (modes & EDGE_LINUX_ADJ_MICRO)
            g_time_discipline.status &= ~EDGE_LINUX_STA_NANO;
        if (modes & EDGE_LINUX_ADJ_TIMECONST) {
            g_time_discipline.constant = kernel_time_discipline_clamp(
                timex->constant, 0, KERNEL_TIMEX_MAX_CONSTANT);
            if (!(g_time_discipline.status & EDGE_LINUX_STA_NANO))
                g_time_discipline.constant =
                    kernel_time_discipline_clamp(
                        g_time_discipline.constant + 4, 0,
                        KERNEL_TIMEX_MAX_CONSTANT);
        }
        if ((modes & EDGE_LINUX_ADJ_TAI) && timex->constant >= 0 &&
            timex->constant <= KERNEL_TIMEX_MAX_TAI)
            g_time_discipline.tai = (int32_t)timex->constant;
        if (modes & EDGE_LINUX_ADJ_TICK)
            g_time_discipline.tick = timex->tick;
        if (modes & EDGE_LINUX_ADJ_FREQUENCY)
            g_time_discipline.frequency = kernel_time_discipline_clamp(
                timex->frequency, -KERNEL_TIMEX_MAX_FREQUENCY,
                KERNEL_TIMEX_MAX_FREQUENCY);
        if (modes & (EDGE_LINUX_ADJ_FREQUENCY | EDGE_LINUX_ADJ_TICK)) {
            effective_frequency =
                kernel_time_discipline_effective_frequency();
            (void)boottime_set_frequency_scaled_ppm(effective_frequency);
        }
        if ((modes & EDGE_LINUX_ADJ_OFFSET) &&
            (g_time_discipline.status & EDGE_LINUX_STA_PLL)) {
            adjustment = timex->offset;
            if (g_time_discipline.status & EDGE_LINUX_STA_NANO)
                adjustment /= 1000ll;
            adjustment = kernel_time_discipline_clamp(
                adjustment, -KERNEL_TIMEX_MAX_PHASE_US,
                KERNEL_TIMEX_MAX_PHASE_US);
            (void)boottime_adjust_realtime_us(adjustment, 0);
        }
    }
    kernel_time_discipline_fill(timex, &g_time_discipline);
    if (old_adjustment_mode)
        timex->offset = previous_adjustment;
    state_code = kernel_time_discipline_state_code(
        g_time_discipline.status);
    kernel_time_discipline_unlock();
    return state_code;
}
