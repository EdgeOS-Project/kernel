/* SPDX-License-Identifier: MPL-2.0 */
/* Shared kernel timer cadence used by every supported architecture. */

#ifndef EDGEOS_KERNEL_TIMER_POLICY_H
#define EDGEOS_KERNEL_TIMER_POLICY_H

/*
 * Keep the periodic scheduler tick at 100 Hz.  EdgeOS still executes a
 * substantial compatibility and device-service path from each timer event,
 * so increasing the periodic rate multiplies CPU overhead on every online
 * CPU.  Interactive wakeups and display completion use explicit reschedule
 * notifications; they must not depend on a faster polling tick.
 */
#define EDGE_KERNEL_TIMER_HZ 100u
#define EDGE_KERNEL_TIMER_TICK_US (1000000u / EDGE_KERNEL_TIMER_HZ)
#define EDGE_KERNEL_TIMER_20MS_TICKS \
    ((EDGE_KERNEL_TIMER_HZ + 49u) / 50u)
#define EDGE_KERNEL_TIMER_50MS_TICKS \
    ((EDGE_KERNEL_TIMER_HZ + 19u) / 20u)
#define EDGE_KERNEL_TIMER_100MS_TICKS \
    ((EDGE_KERNEL_TIMER_HZ + 9u) / 10u)
#define EDGE_KERNEL_TIMER_500MS_TICKS \
    ((EDGE_KERNEL_TIMER_HZ + 1u) / 2u)

/* Per-CPU scheduler accounting runs everywhere; global device time runs once. */
static inline int edge_kernel_timer_runs_global_work(unsigned int cpu) {
    return cpu == 0u;
}

#endif
