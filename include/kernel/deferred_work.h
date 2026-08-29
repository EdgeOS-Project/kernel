/* SPDX-License-Identifier: MPL-2.0 */
#ifndef KERNEL_DEFERRED_WORK_H
#define KERNEL_DEFERRED_WORK_H

#include <stdint.h>

#define KERNEL_DEFERRED_WORK_GENERAL (1u << 0)
#define KERNEL_DEFERRED_WORK_DISPLAY (1u << 1)
#define KERNEL_DEFERRED_WORK_INPUT (1u << 2)

/*
 * Architecture interrupt paths publish work here and scheduler context
 * consumes it.  The latch intentionally coalesces repeated notifications:
 * one bounded worker turn services every subsystem before userspace resumes.
 */
void kernel_deferred_work_request(void);
int kernel_deferred_work_pending(void);
int kernel_deferred_work_take(void);
int kernel_deferred_work_tick(uint32_t interval_ticks);

/* Display cadence is independent from the slower general worker cadence. */
void kernel_display_work_request(void);
int kernel_display_work_pending(void);
int kernel_display_work_take(void);

/* Arm a precise wakeup for display work without raising the base timer rate. */
void kernel_display_deadline_request(uint64_t deadline_us);
uint64_t kernel_display_deadline(void);
int kernel_display_deadline_poll(uint64_t now_us);

/* Input wakeups are latency-sensitive and may be serviced by any CPU. */
void kernel_input_work_request(void);
int kernel_input_work_pending(void);
int kernel_input_work_take(void);

/* Wake architecture scheduler context after an idle-to-pending transition. */
void kernel_arch_input_work_request(void);

/* General work remains on the bootstrap CPU; display and input do not. */
int kernel_deferred_work_service_pending(uint32_t cpu_id);

/*
 * Snapshot all independent work classes without allowing one class to hide
 * or consume another. Callers service INPUT and DISPLAY before GENERAL.
 */
uint32_t kernel_deferred_work_take_ready(void);

#endif
