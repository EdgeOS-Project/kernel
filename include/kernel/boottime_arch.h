#ifndef KERNEL_BOOTTIME_ARCH_H
#define KERNEL_BOOTTIME_ARCH_H

#include <stdint.h>

/*
 * Architecture backends provide hardware clock mechanisms only. The shared
 * boottime runtime owns monotonicity, realtime offset, and public API policy.
 */
uint64_t kernel_arch_boottime_initialize(void);
uint64_t kernel_arch_boottime_monotonic_us(void);
void kernel_arch_boottime_timer_tick(uint32_t hz);
int kernel_arch_boottime_refine(uint64_t hz, uint64_t monotonic_floor_us);
uint64_t kernel_arch_boottime_source_hz(void);
const char *kernel_arch_boottime_source_name(void);
void kernel_arch_boottime_vdso_snapshot(uint64_t *cycle_last,
                                        uint64_t *monotonic_base_us,
                                        uint64_t *frequency);

#endif
