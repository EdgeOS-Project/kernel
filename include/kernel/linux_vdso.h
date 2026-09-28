/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_LINUX_VDSO_H
#define EDGEOS_KERNEL_LINUX_VDSO_H

#include <stdint.h>

uint64_t linux_vdso_map(uint64_t address_space);
void linux_vdso_time_update(uint64_t cycle_last,
                            uint64_t monotonic_base_us,
                            uint64_t realtime_offset_us,
                            uint64_t frequency,
                            uint64_t discipline_anchor_us,
                            int64_t frequency_scaled_ppm,
                            int64_t pending_adjustment_us);

#endif
