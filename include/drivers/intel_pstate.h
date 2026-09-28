/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Intel HWP-backed P-State control.
 */

#ifndef EDGEOS_DRIVERS_INTEL_PSTATE_H
#define EDGEOS_DRIVERS_INTEL_PSTATE_H

#include <stdint.h>

int intel_pstate_init(void);
int intel_pstate_available(void);
uint32_t intel_pstate_lowest_perf(void);
uint32_t intel_pstate_highest_perf(void);

#endif
