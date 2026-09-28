/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux clock discipline policy. */

#ifndef EDGEOS_KERNEL_TIME_DISCIPLINE_H
#define EDGEOS_KERNEL_TIME_DISCIPLINE_H

#include "kernel/linux_abi.h"

int kernel_time_discipline_adjust(
    int32_t clock_id, edge_linux_timex_t *timex, int privileged);

#endif
