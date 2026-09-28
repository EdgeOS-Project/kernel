/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS LinuxKPI DMA ordering barriers. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_ASM_BARRIER_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_ASM_BARRIER_H_

#include_next <asm/barrier.h>

#define dma_mb() smp_mb()
#define dma_wmb() smp_wmb()
#define dma_rmb() smp_rmb()

#endif
