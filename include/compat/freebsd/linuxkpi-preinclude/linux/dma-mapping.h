/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS LinuxKPI DMA extensions. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_DMA_MAPPING_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_DMA_MAPPING_H_

#include_next <linux/dma-mapping.h>

static inline void *
dma_alloc_noncoherent(struct device *dev, size_t size,
    dma_addr_t *dma_handle, enum dma_data_direction direction, gfp_t flag)
{
    /* Supported EdgeOS platforms expose a coherent DMA domain. */
    (void)direction;
    return dma_alloc_coherent(dev, size, dma_handle, flag);
}

static inline void
dma_free_noncoherent(struct device *dev, size_t size, void *cpu_addr,
    dma_addr_t dma_addr, enum dma_data_direction direction)
{
    (void)direction;
    dma_free_coherent(dev, size, cpu_addr, dma_addr);
}

#endif
