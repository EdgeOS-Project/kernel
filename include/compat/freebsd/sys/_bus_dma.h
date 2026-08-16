/* SPDX-License-Identifier: BSD-2-Clause */
/* Common FreeBSD bus-DMA opaque types used by the EdgeOS bridge. */

#ifndef _SYS__BUS_DMA_H_
#define _SYS__BUS_DMA_H_

typedef int bus_dmasync_op_t;
typedef struct bus_dma_tag *bus_dma_tag_t;
typedef struct bus_dmamap *bus_dmamap_t;

typedef enum {
    BUS_DMA_LOCK = 0x01,
    BUS_DMA_UNLOCK = 0x02,
} bus_dma_lock_op_t;

typedef void bus_dma_lock_t(void *, bus_dma_lock_op_t);

#endif
