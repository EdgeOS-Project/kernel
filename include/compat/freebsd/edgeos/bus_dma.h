/* SPDX-License-Identifier: MPL-2.0 */
/* Backend contract for the EdgeOS FreeBSD bus-DMA adapter. */

#ifndef EDGEOS_COMPAT_FREEBSD_BUS_DMA_H
#define EDGEOS_COMPAT_FREEBSD_BUS_DMA_H

#include <stddef.h>
#include <stdint.h>

typedef void *(*bsd_bus_dma_allocate_pages_fn)(uint64_t page_count,
    uint32_t flags, void *context);
typedef void (*bsd_bus_dma_release_pages_fn)(void *base, uint64_t page_count,
    void *context);
typedef int (*bsd_bus_dma_physical_address_fn)(const void *pointer,
    uint64_t *physical_address, void *context);
typedef int (*bsd_bus_dma_virtual_address_fn)(uint64_t physical_address,
    size_t length, void **virtual_address, void *context);
typedef int (*bsd_bus_dma_physical_override_fn)(const void *pointer,
    uint64_t *physical_address);
typedef void (*bsd_bus_dma_sync_fn)(void *buffer, size_t length, int operation,
    void *context);

typedef struct {
    bsd_bus_dma_allocate_pages_fn allocate_pages;
    bsd_bus_dma_release_pages_fn release_pages;
    bsd_bus_dma_physical_address_fn physical_address;
    bsd_bus_dma_virtual_address_fn virtual_address;
    bsd_bus_dma_sync_fn sync;
    void *context;
} bsd_bus_dma_ops_t;

int bsd_bus_dma_initialize(const bsd_bus_dma_ops_t *ops);
int bsd_bus_dma_is_initialized(void);
int bsd_bus_dma_ensure_initialized(void);
int bsd_bus_dma_physical_address(const void *pointer,
    uint64_t *physical_address);
int bsd_bus_dma_virtual_address(uint64_t physical_address, size_t length,
    void **virtual_address);
int bsd_bus_dma_register_physical_override(
    bsd_bus_dma_physical_override_fn function);

#endif
