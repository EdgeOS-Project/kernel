/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS BSD Driver Bridge allocator interface. */

#ifndef EDGEOS_COMPAT_FREEBSD_ALLOCATOR_H
#define EDGEOS_COMPAT_FREEBSD_ALLOCATOR_H

#include <stddef.h>
#include <stdint.h>

#define BSD_M_NOWAIT 0x0001u
#define BSD_M_WAITOK 0x0002u
#define BSD_M_ZERO 0x0100u

typedef void *(*bsd_allocator_allocate_pages_fn)(uint64_t page_count,
                                                 void *context);
typedef void (*bsd_allocator_release_pages_fn)(void *base,
                                               uint64_t page_count,
                                               void *context);
typedef int (*bsd_allocator_wait_fn)(void *context);

typedef struct {
    bsd_allocator_allocate_pages_fn allocate_pages;
    bsd_allocator_release_pages_fn release_pages;
    bsd_allocator_wait_fn wait_for_memory;
    void *context;
} bsd_allocator_ops_t;

typedef struct {
    uint64_t bytes_in_use;
    uint64_t peak_bytes_in_use;
    uint64_t allocation_count;
    uint64_t free_count;
    uint64_t failed_allocation_count;
    uint32_t active_arenas;
} bsd_allocator_stats_t;

int bsd_allocator_initialize(const bsd_allocator_ops_t *ops);
int bsd_allocator_is_initialized(void);
void bsd_allocator_get_stats(bsd_allocator_stats_t *stats);

void *bsd_kmalloc(size_t size, uint32_t flags);
void *bsd_kmallocarray(size_t count, size_t size, uint32_t flags);
void *bsd_krealloc(void *allocation, size_t size, uint32_t flags);
void bsd_kfree(void *allocation);
size_t bsd_kmalloc_usable_size(const void *allocation);
int bsd_allocator_wait_for_memory(void);

#endif
