/* SPDX-License-Identifier: MPL-2.0 */
/* Shared block-publication backend for imported BSD storage drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_BLOCK_H
#define EDGEOS_COMPAT_FREEBSD_BLOCK_H

#include <stddef.h>
#include <stdint.h>

typedef int (*bsd_block_read_fn)(void *device_context, uint64_t lba,
    uint32_t sector_count, void *output);
typedef int (*bsd_block_write_fn)(void *device_context, uint64_t lba,
    uint32_t sector_count, const void *input);
typedef int (*bsd_block_flush_fn)(void *device_context);

typedef struct bsd_block_description {
    const char *name;
    uint32_t sector_size;
    uint64_t sector_count;
    uint32_t max_transfer_sectors;
    bsd_block_read_fn read;
    bsd_block_write_fn write;
    bsd_block_flush_fn flush;
    void *device_context;
} bsd_block_description_t;

typedef int (*bsd_block_publish_fn)(
    const bsd_block_description_t *description, void **publication,
    void *backend_context);
typedef int (*bsd_block_unpublish_fn)(void *publication,
    void *backend_context);
typedef int (*bsd_block_resize_fn)(void *publication,
    uint64_t sector_count, void *backend_context);

typedef struct bsd_block_backend_ops {
    bsd_block_publish_fn publish;
    bsd_block_unpublish_fn unpublish;
    bsd_block_resize_fn resize;
    void *context;
} bsd_block_backend_ops_t;

int bsd_block_initialize(const bsd_block_backend_ops_t *operations);
int bsd_block_ensure_initialized(void);
int bsd_block_is_initialized(void);

#endif
