/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef DRIVERS_VIRTIO_BLK_H
#define DRIVERS_VIRTIO_BLK_H

#include <stdint.h>

int virtio_blk_init(void);
int virtio_blk_present(void);
uint32_t virtio_blk_sector_size(void);
uint32_t virtio_blk_sector_count(void);
int virtio_blk_read(uint32_t lba, uint32_t sector_count, void *buf);
int virtio_blk_write(uint32_t lba, uint32_t sector_count, const void *buf);

#endif
