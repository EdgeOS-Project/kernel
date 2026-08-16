/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef DRIVERS_VIRTIO_SCSI_H
#define DRIVERS_VIRTIO_SCSI_H

#include <stdint.h>

int virtio_scsi_init(void);
int virtio_scsi_present(void);
uint32_t virtio_scsi_sector_size(void);
uint32_t virtio_scsi_sector_count(void);
int virtio_scsi_read(uint32_t lba, uint32_t sector_count, void *buf);
int virtio_scsi_write(uint32_t lba, uint32_t sector_count, const void *buf);

#endif
