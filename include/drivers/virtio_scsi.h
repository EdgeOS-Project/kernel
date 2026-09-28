/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef DRIVERS_VIRTIO_SCSI_H
#define DRIVERS_VIRTIO_SCSI_H

#include <stdint.h>

#define VIRTIO_SCSI_PASSTHROUGH_MAX_DATA (2u * 1024u * 1024u)
#define VIRTIO_SCSI_PASSTHROUGH_MAX_CDB 32u
#define VIRTIO_SCSI_PASSTHROUGH_MAX_SENSE 96u

typedef struct virtio_scsi_passthrough_result {
    uint32_t residual_length;
    uint8_t device_status;
    uint8_t driver_status;
    uint8_t host_status;
    uint8_t sense_length;
    uint8_t sense[VIRTIO_SCSI_PASSTHROUGH_MAX_SENSE];
} virtio_scsi_passthrough_result_t;

int virtio_scsi_init(void);
int virtio_scsi_present(void);
uint32_t virtio_scsi_sector_size(void);
uint32_t virtio_scsi_sector_count(void);
int virtio_scsi_read(uint32_t lba, uint32_t sector_count, void *buf);
int virtio_scsi_write(uint32_t lba, uint32_t sector_count, const void *buf);
int virtio_scsi_passthrough(
    const uint8_t *cdb, uint32_t cdb_length, void *data,
    uint32_t data_length, int data_in, uint32_t timeout_milliseconds,
    virtio_scsi_passthrough_result_t *result);

#endif
