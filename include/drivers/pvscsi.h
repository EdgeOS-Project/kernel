/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 VMware, Inc.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_PVSCSI_H
#define EDGEOS_DRIVERS_PVSCSI_H

#include <stdint.h>

int pvscsi_init(void);
int pvscsi_present(void);
uint32_t pvscsi_sector_size(void);
uint32_t pvscsi_sector_count(void);
int pvscsi_read(uint32_t lba, uint32_t sector_count, void *buf);
int pvscsi_write(uint32_t lba, uint32_t sector_count, const void *buf);

#endif
