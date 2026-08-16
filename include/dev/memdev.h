/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef EDGEOS_DEV_MEMDEV_H
#define EDGEOS_DEV_MEMDEV_H

#include <stdint.h>

#define EDGE_MEMDEV_NOT_HANDLED (-4096)

int edge_memdev_read(uint64_t linux_rdev, void *buffer, uint32_t length);
int edge_memdev_write(uint64_t linux_rdev, const void *buffer, uint32_t length);
int edge_memdev_read_description(uint64_t linux_rdev,
    uint64_t description_identity, void *buffer, uint32_t length);
int edge_memdev_write_description(uint64_t linux_rdev,
    uint64_t description_identity, const void *buffer, uint32_t length);

#endif
