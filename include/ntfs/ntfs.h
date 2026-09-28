/*
 * EdgeOS NTFS filesystem support.
 *
 * Copyright (c) EdgeOS Contributors.
 * Licensed under the Mozilla Public License, v. 2.0.
 */
#ifndef EDGEOS_NTFS_H
#define EDGEOS_NTFS_H

#include "block/block.h"

int ntfs_mount(const char *dev, const char *target);
int ntfs_mount_block(block_device_t *bdev, const char *target);

#endif
