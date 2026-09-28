/*
 * EdgeOS exFAT filesystem support.
 *
 * Copyright (c) EdgeOS Contributors.
 * Licensed under the Mozilla Public License, v. 2.0.
 */
#ifndef EDGEOS_EXFAT_H
#define EDGEOS_EXFAT_H

#include "block/block.h"

int exfat_mount(const char *dev, const char *target);
int exfat_mount_block(block_device_t *bdev, const char *target);

#endif
