/*
 * EdgeOS ISO9660 filesystem support.
 *
 * Copyright (c) EdgeOS Contributors.
 * Licensed under the Mozilla Public License, v. 2.0.
 */
#ifndef ISO9660_ISO9660_H
#define ISO9660_ISO9660_H

#include "block/block.h"

int iso9660_mount(const char *dev, const char *target);
int iso9660_mount_block(block_device_t *bdev, const char *target);

#endif
