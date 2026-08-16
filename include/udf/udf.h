/*
 * EdgeOS UDF filesystem support.
 *
 * Copyright (c) EdgeOS Contributors.
 * Licensed under the Mozilla Public License, v. 2.0.
 */
#ifndef EDGEOS_UDF_H
#define EDGEOS_UDF_H

#include "block/block.h"

int udf_mount(const char *dev, const char *target);
int udf_mount_block(block_device_t *bdev, const char *target);

#endif
