/* SPDX-License-Identifier: MPL-2.0 */

#ifndef EDGEOS_FS_XFS_H
#define EDGEOS_FS_XFS_H

#include "block/block.h"

int xfs_mount(const char *device, const char *target);
int xfs_mount_block(block_device_t *device, const char *target);

#endif
