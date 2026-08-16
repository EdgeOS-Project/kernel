/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS SquashFS VFS adapter. */

#ifndef EDGEOS_FS_SQUASHFS_H
#define EDGEOS_FS_SQUASHFS_H

#include "block/block.h"

int squashfs_mount(const char *device, const char *target);
int squashfs_mount_block(block_device_t *device, const char *target);

#endif
