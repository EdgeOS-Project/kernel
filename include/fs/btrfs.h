/* SPDX-License-Identifier: MPL-2.0 */
/* Shared Btrfs VFS integration. */

#ifndef EDGEOS_FS_BTRFS_H
#define EDGEOS_FS_BTRFS_H

#include "block/block.h"

int btrfs_mount(const char *device_name, const char *target);
int btrfs_mount_block(block_device_t *device, const char *target);

#endif
