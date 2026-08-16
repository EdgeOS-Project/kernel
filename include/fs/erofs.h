/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS EROFS VFS adapter. */

#ifndef EDGEOS_FS_EROFS_H
#define EDGEOS_FS_EROFS_H

#include "block/block.h"

int erofs_mount(const char *device, const char *target);
int erofs_mount_block(block_device_t *device, const char *target);

#endif
