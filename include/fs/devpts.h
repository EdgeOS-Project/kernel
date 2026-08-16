/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_FS_DEVPTS_H
#define EDGEOS_FS_DEVPTS_H

#include <stdint.h>
#include "vfs/vfs.h"

typedef struct devpts_slave_handle {
    uint8_t linked;
    uint8_t padding[3];
    uint32_t index;
    vfs_superblock_t *superblock;
    vfs_inode_t inode;
    char path[24];
} devpts_slave_handle_t;

int devpts_mount(const char *device, const char *target,
                 const char *options);
int devpts_slave_create(devpts_slave_handle_t *handle, uint32_t index,
                        uint32_t uid);
int devpts_slave_refresh(devpts_slave_handle_t *handle,
                         vfs_inode_t *inode,
                         vfs_superblock_t **superblock);
void devpts_slave_destroy(devpts_slave_handle_t *handle);

#endif
