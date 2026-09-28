// SPDX-License-Identifier: MPL-2.0
/*
 * Linux initramfs unpacking support for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_FS_INITRAMFS_H
#define EDGEOS_FS_INITRAMFS_H

#include <stdint.h>

int initramfs_buffer_has_archive(const void *data, uint64_t size);
int initramfs_mount_root(void);
int initramfs_unpack_memory(const void *data, uint64_t size);
int initramfs_multiboot_has_archive(uint32_t magic, void *mb_info);
int initramfs_unpack_multiboot(uint32_t magic, void *mb_info);

#endif
