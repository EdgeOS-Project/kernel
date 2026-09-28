/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS procfs platform backend interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_PROC_PLATFORM_H
#define EDGEOS_KERNEL_PROC_PLATFORM_H

#include <stdint.h>

typedef enum kernel_proc_filesystem_kind {
    KERNEL_PROC_FS_EXT2 = 1,
    KERNEL_PROC_FS_EXT4,
    KERNEL_PROC_FS_FAT32,
    KERNEL_PROC_FS_EXFAT,
    KERNEL_PROC_FS_NTFS,
    KERNEL_PROC_FS_ISO9660,
    KERNEL_PROC_FS_UDF,
} kernel_proc_filesystem_kind_t;

#define KERNEL_PROC_UNIX_PATH_MAX 216u

typedef struct kernel_proc_unix_socket_snapshot {
    uint64_t inode;
    uint32_t references;
    uint32_t type;
    uint32_t flags;
    uint32_t state;
    char path[KERNEL_PROC_UNIX_PATH_MAX];
} kernel_proc_unix_socket_snapshot_t;

int arch_proc_filesystem_available(kernel_proc_filesystem_kind_t kind);
int arch_proc_sound_available(void);
int arch_proc_sound_read(const char *name, char *buffer, uint32_t capacity);
int arch_proc_unix_socket_at(
    uint32_t network_namespace, uint32_t ordinal,
    kernel_proc_unix_socket_snapshot_t *snapshot);

#endif /* EDGEOS_KERNEL_PROC_PLATFORM_H */
