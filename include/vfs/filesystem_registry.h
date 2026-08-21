/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_VFS_FILESYSTEM_REGISTRY_H
#define EDGEOS_VFS_FILESYSTEM_REGISTRY_H

#include <stdint.h>

typedef int (*vfs_filesystem_mount_fn_t)(const char *device,
                                         const char *target);

void vfs_filesystem_registry_reset(void);
int vfs_filesystem_registry_register(const char *name,
                                     vfs_filesystem_mount_fn_t mount_fn);
int vfs_filesystem_registry_mount(const char *name, const char *device,
                                  const char *target);
uint32_t vfs_filesystem_registry_count(void);
uint32_t vfs_filesystem_registry_capacity(void);
int32_t vfs_filesystem_registry_index(const char *name);
int vfs_filesystem_registry_name(uint32_t index, char *name,
                                 uint32_t capacity);

#endif
