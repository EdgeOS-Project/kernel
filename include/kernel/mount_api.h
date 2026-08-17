/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent descriptor mount API.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_MOUNT_API_H
#define EDGEOS_KERNEL_MOUNT_API_H

#include <stdint.h>

#define KERNEL_MOUNT_API_SET_FLAG         0u
#define KERNEL_MOUNT_API_SET_STRING       1u
#define KERNEL_MOUNT_API_SET_BINARY       2u
#define KERNEL_MOUNT_API_SET_PATH         3u
#define KERNEL_MOUNT_API_SET_PATH_EMPTY   4u
#define KERNEL_MOUNT_API_SET_FD           5u
#define KERNEL_MOUNT_API_CREATE           6u
#define KERNEL_MOUNT_API_RECONFIGURE      7u
#define KERNEL_MOUNT_API_CREATE_EXCLUSIVE 8u

int kernel_mount_api_filesystem_supported(const char *filesystem);
int kernel_mount_api_context_create(const char *filesystem);
int kernel_mount_api_context_pick(const char *path);
int kernel_mount_api_context_pick_object(int object_id);
int kernel_mount_api_context_configure(
    int object_id, uint32_t command, const char *key, const char *value,
    int32_t auxiliary, char *workspace, uint32_t workspace_capacity);
int kernel_mount_api_context_mount(int context_id, uint64_t attributes);
int kernel_mount_api_tree_open(const char *path, int clone, int recursive);
int kernel_mount_api_mount_attach(
    int object_id, char *target, char *workspace,
    uint32_t workspace_capacity);
int kernel_mount_api_mount_setattr(
    int object_id, uint64_t attr_set, uint64_t attr_clear,
    uint64_t propagation, int recursive);
int kernel_mount_api_retain(int object_id);
void kernel_mount_api_release(int object_id);

#endif
