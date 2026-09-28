/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS AArch64 Linux UAPI layouts. */

#ifndef EDGEOS_ARCH_ARM64_LINUX_ABI_H
#define EDGEOS_ARCH_ARM64_LINUX_ABI_H

#include <stddef.h>
#include <stdint.h>

#include "kernel/file_metadata.h"

typedef struct edge_arm64_linux_stat {
    uint64_t device;
    uint64_t inode;
    uint32_t mode;
    uint32_t links;
    uint32_t uid;
    uint32_t gid;
    uint64_t rdev;
    uint64_t padding0;
    int64_t size;
    int32_t block_size;
    int32_t padding1;
    int64_t blocks;
    int64_t access_time_seconds;
    uint64_t access_time_nanoseconds;
    int64_t modification_time_seconds;
    uint64_t modification_time_nanoseconds;
    int64_t change_time_seconds;
    uint64_t change_time_nanoseconds;
    uint32_t unused0;
    uint32_t unused1;
} edge_arm64_linux_stat_t;

_Static_assert(sizeof(edge_arm64_linux_stat_t) == 128,
               "AArch64 Linux stat size mismatch");
_Static_assert(offsetof(edge_arm64_linux_stat_t, mode) == 16,
               "AArch64 Linux stat mode offset mismatch");
_Static_assert(offsetof(edge_arm64_linux_stat_t, rdev) == 32,
               "AArch64 Linux stat rdev offset mismatch");
_Static_assert(offsetof(edge_arm64_linux_stat_t,
                        access_time_seconds) == 72,
               "AArch64 Linux stat atime offset mismatch");

int edge_arm64_linux_stat_to_user(
    void *context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_destination, const kernel_file_metadata_t *metadata);

#endif
