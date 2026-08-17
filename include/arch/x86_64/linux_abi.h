/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS x86_64 Linux UAPI layouts. */

#ifndef EDGEOS_ARCH_X86_64_LINUX_ABI_H
#define EDGEOS_ARCH_X86_64_LINUX_ABI_H

#include <stddef.h>
#include <stdint.h>

#include "kernel/file_metadata.h"

typedef struct edge_x86_64_linux_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
} edge_x86_64_linux_timespec_t;

typedef struct edge_x86_64_linux_stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t padding0;
    uint64_t st_rdev;
    int64_t st_size;
    int64_t st_blksize;
    int64_t st_blocks;
    edge_x86_64_linux_timespec_t st_atim;
    edge_x86_64_linux_timespec_t st_mtim;
    edge_x86_64_linux_timespec_t st_ctim;
    int64_t unused[3];
} edge_x86_64_linux_stat_t;

_Static_assert(sizeof(edge_x86_64_linux_stat_t) == 144,
               "x86_64 Linux stat size mismatch");
_Static_assert(offsetof(edge_x86_64_linux_stat_t, st_mode) == 24,
               "x86_64 Linux stat mode offset mismatch");
_Static_assert(offsetof(edge_x86_64_linux_stat_t, st_rdev) == 40,
               "x86_64 Linux stat rdev offset mismatch");
_Static_assert(offsetof(edge_x86_64_linux_stat_t, st_atim) == 72,
               "x86_64 Linux stat atime offset mismatch");

int edge_x86_64_linux_stat_to_user(
    void *context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_destination, const kernel_file_metadata_t *metadata);

#endif
