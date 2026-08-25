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

typedef struct __attribute__((packed)) edge_ia32_linux_stat64 {
    uint64_t st_dev;
    uint8_t padding0[4];
    uint32_t legacy_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint8_t padding3[4];
    int64_t st_size;
    uint32_t st_blksize;
    uint64_t st_blocks;
    uint32_t st_atime;
    uint32_t st_atime_nsec;
    uint32_t st_mtime;
    uint32_t st_mtime_nsec;
    uint32_t st_ctime;
    uint32_t st_ctime_nsec;
    uint64_t st_ino;
} edge_ia32_linux_stat64_t;

_Static_assert(sizeof(edge_x86_64_linux_stat_t) == 144,
               "x86_64 Linux stat size mismatch");
_Static_assert(offsetof(edge_x86_64_linux_stat_t, st_mode) == 24,
               "x86_64 Linux stat mode offset mismatch");
_Static_assert(offsetof(edge_x86_64_linux_stat_t, st_rdev) == 40,
               "x86_64 Linux stat rdev offset mismatch");
_Static_assert(offsetof(edge_x86_64_linux_stat_t, st_atim) == 72,
               "x86_64 Linux stat atime offset mismatch");
_Static_assert(sizeof(edge_ia32_linux_stat64_t) == 96,
               "ia32 Linux stat64 size mismatch");
_Static_assert(offsetof(edge_ia32_linux_stat64_t, st_size) == 44,
               "ia32 Linux stat64 size offset mismatch");
_Static_assert(offsetof(edge_ia32_linux_stat64_t, st_ino) == 88,
               "ia32 Linux stat64 inode offset mismatch");

int edge_x86_64_linux_stat_to_user(
    void *context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_destination, const kernel_file_metadata_t *metadata);
int edge_ia32_linux_stat64_to_user(
    void *context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_destination, const kernel_file_metadata_t *metadata);

#endif
