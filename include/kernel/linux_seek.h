/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux open-file-description seek policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_SEEK_H
#define EDGEOS_KERNEL_LINUX_SEEK_H

#include <stdint.h>

#define EDGE_LINUX_SEEK_SET  0u
#define EDGE_LINUX_SEEK_CUR  1u
#define EDGE_LINUX_SEEK_END  2u
#define EDGE_LINUX_SEEK_DATA 3u
#define EDGE_LINUX_SEEK_HOLE 4u

#define EDGE_LINUX_SEEK_POSITIONAL 0x01u
#define EDGE_LINUX_SEEK_DATA_HOLE  0x02u
#define EDGE_LINUX_SEEK_NOOP       0x04u

typedef struct edge_linux_seek_state {
    uint64_t offset;
    uint64_t end;
    uint64_t maximum;
    uint64_t data_hole_position;
    uint32_t capabilities;
    uint8_t data_hole_resolved;
} edge_linux_seek_state_t;

typedef enum edge_linux_seek_result {
    EDGE_LINUX_SEEK_OK = 0,
    EDGE_LINUX_SEEK_BAD_DESCRIPTOR,
    EDGE_LINUX_SEEK_PATH_DESCRIPTOR,
    EDGE_LINUX_SEEK_ILLEGAL,
    EDGE_LINUX_SEEK_INVALID,
    EDGE_LINUX_SEEK_NO_DATA,
    EDGE_LINUX_SEEK_INTERNAL,
} edge_linux_seek_result_t;

struct vfs_inode;
struct vfs_superblock;

edge_linux_seek_result_t edge_linux_seek_resolve_data_hole(
    struct vfs_superblock *superblock, const struct vfs_inode *inode,
    int64_t displacement, uint32_t whence,
    edge_linux_seek_state_t *state);

edge_linux_seek_result_t edge_linux_seek_calculate(
    const edge_linux_seek_state_t *state, int64_t displacement,
    uint32_t whence, uint64_t *result);
int64_t edge_linux_lseek_descriptor(int32_t descriptor,
                                    int64_t displacement,
                                    uint32_t whence);

/* Runtime hook: descriptor-table access and offset commit are local mechanisms. */
edge_linux_seek_result_t kernel_vfs_seek_descriptor(
    int32_t descriptor, int64_t displacement, uint32_t whence,
    uint64_t *result);
edge_linux_seek_result_t arch_vfs_seek_descriptor(
    int32_t descriptor, int64_t displacement, uint32_t whence,
    uint64_t *result);

#endif
