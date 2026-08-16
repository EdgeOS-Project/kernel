/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux seek policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_seek.h"
#include "vfs/vfs.h"

edge_linux_seek_result_t edge_linux_seek_resolve_data_hole(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    int64_t displacement, uint32_t whence,
    edge_linux_seek_state_t *state) {
    uint64_t position;
    int result;

    if (!state) return EDGE_LINUX_SEEK_INTERNAL;
    if (whence != EDGE_LINUX_SEEK_DATA &&
        whence != EDGE_LINUX_SEEK_HOLE)
        return EDGE_LINUX_SEEK_OK;
    if (displacement < 0) return EDGE_LINUX_SEEK_NO_DATA;
    result = vfs_seek_data_hole(
        superblock, inode, (uint64_t)displacement,
        whence == EDGE_LINUX_SEEK_HOLE, &position);
    if (result == VFS_SEEK_DATA_HOLE_ERR_NO_DATA)
        return EDGE_LINUX_SEEK_NO_DATA;
    if (result == VFS_SEEK_DATA_HOLE_ERR_INVALID)
        return EDGE_LINUX_SEEK_INVALID;
    if (result < 0) return EDGE_LINUX_SEEK_INTERNAL;
    state->data_hole_position = position;
    state->data_hole_resolved = 1u;
    return EDGE_LINUX_SEEK_OK;
}

static edge_linux_seek_result_t edge_linux_seek_add(
    uint64_t base, int64_t displacement, uint64_t *result) {
    uint64_t magnitude;

    if (!result || base > INT64_MAX) return EDGE_LINUX_SEEK_INVALID;
    if (displacement >= 0) {
        if (base > (uint64_t)INT64_MAX - (uint64_t)displacement)
            return EDGE_LINUX_SEEK_INVALID;
        *result = base + (uint64_t)displacement;
        return EDGE_LINUX_SEEK_OK;
    }
    magnitude = (uint64_t)(-(displacement + 1)) + 1u;
    if (magnitude > base) return EDGE_LINUX_SEEK_INVALID;
    *result = base - magnitude;
    return EDGE_LINUX_SEEK_OK;
}

edge_linux_seek_result_t edge_linux_seek_calculate(
    const edge_linux_seek_state_t *state, int64_t displacement,
    uint32_t whence, uint64_t *result) {
    edge_linux_seek_result_t status;
    uint64_t position;

    if (!state || !result) return EDGE_LINUX_SEEK_INTERNAL;
    if (whence > EDGE_LINUX_SEEK_HOLE) return EDGE_LINUX_SEEK_INVALID;
    if (state->capabilities & EDGE_LINUX_SEEK_NOOP) {
        *result = 0;
        return EDGE_LINUX_SEEK_OK;
    }
    if (!(state->capabilities & EDGE_LINUX_SEEK_POSITIONAL))
        return EDGE_LINUX_SEEK_ILLEGAL;

    if (whence == EDGE_LINUX_SEEK_DATA ||
        whence == EDGE_LINUX_SEEK_HOLE) {
        if (!(state->capabilities & EDGE_LINUX_SEEK_DATA_HOLE))
            return EDGE_LINUX_SEEK_INVALID;
        if (displacement < 0 ||
            (uint64_t)displacement >= state->end)
            return EDGE_LINUX_SEEK_NO_DATA;
        position = state->data_hole_resolved ?
                   state->data_hole_position :
                   whence == EDGE_LINUX_SEEK_DATA ?
                   (uint64_t)displacement : state->end;
    } else {
        uint64_t base = 0;
        if (whence == EDGE_LINUX_SEEK_CUR) base = state->offset;
        else if (whence == EDGE_LINUX_SEEK_END) base = state->end;
        status = edge_linux_seek_add(base, displacement, &position);
        if (status != EDGE_LINUX_SEEK_OK) return status;
    }
    if (position > state->maximum) return EDGE_LINUX_SEEK_INVALID;
    *result = position;
    return EDGE_LINUX_SEEK_OK;
}

int64_t edge_linux_lseek_descriptor(int32_t descriptor,
                                    int64_t displacement,
                                    uint32_t whence) {
    edge_linux_seek_result_t status;
    uint64_t result = 0;

    status = kernel_vfs_seek_descriptor(descriptor, displacement, whence,
                                        &result);
    if (status == EDGE_LINUX_SEEK_OK) return (int64_t)result;
    if (status == EDGE_LINUX_SEEK_BAD_DESCRIPTOR ||
        status == EDGE_LINUX_SEEK_PATH_DESCRIPTOR)
        return -EDGE_LINUX_EBADF;
    if (status == EDGE_LINUX_SEEK_ILLEGAL)
        return -EDGE_LINUX_ESPIPE;
    if (status == EDGE_LINUX_SEEK_NO_DATA)
        return -EDGE_LINUX_ENXIO;
    if (status == EDGE_LINUX_SEEK_INVALID)
        return -EDGE_LINUX_EINVAL;
    return -EDGE_LINUX_EIO;
}
