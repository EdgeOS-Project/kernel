/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_VFS_CACHED_PARENT_H
#define EDGEOS_VFS_CACHED_PARENT_H
#include "vfs/vfs.h"

typedef int (*vfs_cached_parent_lookup_t)(
    const char *path, vfs_inode_t *inode, vfs_superblock_t **superblock,
    int *negative);

/* Reuse only the immediate parent of a non-canonical inode-only lookup.
 * Permission checking remains with the caller's existing ancestor walk.
 * A different mount or a symlink/type-only non-directory result cannot stand
 * in for the directory selected by the normal filesystem component walk. */
static inline int vfs_cached_parent_start(
    char *absolute, vfs_superblock_t *selected, int require_full_walk,
    vfs_cached_parent_lookup_t lookup, vfs_inode_t *parent,
    const char **remaining) {
    uint32_t length = 0, parent_length, mount_length = 0;
    vfs_superblock_t *cached_mount = 0;
    vfs_inode_t cached;
    int negative = 0, hit;
    if (!absolute || absolute[0] != '/' || !selected || !lookup ||
        !parent || !remaining || require_full_walk ||
        (selected->runtime_flags & VFS_SUPERBLOCK_DYNAMIC_LOOKUP)) return 0;
    while (absolute[length]) ++length;
    if (!length || absolute[length - 1u] == '/') return 0;
    parent_length = length;
    while (parent_length && absolute[parent_length - 1u] != '/') --parent_length;
    if (!parent_length) return 0;
    --parent_length;
    while (selected->mountpoint[mount_length]) ++mount_length;
    if (parent_length <= mount_length) return 0;
    absolute[parent_length] = 0;
    hit = lookup(absolute, &cached, &cached_mount, &negative);
    absolute[parent_length] = '/';
    if (!hit || negative || cached_mount != selected ||
        (cached.mode & 0xf000u) != VFS_INODE_DIR) return 0;
    *parent = cached;
    *remaining = absolute + parent_length + 1u;
    return 1;
}
#endif
