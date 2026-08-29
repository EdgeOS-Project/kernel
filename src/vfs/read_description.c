/* SPDX-License-Identifier: MPL-2.0 */
/* Open-file-description-aware filesystem reads. */

#include "vfs/vfs.h"

int vfs_read_description(vfs_superblock_t *sb, vfs_inode_t *inode,
                         uint64_t description_identity, uint32_t off,
                         void *out, uint32_t len) {
    if (!sb || !inode || !sb->ops || (!out && len)) return -1;
    if (sb->ops->read_description)
        return sb->ops->read_description(
            sb, inode, description_identity, off, out, len);
    if (!sb->ops->read) return -1;
    return sb->ops->read(sb, inode, off, out, len);
}
