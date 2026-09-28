/* SPDX-License-Identifier: MPL-2.0 */
/* Open-file-description-aware filesystem reads. */

#include "vfs/vfs.h"

__attribute__((weak))
uint32_t kernel_arch_vfs_read_resident(vfs_superblock_t *sb,
                                      const vfs_inode_t *inode,
                                      uint64_t offset, void *out, uint32_t len) {
    (void)sb;
    (void)inode;
    (void)offset;
    (void)out;
    (void)len;
    return 0;
}

int vfs_read_description(vfs_superblock_t *sb, vfs_inode_t *inode,
                         uint64_t description_identity, uint32_t off,
                         void *out, uint32_t len) {
    if (!sb || !inode || !sb->ops || (!out && len)) return -1;
    if (sb->ops->read_description)
        return sb->ops->read_description(
            sb, inode, description_identity, off, out, len);
    if (!sb->ops->read) return -1;
    if ((sb->runtime_flags & VFS_SUPERBLOCK_IMMUTABLE_DATA) &&
        (inode->mode & 0xf000u) == VFS_INODE_FILE) {
        uint32_t resident;
        if (!len || off >= inode->size) return 0;
        if ((uint64_t)len > inode->size - off)
            len = (uint32_t)(inode->size - off);
        if (len > 0x7fffffffu) len = 0x7fffffffu;
        resident = kernel_arch_vfs_read_resident(sb, inode, off, out, len);
        /* Preserve copied progress even when the following page is absent. */
        if (resident) return (int)resident;
    }
    return sb->ops->read(sb, inode, off, out, len);
}
