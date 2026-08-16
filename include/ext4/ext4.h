#ifndef EXT4_EXT4_H
#define EXT4_EXT4_H

#include "block/block.h"
#include "vfs/vfs.h"

int ext4_mount(const char *dev, const char *target);
int ext4_mount_block(block_device_t *bdev, const char *target);
int ext4_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                 uint16_t mode, uint32_t uid, uint32_t gid, uint32_t mask);
int ext4_settimes(vfs_superblock_t *sb, const vfs_inode_t *inode, uint32_t atime, uint32_t mtime, int set_atime, int set_mtime);
int ext4_sync(vfs_superblock_t *sb);

#endif
