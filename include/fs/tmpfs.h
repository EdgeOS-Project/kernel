/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Shared tmpfs and memfd interfaces.  Anonymous tmpfs inodes have independent
 * open-file and VMA references so Linux memfd lifetime rules do not depend on
 * an architecture-specific descriptor implementation.
 */
#ifndef FS_TMPFS_H
#define FS_TMPFS_H

#include <stdint.h>
#include "vfs/vfs.h"

int tmpfs_mount(const char *dev, const char *target);
int tmpfs_mount_type(const char *dev, const char *target,
                     const char *fs_name);
int tmpfs_mount_type_options(const char *dev, const char *target,
                             const char *fs_name, const char *options);
int tmpfs_create_anonymous(uint16_t mode, uint32_t initial_seals,
                           vfs_inode_t *out_inode,
                           vfs_superblock_t **out_sb);
int tmpfs_memfd_get_seals(vfs_superblock_t *sb,
                          const vfs_inode_t *inode,
                          uint32_t *seals);
int tmpfs_memfd_add_seals(vfs_superblock_t *sb,
                          const vfs_inode_t *inode,
                          uint32_t seals);
int tmpfs_retain_anonymous(vfs_superblock_t *sb,
                           const vfs_inode_t *inode);
void tmpfs_release_anonymous(vfs_superblock_t *sb,
                             const vfs_inode_t *inode);
int tmpfs_retain_mapping(vfs_superblock_t *sb,
                         const vfs_inode_t *inode);
void tmpfs_release_mapping(vfs_superblock_t *sb,
                           const vfs_inode_t *inode);
int tmpfs_shared_page(vfs_superblock_t *sb, vfs_inode_t *inode,
                      uint32_t offset, int create, uint64_t *physical_out);
uint32_t tmpfs_pageout_range(vfs_superblock_t *sb, vfs_inode_t *inode,
                             uint32_t offset, uint32_t length,
                             uint32_t cgroup_id);
int arch_tmpfs_unmap_shared_page(vfs_superblock_t *sb,
                                 const vfs_inode_t *inode,
                                 uint32_t offset, uint64_t physical);
int arch_tmpfs_shared_page_cgroup(uint64_t physical,
                                  uint32_t *cgroup_id_out);
int tmpfs_settimes(vfs_superblock_t *sb, const vfs_inode_t *inode,
                   uint32_t atime, uint32_t mtime, int set_atime,
                   int set_mtime);
int tmpfs_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                  uint16_t mode, uint32_t uid, uint32_t gid, uint32_t mask);
uint64_t tmpfs_resident_bytes(void);
int tmpfs_cachestat(vfs_superblock_t *sb, const vfs_inode_t *inode,
                    uint64_t offset, uint64_t length,
                    uint64_t *resident_pages,
                    uint64_t *swapped_pages);

#endif
