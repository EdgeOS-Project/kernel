/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include "vfs/vfs.h"

static const vfs_inode_lifetime_backend_ops_t *g_lifetime_backend_ops;
static void *g_lifetime_backend_context;

int vfs_inode_lifetime_backend_register(
    const vfs_inode_lifetime_backend_ops_t *ops, void *context) {
    if (!ops || !ops->orphan_inode || !ops->prepare_alias_release ||
        !ops->finish_alias_release || !ops->shutdown)
        return -1;
    g_lifetime_backend_ops = ops;
    g_lifetime_backend_context = context;
    return 0;
}

void vfs_inode_lifetime_orphan_inode(vfs_superblock_t *sb,
                                     const vfs_inode_t *inode) {
    vfs_inode_t current;

    if (!sb || !inode || !g_lifetime_backend_ops) return;
    current = *inode;
    /*
     * unlink and rename-replace also operate on multiply linked files.  Only
     * the transition to zero links creates an orphan lifetime; refreshing
     * after the successful namespace mutation keeps that policy in one shared
     * place and passes the backend the current metadata snapshot.
     */
    if (vfs_inode_refresh(sb, &current) < 0 ||
        vfs_inode_link_count(&current) != 0)
        return;
    if (!vfs_inode_same_object(sb, inode, sb, &current)) return;
    g_lifetime_backend_ops->orphan_inode(
        g_lifetime_backend_context, sb, &current);
}

void vfs_inode_lifetime_prepare_alias_release(
    vfs_superblock_t *sb, const vfs_inode_t *inode) {
    if (!sb || !inode || !g_lifetime_backend_ops) return;
    g_lifetime_backend_ops->prepare_alias_release(
        g_lifetime_backend_context, sb, inode);
}

void vfs_inode_lifetime_finish_alias_release(void) {
    if (!g_lifetime_backend_ops) return;
    g_lifetime_backend_ops->finish_alias_release(
        g_lifetime_backend_context);
}

int vfs_inode_lifetime_shutdown(void) {
    if (!g_lifetime_backend_ops) return 0;
    return g_lifetime_backend_ops->shutdown(g_lifetime_backend_context);
}

int vfs_shutdown_sync_all(void) {
    /*
     * Terminal reclamation is intentionally gated by both writeback stages.
     * If a dirty page or ordinary filesystem sync fails, leave every live
     * zero-link inode allocated so returning an error cannot invalidate an
     * open descriptor or VMA.
     */
    if (vfs_inode_lifetime_shutdown() < 0) return -1;
    if (vfs_filesystem_sync_all() < 0) return -1;
    return vfs_filesystem_shutdown_all();
}

int vfs_inode_open(vfs_superblock_t *sb, const vfs_inode_t *inode) {
    vfs_superblock_t *stable;
    int result;

    if (!inode) return -1;
    /*
     * Kernel-owned pseudo inodes such as devtmpfs device nodes intentionally
     * have no backing superblock.  They have no filesystem unlink lifetime to
     * pin, so opening them succeeds without invoking a filesystem hook.
     */
    if (!sb) return 0;
    stable = vfs_superblock_acquire(sb);
    if (!stable) return -1;
    if (!stable->ops || !stable->ops->inode_open) return 0;
    result = stable->ops->inode_open(stable, inode);
    if (result < 0 && g_lifetime_backend_ops &&
        g_lifetime_backend_ops->reclaim_cached_inode &&
        g_lifetime_backend_ops->reclaim_cached_inode(
            g_lifetime_backend_context, stable) > 0)
        result = stable->ops->inode_open(stable, inode);
    if (result < 0) vfs_superblock_release(stable);
    return result;
}

void vfs_inode_close(vfs_superblock_t *sb, const vfs_inode_t *inode) {
    vfs_superblock_t *stable;
    if (!sb || !inode) return;
    stable = vfs_superblock_stable(sb);
    if (stable->ops && stable->ops->inode_close)
        stable->ops->inode_close(stable, inode);
    vfs_superblock_release(stable);
}

int vfs_inode_refresh(vfs_superblock_t *sb, vfs_inode_t *inode) {
    vfs_inode_t refreshed;
    if (!inode) return -1;
    if (!sb || !sb->ops || !sb->ops->getattr) return 0;
    if (sb->ops->getattr(sb, inode, &refreshed) < 0) return -1;
    *inode = refreshed;
    return 0;
}

int vfs_inode_setattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                      uint16_t mode, uint32_t uid, uint32_t gid,
                      uint32_t valid) {
    int result;
    if (!sb || !inode || !valid ||
        (valid & ~(VFS_SETATTR_MODE | VFS_SETATTR_UID | VFS_SETATTR_GID |
                   VFS_SETATTR_CTIME)))
        return -1;
    if (!sb->ops || !sb->ops->setattr) return -1;
    result = sb->ops->setattr(sb, inode, mode, uid, gid, valid);
    if (result < 0) return result;
    if (valid & VFS_SETATTR_MODE)
        inode->mode = (uint16_t)((inode->mode & 0xf000u) | (mode & 07777u));
    if (valid & VFS_SETATTR_UID) inode->uid = uid;
    if (valid & VFS_SETATTR_GID) inode->gid = gid;
    (void)vfs_inode_refresh(sb, inode);
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_inode_chmod(vfs_superblock_t *sb, vfs_inode_t *inode,
                    uint16_t mode) {
    return vfs_inode_setattr(sb, inode, mode, 0, 0, VFS_SETATTR_MODE);
}

int vfs_inode_chown(vfs_superblock_t *sb, vfs_inode_t *inode,
                    uint32_t uid, uint32_t gid, uint32_t valid) {
    valid &= VFS_SETATTR_UID | VFS_SETATTR_GID;
    if (!valid) return 0;
    return vfs_inode_setattr(sb, inode, 0, uid, gid, valid);
}

int vfs_inode_utimens(vfs_superblock_t *sb, vfs_inode_t *inode,
                      uint32_t atime, uint32_t mtime,
                      int set_atime, int set_mtime) {
    int result;
    if (!set_atime && !set_mtime) return 0;
    if (!sb || !inode || !sb->ops || !sb->ops->settimes) return -1;
    result = sb->ops->settimes(sb, inode, atime, mtime,
                               set_atime, set_mtime);
    if (result < 0) return result;
    if (set_atime) inode->atime = atime;
    if (set_mtime) inode->mtime = mtime;
    vfs_path_cache_invalidate_all();
    return 0;
}
