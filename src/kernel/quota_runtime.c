/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS architecture-independent Linux quota control service. */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/quota_runtime.h"
#include "kernel/runtime_limits.h"
#include "string.h"

typedef struct kernel_quota_filesystem {
    uint8_t used;
    uint8_t enabled[KERNEL_QUOTA_TYPES];
    uint32_t format[KERNEL_QUOTA_TYPES];
    kernel_quota_info_t information[KERNEL_QUOTA_TYPES];
    const void *identity;
} kernel_quota_filesystem_t;

typedef struct kernel_quota_entry {
    uint8_t used;
    uint8_t type;
    uint16_t filesystem;
    uint32_t id;
    kernel_quota_block_t quota;
} kernel_quota_entry_t;

static kernel_quota_filesystem_t
    g_quota_filesystems[EDGE_RUNTIME_MAX_QUOTA_FILESYSTEMS];
static kernel_quota_entry_t g_quota_entries[EDGE_RUNTIME_MAX_QUOTA_ENTRIES];
static volatile uint32_t g_quota_lock;

static void quota_lock(void) {
    while (__sync_lock_test_and_set(&g_quota_lock, 1u)) { }
}

static void quota_unlock(void) {
    __sync_lock_release(&g_quota_lock);
}

static int quota_type_valid(uint32_t type) {
    return type < KERNEL_QUOTA_TYPES;
}

static int quota_format_valid(uint32_t format) {
    return format == KERNEL_QUOTA_FORMAT_VFS_OLD ||
           format == KERNEL_QUOTA_FORMAT_VFS_V0 ||
           format == KERNEL_QUOTA_FORMAT_VFS_V1 ||
           format == KERNEL_QUOTA_FORMAT_SHMEM;
}

static int quota_filesystem_find_locked(const void *identity) {
    uint32_t index;
    for (index = 0; index < EDGE_RUNTIME_MAX_QUOTA_FILESYSTEMS; ++index)
        if (g_quota_filesystems[index].used &&
            g_quota_filesystems[index].identity == identity)
            return (int)index;
    return -1;
}

static int quota_filesystem_get_locked(vfs_superblock_t *superblock,
                                       int create) {
    const void *identity;
    uint32_t index;
    int found;

    if (!superblock) return -EDGE_LINUX_ENODEV;
    identity = vfs_superblock_identity(superblock);
    if (!identity) return -EDGE_LINUX_ENODEV;
    found = quota_filesystem_find_locked(identity);
    if (found >= 0 || !create) return found;
    for (index = 0; index < EDGE_RUNTIME_MAX_QUOTA_FILESYSTEMS; ++index) {
        if (g_quota_filesystems[index].used) continue;
        memset(&g_quota_filesystems[index], 0,
               sizeof(g_quota_filesystems[index]));
        g_quota_filesystems[index].used = 1u;
        g_quota_filesystems[index].identity = identity;
        return (int)index;
    }
    return -EDGE_LINUX_ENOSPC;
}

static int quota_enabled_locked(int filesystem, uint32_t type) {
    if (filesystem < 0 ||
        (uint32_t)filesystem >= EDGE_RUNTIME_MAX_QUOTA_FILESYSTEMS ||
        !quota_type_valid(type) ||
        !g_quota_filesystems[filesystem].enabled[type])
        return -EDGE_LINUX_ESRCH;
    return 0;
}

static kernel_quota_entry_t *quota_entry_find_locked(
    int filesystem, uint32_t type, uint32_t id) {
    uint32_t index;
    for (index = 0; index < EDGE_RUNTIME_MAX_QUOTA_ENTRIES; ++index) {
        kernel_quota_entry_t *entry = &g_quota_entries[index];
        if (entry->used && entry->filesystem == (uint16_t)filesystem &&
            entry->type == type && entry->id == id)
            return entry;
    }
    return 0;
}

int kernel_quota_enable(vfs_superblock_t *superblock, uint32_t type,
                        uint32_t format) {
    int filesystem;
    int result = 0;

    if (!quota_type_valid(type) || !quota_format_valid(format))
        return -EDGE_LINUX_EINVAL;
    if (!superblock || !superblock->ops ||
        (superblock->mount_flags & VFS_MOUNT_READONLY))
        return -EDGE_LINUX_EROFS;
    quota_lock();
    filesystem = quota_filesystem_get_locked(superblock, 1);
    if (filesystem < 0) {
        result = filesystem;
    } else if (g_quota_filesystems[filesystem].enabled[type]) {
        result = -EDGE_LINUX_EBUSY;
    } else {
        g_quota_filesystems[filesystem].enabled[type] = 1u;
        g_quota_filesystems[filesystem].format[type] = format;
    }
    quota_unlock();
    return result;
}

int kernel_quota_disable(vfs_superblock_t *superblock, uint32_t type) {
    int filesystem;
    int result;
    uint32_t index;

    if (!quota_type_valid(type)) return -EDGE_LINUX_EINVAL;
    quota_lock();
    filesystem = quota_filesystem_get_locked(superblock, 0);
    result = quota_enabled_locked(filesystem, type);
    if (!result) {
        g_quota_filesystems[filesystem].enabled[type] = 0u;
        g_quota_filesystems[filesystem].format[type] = 0u;
        memset(&g_quota_filesystems[filesystem].information[type], 0,
               sizeof(g_quota_filesystems[filesystem].information[type]));
        for (index = 0; index < EDGE_RUNTIME_MAX_QUOTA_ENTRIES; ++index)
            if (g_quota_entries[index].used &&
                g_quota_entries[index].filesystem == (uint16_t)filesystem &&
                g_quota_entries[index].type == type)
                memset(&g_quota_entries[index], 0,
                       sizeof(g_quota_entries[index]));
    }
    quota_unlock();
    return result;
}

int kernel_quota_sync(vfs_superblock_t *superblock, uint32_t type) {
    int filesystem;
    int result;

    if (!quota_type_valid(type)) return -EDGE_LINUX_EINVAL;
    quota_lock();
    filesystem = quota_filesystem_get_locked(superblock, 0);
    result = quota_enabled_locked(filesystem, type);
    quota_unlock();
    if (result < 0) return result;
    if (!superblock->ops || !superblock->ops->sync)
        return 0;
    return superblock->ops->sync(superblock) < 0 ?
        -EDGE_LINUX_EIO : 0;
}

int kernel_quota_format(vfs_superblock_t *superblock, uint32_t type,
                        uint32_t *format) {
    int filesystem;
    int result;

    if (!format || !quota_type_valid(type)) return -EDGE_LINUX_EINVAL;
    quota_lock();
    filesystem = quota_filesystem_get_locked(superblock, 0);
    result = quota_enabled_locked(filesystem, type);
    if (!result) *format = g_quota_filesystems[filesystem].format[type];
    quota_unlock();
    return result;
}

int kernel_quota_get_info(vfs_superblock_t *superblock, uint32_t type,
                          kernel_quota_info_t *information) {
    int filesystem;
    int result;

    if (!information || !quota_type_valid(type))
        return -EDGE_LINUX_EINVAL;
    quota_lock();
    filesystem = quota_filesystem_get_locked(superblock, 0);
    result = quota_enabled_locked(filesystem, type);
    if (!result)
        *information = g_quota_filesystems[filesystem].information[type];
    quota_unlock();
    return result;
}

int kernel_quota_set_info(vfs_superblock_t *superblock, uint32_t type,
                          const kernel_quota_info_t *information) {
    kernel_quota_info_t *stored;
    int filesystem;
    int result;

    if (!information || !quota_type_valid(type) ||
        (information->valid & ~KERNEL_QUOTA_INFO_ALL))
        return -EDGE_LINUX_EINVAL;
    quota_lock();
    filesystem = quota_filesystem_get_locked(superblock, 0);
    result = quota_enabled_locked(filesystem, type);
    if (!result) {
        stored = &g_quota_filesystems[filesystem].information[type];
        if (information->valid & KERNEL_QUOTA_INFO_BLOCK_GRACE)
            stored->block_grace = information->block_grace;
        if (information->valid & KERNEL_QUOTA_INFO_INODE_GRACE)
            stored->inode_grace = information->inode_grace;
        if (information->valid & KERNEL_QUOTA_INFO_FLAGS)
            stored->flags = information->flags;
        stored->valid |= information->valid;
    }
    quota_unlock();
    return result;
}

int kernel_quota_get(vfs_superblock_t *superblock, uint32_t type,
                     uint32_t id, kernel_quota_block_t *quota) {
    kernel_quota_entry_t *entry;
    int filesystem;
    int result;

    if (!quota || !quota_type_valid(type)) return -EDGE_LINUX_EINVAL;
    quota_lock();
    filesystem = quota_filesystem_get_locked(superblock, 0);
    result = quota_enabled_locked(filesystem, type);
    if (!result) {
        entry = quota_entry_find_locked(filesystem, type, id);
        if (entry) {
            *quota = entry->quota;
        } else {
            memset(quota, 0, sizeof(*quota));
            quota->valid = KERNEL_QUOTA_VALID_ALL;
        }
    }
    quota_unlock();
    return result;
}

int kernel_quota_get_next(vfs_superblock_t *superblock, uint32_t type,
                          uint32_t id, kernel_quota_next_block_t *quota) {
    kernel_quota_entry_t *selected = 0;
    int filesystem;
    int result;
    uint32_t index;

    if (!quota || !quota_type_valid(type)) return -EDGE_LINUX_EINVAL;
    quota_lock();
    filesystem = quota_filesystem_get_locked(superblock, 0);
    result = quota_enabled_locked(filesystem, type);
    if (!result) {
        for (index = 0; index < EDGE_RUNTIME_MAX_QUOTA_ENTRIES; ++index) {
            kernel_quota_entry_t *candidate = &g_quota_entries[index];
            if (!candidate->used ||
                candidate->filesystem != (uint16_t)filesystem ||
                candidate->type != type || candidate->id < id ||
                (selected && candidate->id >= selected->id))
                continue;
            selected = candidate;
        }
        if (!selected) {
            result = -EDGE_LINUX_ENOENT;
        } else {
            memset(quota, 0, sizeof(*quota));
            quota->block_hard_limit = selected->quota.block_hard_limit;
            quota->block_soft_limit = selected->quota.block_soft_limit;
            quota->current_space = selected->quota.current_space;
            quota->inode_hard_limit = selected->quota.inode_hard_limit;
            quota->inode_soft_limit = selected->quota.inode_soft_limit;
            quota->current_inodes = selected->quota.current_inodes;
            quota->block_time = selected->quota.block_time;
            quota->inode_time = selected->quota.inode_time;
            quota->valid = selected->quota.valid;
            quota->id = selected->id;
        }
    }
    quota_unlock();
    return result;
}

int kernel_quota_set(vfs_superblock_t *superblock, uint32_t type,
                     uint32_t id, const kernel_quota_block_t *quota) {
    kernel_quota_entry_t *entry;
    int filesystem;
    int result;
    uint32_t index;

    if (!quota || !quota_type_valid(type) ||
        (quota->valid & ~KERNEL_QUOTA_VALID_ALL))
        return -EDGE_LINUX_EINVAL;
    quota_lock();
    filesystem = quota_filesystem_get_locked(superblock, 0);
    result = quota_enabled_locked(filesystem, type);
    if (!result) {
        entry = quota_entry_find_locked(filesystem, type, id);
        if (!entry) {
            for (index = 0; index < EDGE_RUNTIME_MAX_QUOTA_ENTRIES; ++index)
                if (!g_quota_entries[index].used) break;
            if (index == EDGE_RUNTIME_MAX_QUOTA_ENTRIES) {
                result = -EDGE_LINUX_ENOSPC;
                goto out;
            }
            entry = &g_quota_entries[index];
            memset(entry, 0, sizeof(*entry));
            entry->used = 1u;
            entry->filesystem = (uint16_t)filesystem;
            entry->type = (uint8_t)type;
            entry->id = id;
        }
        if (quota->valid & KERNEL_QUOTA_VALID_BLOCK_LIMITS) {
            entry->quota.block_hard_limit = quota->block_hard_limit;
            entry->quota.block_soft_limit = quota->block_soft_limit;
        }
        if (quota->valid & KERNEL_QUOTA_VALID_SPACE)
            entry->quota.current_space = quota->current_space;
        if (quota->valid & KERNEL_QUOTA_VALID_INODE_LIMITS) {
            entry->quota.inode_hard_limit = quota->inode_hard_limit;
            entry->quota.inode_soft_limit = quota->inode_soft_limit;
        }
        if (quota->valid & KERNEL_QUOTA_VALID_INODES)
            entry->quota.current_inodes = quota->current_inodes;
        if (quota->valid & KERNEL_QUOTA_VALID_BLOCK_TIME)
            entry->quota.block_time = quota->block_time;
        if (quota->valid & KERNEL_QUOTA_VALID_INODE_TIME)
            entry->quota.inode_time = quota->inode_time;
        entry->quota.valid |= quota->valid;
    }
out:
    quota_unlock();
    return result;
}
