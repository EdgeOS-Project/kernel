/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS VFS adapter for the shared read-only XFS reader. */

#include <stdint.h>

#include "fs/xfs.h"
#include "stdio.h"
#include "string.h"
#include "vfs/vfs.h"
#include "xfs_reader.h"

#define EDGE_XFS_MAX_MOUNTS 8u

typedef struct edge_xfs_mount {
    volatile uint32_t lock;
    uint32_t references;
    uint8_t used;
    uint8_t reserved[3];
    edge_xfs_reader_t reader;
} edge_xfs_mount_t;

static edge_xfs_mount_t g_xfs_mounts[EDGE_XFS_MAX_MOUNTS];
static volatile uint32_t g_xfs_mount_lock;

static void edge_xfs_lock(volatile uint32_t *lock) {
    while (__atomic_exchange_n(lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(lock, __ATOMIC_RELAXED)) {
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
        }
    }
}

static void edge_xfs_unlock(volatile uint32_t *lock) {
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}

static uint64_t edge_xfs_vfs_inode_number(const vfs_inode_t *inode) {
    if (!inode) return 0;
    return inode->fs_private[0] |
           ((uint64_t)inode->fs_private[1] << 32);
}

static int edge_xfs_fill_inode(const edge_xfs_inode_t *source,
                               vfs_inode_t *output) {
    if (!source || !output || source->size > UINT32_MAX) return -1;
    memset(output, 0, sizeof(*output));
    output->ino = (uint32_t)source->number;
    output->generation = source->generation;
    output->mode = source->mode;
    output->uid = source->uid;
    output->gid = source->gid;
    output->nlink = source->link_count;
    output->nlink_valid = 1u;
    output->size = (uint32_t)source->size;
    output->atime = source->atime < 0 ? 0u : (uint32_t)source->atime;
    output->mtime = source->mtime < 0 ? 0u : (uint32_t)source->mtime;
    output->ctime = source->ctime < 0 ? 0u : (uint32_t)source->ctime;
    output->fs_private[0] = (uint32_t)source->number;
    output->fs_private[1] = (uint32_t)(source->number >> 32);
    return 0;
}

static int edge_xfs_lookup(vfs_superblock_t *superblock,
                           vfs_inode_t *directory, const char *name,
                           vfs_inode_t *output) {
    edge_xfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_xfs_inode_t source;
    uint64_t inode_number;
    int result = -1;

    if (!mount || !directory || !name || !output) return -1;
    edge_xfs_lock(&mount->lock);
    if (edge_xfs_inode_load(&mount->reader,
            edge_xfs_vfs_inode_number(directory), &source) == 0 &&
        edge_xfs_directory_lookup(
            &mount->reader, &source, name, &inode_number) == 0 &&
        edge_xfs_inode_load(&mount->reader, inode_number, &source) == 0)
        result = edge_xfs_fill_inode(&source, output);
    edge_xfs_unlock(&mount->lock);
    return result;
}

static int edge_xfs_read_vfs(vfs_superblock_t *superblock,
                             vfs_inode_t *inode, uint32_t offset,
                             void *buffer, uint32_t length) {
    edge_xfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_xfs_inode_t source;
    int64_t result = -1;

    if (!mount || !inode || (!buffer && length)) return -1;
    edge_xfs_lock(&mount->lock);
    if (edge_xfs_inode_load(&mount->reader,
            edge_xfs_vfs_inode_number(inode), &source) == 0)
        result = edge_xfs_inode_read(
            &mount->reader, &source, offset, buffer, length);
    edge_xfs_unlock(&mount->lock);
    return result >= 0 && result <= INT32_MAX ? (int)result : -1;
}

static int edge_xfs_readlink(vfs_superblock_t *superblock,
                             vfs_inode_t *inode, char *output,
                             uint32_t capacity) {
    int result;

    if (!output || capacity < 2u) return -1;
    result = edge_xfs_read_vfs(
        superblock, inode, 0, output, capacity - 1u);
    if (result < 0 || (uint32_t)result >= capacity) return -1;
    output[result] = 0;
    return result;
}

static int edge_xfs_readdir(vfs_superblock_t *superblock,
                            vfs_inode_t *directory, uint32_t index,
                            char *name, vfs_inode_t *output) {
    edge_xfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_xfs_directory_entry_t entry;
    edge_xfs_inode_t source;
    int result = -1;

    if (!mount || !directory || !name || !output) return -1;
    edge_xfs_lock(&mount->lock);
    if (edge_xfs_inode_load(&mount->reader,
            edge_xfs_vfs_inode_number(directory), &source) == 0 &&
        edge_xfs_directory_entry(
            &mount->reader, &source, index, &entry) == 0 &&
        edge_xfs_inode_load(
            &mount->reader, entry.inode_number, &source) == 0 &&
        edge_xfs_fill_inode(&source, output) == 0) {
        strcpy(name, entry.name);
        result = 0;
    }
    edge_xfs_unlock(&mount->lock);
    return result;
}

static int edge_xfs_statfs(vfs_superblock_t *superblock,
                           uint32_t *total_kb, uint32_t *used_kb) {
    edge_xfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    uint64_t total;
    uint64_t free;

    if (!mount || !total_kb || !used_kb) return -1;
    total = mount->reader.data_blocks *
            (mount->reader.block_size / 1024u);
    free = mount->reader.free_data_blocks *
           (mount->reader.block_size / 1024u);
    if (total > UINT32_MAX || free > total) return -1;
    *total_kb = (uint32_t)total;
    *used_kb = (uint32_t)(total - free);
    return 0;
}

static filesystem_ops_t g_xfs_ops = {
    .lookup = edge_xfs_lookup,
    .read = edge_xfs_read_vfs,
    .readlink = edge_xfs_readlink,
    .readdir = edge_xfs_readdir,
    .statfs = edge_xfs_statfs
};

static void edge_xfs_retain(void *private_data) {
    edge_xfs_mount_t *mount = private_data;
    if (mount)
        __atomic_add_fetch(&mount->references, 1u, __ATOMIC_RELAXED);
}

static void edge_xfs_release(void *private_data) {
    edge_xfs_mount_t *mount = private_data;
    if (!mount || __atomic_sub_fetch(
            &mount->references, 1u, __ATOMIC_ACQ_REL) != 0)
        return;
    edge_xfs_lock(&g_xfs_mount_lock);
    memset(mount, 0, sizeof(*mount));
    edge_xfs_unlock(&g_xfs_mount_lock);
}

static int edge_xfs_mount_common(block_device_t *device,
                                 const char *device_name,
                                 const char *target) {
    edge_xfs_mount_t *mount = 0;
    edge_xfs_inode_t root;
    vfs_superblock_t superblock;

    if (!device || !target) return -1;
    edge_xfs_lock(&g_xfs_mount_lock);
    for (uint32_t index = 0; index < EDGE_XFS_MAX_MOUNTS; ++index) {
        if (!g_xfs_mounts[index].used) {
            mount = &g_xfs_mounts[index];
            memset(mount, 0, sizeof(*mount));
            mount->used = 1u;
            break;
        }
    }
    edge_xfs_unlock(&g_xfs_mount_lock);
    if (!mount) return -1;
    if (edge_xfs_reader_init(&mount->reader, device) < 0 ||
        edge_xfs_inode_load(
            &mount->reader, mount->reader.root_inode, &root) < 0 ||
        (root.mode & 0xf000u) != VFS_INODE_DIR)
        goto fail;

    memset(&superblock, 0, sizeof(superblock));
    strcpy(superblock.fs_name, "xfs");
    strncpy(superblock.dev_name,
            device_name ? device_name : device->name,
            sizeof(superblock.dev_name) - 1u);
    strncpy(superblock.mountpoint, target,
            sizeof(superblock.mountpoint) - 1u);
    if (edge_xfs_fill_inode(&root, &superblock.root) < 0) goto fail;
    superblock.ops = &g_xfs_ops;
    superblock.fs_private = mount;
    superblock.retain = edge_xfs_retain;
    superblock.release = edge_xfs_release;
    superblock.mount_flags = VFS_MOUNT_READONLY;
    if (vfs_add_superblock(&superblock) < 0) goto fail;
    printf("[xfs] mounted %s on %s block=%u root=%llu read-only\n",
           superblock.dev_name, target, mount->reader.block_size,
           (unsigned long long)mount->reader.root_inode);
    return 0;

fail:
    edge_xfs_lock(&g_xfs_mount_lock);
    memset(mount, 0, sizeof(*mount));
    edge_xfs_unlock(&g_xfs_mount_lock);
    return -1;
}

int xfs_mount(const char *device_name, const char *target) {
    block_device_t *device;

    if (!device_name || !target) return -1;
    device = block_find(device_name[0] == '/' ? device_name + 5 : device_name);
    return device ? edge_xfs_mount_common(
                        device, device_name, target) : -1;
}

int xfs_mount_block(block_device_t *device, const char *target) {
    return edge_xfs_mount_common(
        device, device ? device->name : 0, target);
}
