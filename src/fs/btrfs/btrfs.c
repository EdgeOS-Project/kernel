/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS VFS adapter for the shared read-only Btrfs reader. */

#include <stdint.h>

#include "btrfs_reader.h"
#include "fs/btrfs.h"
#include "stdio.h"
#include "string.h"
#include "vfs/vfs.h"

#define EDGE_BTRFS_MAX_MOUNTS 8u

typedef struct edge_btrfs_mount {
    volatile uint32_t lock;
    uint32_t references;
    uint8_t used;
    uint8_t reserved[3];
    edge_btrfs_reader_t reader;
} edge_btrfs_mount_t;

static edge_btrfs_mount_t g_btrfs_mounts[EDGE_BTRFS_MAX_MOUNTS];
static volatile uint32_t g_btrfs_mount_lock;

static void edge_btrfs_lock(volatile uint32_t *lock) {
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

static void edge_btrfs_unlock(volatile uint32_t *lock) {
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}

static uint64_t edge_btrfs_vfs_inode_number(const vfs_inode_t *inode) {
    return inode ? inode->fs_private[0] |
                       ((uint64_t)inode->fs_private[1] << 32) : 0;
}

static int edge_btrfs_fill_inode(const edge_btrfs_inode_t *source,
                                 vfs_inode_t *output) {
    if (!source || !output || source->size > UINT32_MAX) return -1;
    memset(output, 0, sizeof(*output));
    output->ino = (uint32_t)source->number;
    output->generation = (uint32_t)source->generation;
    output->mode = (uint16_t)source->mode;
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

static int edge_btrfs_lookup(vfs_superblock_t *superblock,
                             vfs_inode_t *directory, const char *name,
                             vfs_inode_t *output) {
    edge_btrfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_btrfs_inode_t source;
    uint64_t inode_number;
    int result = -1;

    if (!mount || !directory || !name || !output) return -1;
    edge_btrfs_lock(&mount->lock);
    if (edge_btrfs_inode_load(&mount->reader,
            edge_btrfs_vfs_inode_number(directory), &source) == 0 &&
        edge_btrfs_directory_lookup(
            &mount->reader, &source, name, &inode_number) == 0 &&
        edge_btrfs_inode_load(
            &mount->reader, inode_number, &source) == 0)
        result = edge_btrfs_fill_inode(&source, output);
    edge_btrfs_unlock(&mount->lock);
    return result;
}

static int edge_btrfs_read_vfs(vfs_superblock_t *superblock,
                               vfs_inode_t *inode, uint32_t offset,
                               void *buffer, uint32_t length) {
    edge_btrfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_btrfs_inode_t source;
    int64_t result = -1;

    if (!mount || !inode || (!buffer && length)) return -1;
    edge_btrfs_lock(&mount->lock);
    if (edge_btrfs_inode_load(&mount->reader,
            edge_btrfs_vfs_inode_number(inode), &source) == 0)
        result = edge_btrfs_inode_read(
            &mount->reader, &source, offset, buffer, length);
    edge_btrfs_unlock(&mount->lock);
    return result >= 0 && result <= INT32_MAX ? (int)result : -1;
}

static int edge_btrfs_readlink(vfs_superblock_t *superblock,
                               vfs_inode_t *inode, char *output,
                               uint32_t capacity) {
    int result;
    if (!output || capacity < 2u) return -1;
    result = edge_btrfs_read_vfs(
        superblock, inode, 0, output, capacity - 1u);
    if (result < 0 || (uint32_t)result >= capacity) return -1;
    output[result] = 0;
    return result;
}

static int edge_btrfs_readdir(vfs_superblock_t *superblock,
                              vfs_inode_t *directory, uint32_t index,
                              char *name, vfs_inode_t *output) {
    edge_btrfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_btrfs_directory_entry_t entry;
    edge_btrfs_inode_t source;
    int result = -1;

    if (!mount || !directory || !name || !output) return -1;
    edge_btrfs_lock(&mount->lock);
    if (edge_btrfs_inode_load(&mount->reader,
            edge_btrfs_vfs_inode_number(directory), &source) == 0 &&
        edge_btrfs_directory_entry(
            &mount->reader, &source, index, &entry) == 0 &&
        edge_btrfs_inode_load(
            &mount->reader, entry.inode_number, &source) == 0 &&
        edge_btrfs_fill_inode(&source, output) == 0) {
        strcpy(name, entry.name);
        result = 0;
    }
    edge_btrfs_unlock(&mount->lock);
    return result;
}

static int edge_btrfs_statfs(vfs_superblock_t *superblock,
                             uint32_t *total_kb, uint32_t *used_kb) {
    edge_btrfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    if (!mount || !total_kb || !used_kb ||
        mount->reader.total_bytes / 1024u > UINT32_MAX ||
        mount->reader.bytes_used / 1024u > UINT32_MAX)
        return -1;
    *total_kb = (uint32_t)(mount->reader.total_bytes / 1024u);
    *used_kb = (uint32_t)(mount->reader.bytes_used / 1024u);
    return 0;
}

static filesystem_ops_t g_btrfs_ops = {
    .lookup = edge_btrfs_lookup,
    .read = edge_btrfs_read_vfs,
    .readlink = edge_btrfs_readlink,
    .readdir = edge_btrfs_readdir,
    .statfs = edge_btrfs_statfs
};

static void edge_btrfs_retain(void *private_data) {
    edge_btrfs_mount_t *mount = private_data;
    if (mount)
        __atomic_add_fetch(&mount->references, 1u, __ATOMIC_RELAXED);
}

static void edge_btrfs_release(void *private_data) {
    edge_btrfs_mount_t *mount = private_data;
    if (!mount || __atomic_sub_fetch(
            &mount->references, 1u, __ATOMIC_ACQ_REL) != 0)
        return;
    edge_btrfs_lock(&g_btrfs_mount_lock);
    memset(mount, 0, sizeof(*mount));
    edge_btrfs_unlock(&g_btrfs_mount_lock);
}

static int edge_btrfs_mount_common(block_device_t *device,
                                   const char *device_name,
                                   const char *target) {
    edge_btrfs_mount_t *mount = 0;
    edge_btrfs_inode_t root;
    vfs_superblock_t superblock;

    if (!device || !target) return -1;
    edge_btrfs_lock(&g_btrfs_mount_lock);
    for (uint32_t index = 0; index < EDGE_BTRFS_MAX_MOUNTS; ++index) {
        if (!g_btrfs_mounts[index].used) {
            mount = &g_btrfs_mounts[index];
            memset(mount, 0, sizeof(*mount));
            mount->used = 1u;
            break;
        }
    }
    edge_btrfs_unlock(&g_btrfs_mount_lock);
    if (!mount) return -1;
    if (edge_btrfs_reader_init(&mount->reader, device) < 0 ||
        edge_btrfs_inode_load(
            &mount->reader, EDGE_BTRFS_ROOT_INODE, &root) < 0 ||
        (root.mode & 0xf000u) != VFS_INODE_DIR)
        goto fail;

    memset(&superblock, 0, sizeof(superblock));
    strcpy(superblock.fs_name, "btrfs");
    strncpy(superblock.dev_name,
            device_name ? device_name : device->name,
            sizeof(superblock.dev_name) - 1u);
    strncpy(superblock.mountpoint, target,
            sizeof(superblock.mountpoint) - 1u);
    if (edge_btrfs_fill_inode(&root, &superblock.root) < 0) goto fail;
    superblock.ops = &g_btrfs_ops;
    superblock.fs_private = mount;
    superblock.retain = edge_btrfs_retain;
    superblock.release = edge_btrfs_release;
    superblock.mount_flags = VFS_MOUNT_READONLY;
    if (vfs_add_superblock(&superblock) < 0) goto fail;
    printf("[btrfs] mounted %s on %s node=%u chunks=%u read-only\n",
           superblock.dev_name, target, mount->reader.node_size,
           mount->reader.chunk_count);
    return 0;

fail:
    edge_btrfs_lock(&g_btrfs_mount_lock);
    memset(mount, 0, sizeof(*mount));
    edge_btrfs_unlock(&g_btrfs_mount_lock);
    return -1;
}

int btrfs_mount(const char *device_name, const char *target) {
    block_device_t *device;
    if (!device_name || !target) return -1;
    device = block_find(device_name[0] == '/' ? device_name + 5 : device_name);
    return device ? edge_btrfs_mount_common(
                        device, device_name, target) : -1;
}

int btrfs_mount_block(block_device_t *device, const char *target) {
    return edge_btrfs_mount_common(
        device, device ? device->name : 0, target);
}
