/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS VFS adapter for the shared EROFS reader. */

#include <stdint.h>

#include "erofs_reader.h"
#include "fs/erofs.h"
#include "mm/arch_vm.h"
#include "stdio.h"
#include "string.h"
#include "vfs/vfs.h"

#define EDGE_EROFS_MAX_MOUNTS 8u
#define EDGE_EROFS_PAGE_SIZE 4096u
#define EDGE_EROFS_LZ4_HISTORY_SIZE 65536u

typedef struct edge_erofs_mount {
    volatile uint32_t lock;
    uint32_t references;
    uint8_t used;
    uint8_t reserved[3];
    edge_erofs_reader_t reader;
    void *workspace;
    uint32_t workspace_pages;
} edge_erofs_mount_t;

static edge_erofs_mount_t g_erofs_mounts[EDGE_EROFS_MAX_MOUNTS];
static volatile uint32_t g_erofs_mount_lock;

static void edge_erofs_lock(volatile uint32_t *lock) {
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

static void edge_erofs_unlock(volatile uint32_t *lock) {
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}

static uint64_t edge_erofs_vfs_nid(const vfs_inode_t *inode) {
    if (!inode) return 0;
    return inode->fs_private[0] |
           ((uint64_t)inode->fs_private[1] << 32);
}

static int edge_erofs_fill_inode(const edge_erofs_inode_t *source,
                                 vfs_inode_t *output) {
    if (!source || !output || source->size > UINT32_MAX) return -1;
    memset(output, 0, sizeof(*output));
    output->ino = source->inode_number ? source->inode_number :
                  (uint32_t)source->nid;
    output->generation = (uint32_t)source->nid ^
                         (uint32_t)(source->nid >> 32);
    output->mode = source->mode;
    output->uid = source->uid;
    output->gid = source->gid;
    output->nlink = source->link_count;
    output->nlink_valid = 1u;
    output->size = (uint32_t)source->size;
    output->atime = (uint32_t)source->mtime;
    output->mtime = (uint32_t)source->mtime;
    output->ctime = (uint32_t)source->mtime;
    output->fs_private[0] = (uint32_t)source->nid;
    output->fs_private[1] = (uint32_t)(source->nid >> 32);
    if ((source->mode & 0xf000u) == VFS_INODE_BLK ||
        (source->mode & 0xf000u) == VFS_INODE_CHR)
        output->rdev = source->rdev;
    return 0;
}

static int edge_erofs_lookup(vfs_superblock_t *superblock,
                             vfs_inode_t *directory, const char *name,
                             vfs_inode_t *output) {
    edge_erofs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_erofs_inode_t source;
    uint64_t nid;
    int result = -1;

    if (!mount || !directory || !name || !output) return -1;
    if (strcmp(name, ".") == 0) {
        *output = *directory;
        return 0;
    }
    edge_erofs_lock(&mount->lock);
    if (edge_erofs_inode_load(&mount->reader,
            edge_erofs_vfs_nid(directory), &source) == 0 &&
        edge_erofs_directory_lookup(
            &mount->reader, &source, name, &nid) == 0 &&
        edge_erofs_inode_load(&mount->reader, nid, &source) == 0)
        result = edge_erofs_fill_inode(&source, output);
    edge_erofs_unlock(&mount->lock);
    return result;
}

static int edge_erofs_read_vfs(vfs_superblock_t *superblock,
                               vfs_inode_t *inode, uint32_t offset,
                               void *buffer, uint32_t length) {
    edge_erofs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_erofs_inode_t source;
    int64_t result = -1;

    if (!mount || !inode || (!buffer && length)) return -1;
    edge_erofs_lock(&mount->lock);
    if (edge_erofs_inode_load(&mount->reader,
            edge_erofs_vfs_nid(inode), &source) == 0)
        result = edge_erofs_inode_read(
            &mount->reader, &source, offset, buffer, length);
    edge_erofs_unlock(&mount->lock);
    return result >= 0 && result <= INT32_MAX ? (int)result : -1;
}

static int edge_erofs_readlink(vfs_superblock_t *superblock,
                               vfs_inode_t *inode, char *output,
                               uint32_t capacity) {
    int result;

    if (!output || capacity < 2u) return -1;
    result = edge_erofs_read_vfs(
        superblock, inode, 0, output, capacity - 1u);
    if (result < 0 || (uint32_t)result >= capacity) return -1;
    output[result] = 0;
    return result;
}

static int edge_erofs_readdir(vfs_superblock_t *superblock,
                              vfs_inode_t *directory, uint32_t index,
                              char *name, vfs_inode_t *output) {
    edge_erofs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_erofs_directory_entry_t entry;
    edge_erofs_inode_t source;
    int result = -1;

    if (!mount || !directory || !name || !output) return -1;
    edge_erofs_lock(&mount->lock);
    if (edge_erofs_inode_load(&mount->reader,
            edge_erofs_vfs_nid(directory), &source) == 0 &&
        edge_erofs_directory_entry(
            &mount->reader, &source, index, &entry) == 0 &&
        edge_erofs_inode_load(&mount->reader, entry.nid, &source) == 0 &&
        edge_erofs_fill_inode(&source, output) == 0) {
        strcpy(name, entry.name);
        result = 0;
    }
    edge_erofs_unlock(&mount->lock);
    return result;
}

static int edge_erofs_statfs(vfs_superblock_t *superblock,
                             uint32_t *total_kb, uint32_t *used_kb) {
    edge_erofs_mount_t *mount = superblock ? superblock->fs_private : 0;
    uint64_t kilobytes;

    if (!mount || !total_kb || !used_kb) return -1;
    kilobytes = mount->reader.block_count *
                (mount->reader.block_size / 1024u);
    if (kilobytes > UINT32_MAX) return -1;
    *total_kb = (uint32_t)kilobytes;
    *used_kb = *total_kb;
    return 0;
}

static int edge_erofs_getxattr_vfs(vfs_superblock_t *superblock,
                                   const vfs_inode_t *inode,
                                   const char *name, void *value,
                                   uint32_t capacity) {
    edge_erofs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_erofs_inode_t source;
    int result;

    if (!mount || !inode || !name) return VFS_XATTR_ERR_INVALID;
    edge_erofs_lock(&mount->lock);
    if (edge_erofs_inode_load(&mount->reader,
            edge_erofs_vfs_nid(inode), &source) < 0) {
        result = VFS_XATTR_ERR_IO;
    } else {
        result = edge_erofs_getxattr(
            &mount->reader, &source, name, value, capacity);
        if (result == -2) result = VFS_XATTR_ERR_NO_DATA;
        else if (result == -3) result = VFS_XATTR_ERR_RANGE;
        else if (result < 0) result = VFS_XATTR_ERR_IO;
    }
    edge_erofs_unlock(&mount->lock);
    return result;
}

static filesystem_ops_t g_erofs_ops = {
    .lookup = edge_erofs_lookup,
    .read = edge_erofs_read_vfs,
    .readlink = edge_erofs_readlink,
    .readdir = edge_erofs_readdir,
    .statfs = edge_erofs_statfs,
    .getxattr = edge_erofs_getxattr_vfs
};

static void edge_erofs_retain(void *private_data) {
    edge_erofs_mount_t *mount = private_data;
    if (mount)
        __atomic_add_fetch(&mount->references, 1u, __ATOMIC_RELAXED);
}

static void edge_erofs_workspace_release(edge_erofs_mount_t *mount) {
    uint8_t *page;

    if (!mount || !mount->workspace) return;
    page = mount->workspace;
    for (uint32_t index = 0; index < mount->workspace_pages; ++index)
        arch_vm_free_page(page + (uint64_t)index * EDGE_EROFS_PAGE_SIZE);
    mount->workspace = 0;
    mount->workspace_pages = 0;
}

static void edge_erofs_release(void *private_data) {
    edge_erofs_mount_t *mount = private_data;
    if (!mount || __atomic_sub_fetch(
            &mount->references, 1u, __ATOMIC_ACQ_REL) != 0)
        return;
    edge_erofs_lock(&g_erofs_mount_lock);
    edge_erofs_workspace_release(mount);
    memset(mount, 0, sizeof(*mount));
    edge_erofs_unlock(&g_erofs_mount_lock);
}

static int edge_erofs_mount_common(block_device_t *device,
                                   const char *device_name,
                                   const char *target) {
    edge_erofs_mount_t *mount = 0;
    edge_erofs_inode_t root;
    vfs_superblock_t superblock;
    uint64_t compressed_bytes;
    uint64_t workspace_bytes;

    if (!device || !target) return -1;
    edge_erofs_lock(&g_erofs_mount_lock);
    for (uint32_t index = 0; index < EDGE_EROFS_MAX_MOUNTS; ++index) {
        if (!g_erofs_mounts[index].used) {
            mount = &g_erofs_mounts[index];
            memset(mount, 0, sizeof(*mount));
            mount->used = 1u;
            break;
        }
    }
    edge_erofs_unlock(&g_erofs_mount_lock);
    if (!mount) return -1;
    if (edge_erofs_reader_init(&mount->reader, device) < 0)
        goto fail;
    if (mount->reader.compression_algorithms) {
        compressed_bytes =
            (uint64_t)mount->reader.maximum_pcluster_blocks *
            mount->reader.block_size;
        workspace_bytes = compressed_bytes + EDGE_EROFS_LZ4_HISTORY_SIZE;
        mount->workspace_pages = (uint32_t)(
            (workspace_bytes + EDGE_EROFS_PAGE_SIZE - 1u) /
            EDGE_EROFS_PAGE_SIZE);
        mount->workspace = arch_vm_alloc_pages(mount->workspace_pages);
        if (!mount->workspace ||
            edge_erofs_reader_set_compression_workspace(
                &mount->reader, mount->workspace,
                (uint32_t)compressed_bytes,
                (uint8_t *)mount->workspace + compressed_bytes,
                EDGE_EROFS_LZ4_HISTORY_SIZE) < 0)
            goto fail;
    }
    if (edge_erofs_inode_load(
            &mount->reader, mount->reader.root_nid, &root) < 0 ||
        (root.mode & 0xf000u) != VFS_INODE_DIR)
        goto fail;

    memset(&superblock, 0, sizeof(superblock));
    strcpy(superblock.fs_name, "erofs");
    strncpy(superblock.dev_name,
            device_name ? device_name : device->name,
            sizeof(superblock.dev_name) - 1u);
    strncpy(superblock.mountpoint, target,
            sizeof(superblock.mountpoint) - 1u);
    if (edge_erofs_fill_inode(&root, &superblock.root) < 0) goto fail;
    superblock.ops = &g_erofs_ops;
    superblock.fs_private = mount;
    superblock.retain = edge_erofs_retain;
    superblock.release = edge_erofs_release;
    superblock.mount_flags = VFS_MOUNT_READONLY;
    if (vfs_add_superblock(&superblock) < 0) goto fail;
    printf("[erofs] mounted %s on %s block=%u inodes=%llu\n",
           superblock.dev_name, target, mount->reader.block_size,
           (unsigned long long)mount->reader.inode_count);
    return 0;

fail:
    edge_erofs_lock(&g_erofs_mount_lock);
    edge_erofs_workspace_release(mount);
    memset(mount, 0, sizeof(*mount));
    edge_erofs_unlock(&g_erofs_mount_lock);
    return -1;
}

int erofs_mount(const char *device_name, const char *target) {
    block_device_t *device;

    if (!device_name || !target) return -1;
    device = block_find(device_name[0] == '/' ? device_name + 5 : device_name);
    return device ? edge_erofs_mount_common(
                        device, device_name, target) : -1;
}

int erofs_mount_block(block_device_t *device, const char *target) {
    return edge_erofs_mount_common(
        device, device ? device->name : 0, target);
}
