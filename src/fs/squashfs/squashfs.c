/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS VFS adapter for the BSD-2-Clause SquashFUSE reader core. */

#include <stdint.h>

#include "block/block.h"
#include "fs/squashfs.h"
#include "stdio.h"
#include "string.h"
#include "upstream/dir.h"
#include "upstream/file.h"
#include "upstream/fs.h"
#include "upstream/xattr.h"
#include "vfs/vfs.h"

#define EDGE_SQUASHFS_MAX_MOUNTS 8u

typedef struct edge_squashfs_mount {
    volatile uint32_t lock;
    uint32_t references;
    uint8_t used;
    uint8_t initialized;
    uint8_t reserved[2];
    sqfs reader;
    block_device_t *device;
} edge_squashfs_mount_t;

static edge_squashfs_mount_t g_squashfs_mounts[EDGE_SQUASHFS_MAX_MOUNTS];
static volatile uint32_t g_squashfs_mount_lock;

static void edge_squashfs_lock(volatile uint32_t *lock) {
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

static void edge_squashfs_unlock(volatile uint32_t *lock) {
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}

static sqfs_inode_id edge_squashfs_inode_id(const vfs_inode_t *inode) {
    if (!inode) return 0;
    return (sqfs_inode_id)inode->fs_private[0] |
           ((sqfs_inode_id)inode->fs_private[1] << 32);
}

static int edge_squashfs_fill_inode(edge_squashfs_mount_t *mount,
                                    sqfs_inode_id id,
                                    const sqfs_inode *source,
                                    vfs_inode_t *output) {
    sqfs_id_t uid = 0;
    sqfs_id_t gid = 0;
    uint64_t size = 0;

    if (!mount || !source || !output) return -1;
    if (sqfs_id_get(&mount->reader, source->base.uid, &uid) != SQFS_OK ||
        sqfs_id_get(&mount->reader, source->base.guid, &gid) != SQFS_OK)
        return -1;
    if (S_ISREG(source->base.mode))
        size = source->xtra.reg.file_size;
    else if (S_ISLNK(source->base.mode))
        size = source->xtra.symlink_size;
    else if (S_ISDIR(source->base.mode))
        size = source->xtra.dir.dir_size;
    if (size > UINT32_MAX) return -1;

    memset(output, 0, sizeof(*output));
    output->ino = source->base.inode_number;
    output->generation = (uint32_t)(id >> 32) ^ (uint32_t)id;
    output->mode = source->base.mode;
    output->uid = uid;
    output->gid = gid;
    output->nlink = source->nlink > 0 ? (uint32_t)source->nlink : 1u;
    output->nlink_valid = 1u;
    output->size = (uint32_t)size;
    output->atime = source->base.mtime;
    output->mtime = source->base.mtime;
    output->ctime = source->base.mtime;
    output->fs_private[0] = (uint32_t)id;
    output->fs_private[1] = (uint32_t)(id >> 32);
    if (S_ISBLK(source->base.mode) || S_ISCHR(source->base.mode)) {
        output->rdev = ((uint64_t)(source->xtra.dev.minor & 0xff)) |
            ((uint64_t)(source->xtra.dev.major & 0xfff) << 8) |
            ((uint64_t)(source->xtra.dev.minor & ~0xff) << 12);
    }
    return 0;
}

static int edge_squashfs_inode_load(edge_squashfs_mount_t *mount,
                                    sqfs_inode_id id,
                                    sqfs_inode *inode,
                                    vfs_inode_t *output) {
    if (sqfs_inode_get(&mount->reader, inode, id) != SQFS_OK) return -1;
    return output ? edge_squashfs_fill_inode(mount, id, inode, output) : 0;
}

static int edge_squashfs_lookup(vfs_superblock_t *superblock,
                                vfs_inode_t *directory, const char *name,
                                vfs_inode_t *output) {
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    sqfs_inode inode;
    sqfs_dir_entry entry;
    sqfs_name entry_name;
    bool found = false;
    int result = -1;

    if (!mount || !directory || !name || !output) return -1;
    edge_squashfs_lock(&mount->lock);
    if (strcmp(name, ".") == 0) {
        *output = *directory;
        result = 0;
        goto done;
    }
    if (edge_squashfs_inode_load(
            mount, edge_squashfs_inode_id(directory), &inode, 0) < 0)
        goto done;
    sqfs_dentry_init(&entry, entry_name);
    if (sqfs_dir_lookup(&mount->reader, &inode, name, strlen(name),
                        &entry, &found) != SQFS_OK || !found)
        goto done;
    if (edge_squashfs_inode_load(
            mount, sqfs_dentry_inode(&entry), &inode, output) < 0)
        goto done;
    result = 0;
done:
    edge_squashfs_unlock(&mount->lock);
    return result;
}

static int edge_squashfs_read(vfs_superblock_t *superblock,
                              vfs_inode_t *vfs_inode, uint32_t offset,
                              void *buffer, uint32_t length) {
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    sqfs_inode inode;
    sqfs_off_t requested = length;
    int result = -1;

    if (!mount || !vfs_inode || (!buffer && length)) return -1;
    edge_squashfs_lock(&mount->lock);
    if (edge_squashfs_inode_load(
            mount, edge_squashfs_inode_id(vfs_inode), &inode, 0) == 0 &&
        sqfs_read_range(&mount->reader, &inode, offset,
                        &requested, buffer) == SQFS_OK &&
        requested <= INT32_MAX)
        result = (int)requested;
    edge_squashfs_unlock(&mount->lock);
    return result;
}

static int edge_squashfs_readlink(vfs_superblock_t *superblock,
                                  vfs_inode_t *vfs_inode, char *output,
                                  uint32_t capacity) {
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    sqfs_inode inode;
    size_t size = capacity;
    int result = -1;

    if (!mount || !vfs_inode || !output || !capacity) return -1;
    edge_squashfs_lock(&mount->lock);
    if (edge_squashfs_inode_load(
            mount, edge_squashfs_inode_id(vfs_inode), &inode, 0) == 0 &&
        sqfs_readlink(&mount->reader, &inode, output, &size) == SQFS_OK)
        result = (int)strlen(output);
    edge_squashfs_unlock(&mount->lock);
    return result;
}

static int edge_squashfs_readdir(vfs_superblock_t *superblock,
                                 vfs_inode_t *directory, uint32_t index,
                                 char *name, vfs_inode_t *output) {
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    sqfs_inode inode;
    sqfs_dir directory_reader;
    sqfs_dir_entry entry;
    sqfs_name entry_name;
    sqfs_err error = SQFS_OK;
    int result = -1;

    if (!mount || !directory || !name || !output) return -1;
    /*
     * SquashFS stores only real children, while the EdgeOS VFS readdir
     * contract exposes dot entries at positions zero and one. OverlayFS and
     * Linux getdents cursors rely on that contract; without this translation
     * every merged SquashFS directory silently loses its first two children.
     */
    if (index < 2u) {
        strcpy(name, index == 0u ? "." : "..");
        *output = *directory;
        return 0;
    }
    index -= 2u;
    edge_squashfs_lock(&mount->lock);
    if (edge_squashfs_inode_load(
            mount, edge_squashfs_inode_id(directory), &inode, 0) < 0 ||
        sqfs_dir_open(&mount->reader, &inode, &directory_reader, 0) != SQFS_OK)
        goto done;
    sqfs_dentry_init(&entry, entry_name);
    for (uint32_t current = 0; current <= index; ++current) {
        if (!sqfs_dir_next(&mount->reader, &directory_reader,
                           &entry, &error) || error != SQFS_OK)
            goto done;
    }
    if (strlen(sqfs_dentry_name(&entry)) >= VFS_NAME_MAX) goto done;
    strcpy(name, sqfs_dentry_name(&entry));
    if (edge_squashfs_inode_load(
            mount, sqfs_dentry_inode(&entry), &inode, output) < 0)
        goto done;
    result = 0;
done:
    edge_squashfs_unlock(&mount->lock);
    return result;
}

static int edge_squashfs_statfs(vfs_superblock_t *superblock,
                                uint32_t *total_kb, uint32_t *used_kb) {
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    uint64_t bytes;

    if (!mount || !total_kb || !used_kb) return -1;
    bytes = mount->reader.sb.bytes_used;
    if (bytes / 1024u > UINT32_MAX) return -1;
    *total_kb = (uint32_t)((bytes + 1023u) / 1024u);
    *used_kb = *total_kb;
    return 0;
}

static int edge_squashfs_getxattr(vfs_superblock_t *superblock,
                                  const vfs_inode_t *vfs_inode,
                                  const char *name, void *value,
                                  uint32_t capacity) {
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    sqfs_inode inode;
    size_t size = capacity;
    int result = VFS_XATTR_ERR_NO_DATA;

    if (!mount || !vfs_inode || !name) return VFS_XATTR_ERR_INVALID;
    edge_squashfs_lock(&mount->lock);
    if (edge_squashfs_inode_load(
            mount, edge_squashfs_inode_id(vfs_inode), &inode, 0) < 0 ||
        sqfs_xattr_lookup(&mount->reader, &inode, name,
                          value, &size) != SQFS_OK)
        result = VFS_XATTR_ERR_IO;
    else if (!size)
        result = VFS_XATTR_ERR_NO_DATA;
    else if (value && size > capacity)
        result = VFS_XATTR_ERR_RANGE;
    else if (size > INT32_MAX)
        result = VFS_XATTR_ERR_RANGE;
    else
        result = (int)size;
    edge_squashfs_unlock(&mount->lock);
    return result;
}

static filesystem_ops_t g_squashfs_ops = {
    .lookup = edge_squashfs_lookup,
    .read = edge_squashfs_read,
    .readlink = edge_squashfs_readlink,
    .readdir = edge_squashfs_readdir,
    .statfs = edge_squashfs_statfs,
    .getxattr = edge_squashfs_getxattr
};

static void edge_squashfs_retain(void *private_data) {
    edge_squashfs_mount_t *mount = private_data;
    if (!mount) return;
    __atomic_add_fetch(&mount->references, 1u, __ATOMIC_RELAXED);
}

static void edge_squashfs_release(void *private_data) {
    edge_squashfs_mount_t *mount = private_data;
    if (!mount || __atomic_sub_fetch(
            &mount->references, 1u, __ATOMIC_ACQ_REL) != 0)
        return;
    edge_squashfs_lock(&mount->lock);
    if (mount->initialized) sqfs_destroy(&mount->reader);
    memset(&mount->reader, 0, sizeof(mount->reader));
    mount->initialized = 0;
    mount->device = 0;
    edge_squashfs_unlock(&mount->lock);
    edge_squashfs_lock(&g_squashfs_mount_lock);
    mount->used = 0;
    edge_squashfs_unlock(&g_squashfs_mount_lock);
}

static int edge_squashfs_mount_common(block_device_t *device,
                                      const char *device_name,
                                      const char *target) {
    edge_squashfs_mount_t *mount = 0;
    vfs_superblock_t superblock;
    sqfs_inode root;
    sqfs_inode_id root_id;
    sqfs_err init_result;

    if (!device || !target) return -1;
    edge_squashfs_lock(&g_squashfs_mount_lock);
    for (uint32_t index = 0; index < EDGE_SQUASHFS_MAX_MOUNTS; ++index) {
        if (!g_squashfs_mounts[index].used) {
            mount = &g_squashfs_mounts[index];
            memset(mount, 0, sizeof(*mount));
            mount->used = 1u;
            break;
        }
    }
    edge_squashfs_unlock(&g_squashfs_mount_lock);
    if (!mount) return -1;

    mount->device = device;
    init_result = sqfs_init(&mount->reader, device, 0);
    if (init_result != SQFS_OK) {
        printf("[squashfs] mount failed device=%s stage=initialize result=%u\n",
               device_name ? device_name : device->name,
               (unsigned)init_result);
        goto fail;
    }
    mount->initialized = 1u;
    root_id = sqfs_inode_root(&mount->reader);
    if (edge_squashfs_inode_load(mount, root_id, &root, 0) < 0 ||
        !S_ISDIR(root.base.mode)) {
        printf("[squashfs] mount failed device=%s stage=root-inode id=%llu type=%u mode=0%o\n",
               device_name ? device_name : device->name,
               (unsigned long long)root_id,
               (unsigned)root.base.inode_type,
               (unsigned)root.base.mode);
        goto fail;
    }

    memset(&superblock, 0, sizeof(superblock));
    strcpy(superblock.fs_name, "squashfs");
    strncpy(superblock.dev_name, device_name ? device_name : device->name,
            sizeof(superblock.dev_name) - 1u);
    strncpy(superblock.mountpoint, target,
            sizeof(superblock.mountpoint) - 1u);
    if (edge_squashfs_fill_inode(
            mount, root_id, &root, &superblock.root) < 0) {
        printf("[squashfs] mount failed device=%s stage=root-metadata\n",
               device_name ? device_name : device->name);
        goto fail;
    }
    superblock.ops = &g_squashfs_ops;
    superblock.fs_private = mount;
    superblock.retain = edge_squashfs_retain;
    superblock.release = edge_squashfs_release;
    superblock.mount_flags = VFS_MOUNT_READONLY;
    if (vfs_add_superblock(&superblock) < 0) {
        printf("[squashfs] mount failed device=%s stage=register\n",
               device_name ? device_name : device->name);
        goto fail;
    }
    printf("[squashfs] mounted %s on %s compression=%u block=%u\n",
           superblock.dev_name, target,
           (unsigned)mount->reader.sb.compression,
           (unsigned)mount->reader.sb.block_size);
    return 0;

fail:
    if (mount->initialized) sqfs_destroy(&mount->reader);
    edge_squashfs_lock(&g_squashfs_mount_lock);
    memset(mount, 0, sizeof(*mount));
    edge_squashfs_unlock(&g_squashfs_mount_lock);
    return -1;
}

int squashfs_mount(const char *device_name, const char *target) {
    block_device_t *device;

    if (!device_name || !target) return -1;
    device = block_find(device_name[0] == '/' ? device_name + 5 : device_name);
    return device ? edge_squashfs_mount_common(
                        device, device_name, target) : -1;
}

int squashfs_mount_block(block_device_t *device, const char *target) {
    return edge_squashfs_mount_common(
        device, device ? device->name : 0, target);
}
