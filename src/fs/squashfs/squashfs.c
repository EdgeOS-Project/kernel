/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS VFS adapter for the BSD-2-Clause SquashFUSE reader core. */

#include <stdint.h>

#include "block/block.h"
#include "block/loop.h"
#include "fs/squashfs.h"
#include "kernel/process_runtime.h"
#include "kernel/task_scratch.h"
#include "stdio.h"
#include "string.h"
#include "sys/scheduler.h"
#include "sys/spinlock.h"
#include "upstream/dir.h"
#include "upstream/file.h"
#include "upstream/fs.h"
#include "upstream/sqfs_port.h"
#include "upstream/xattr.h"
#include "vfs/profile.h"
#include "vfs/vfs.h"

#define EDGE_SQUASHFS_MAX_MOUNTS 64u
#define EDGE_SQUASHFS_READDIR_CURSORS 16u
#define EDGE_SQUASHFS_READ_MAGIC 0x45535244u
#define EDGE_SQUASHFS_LOOKUP_CACHE_SLOTS 4096u

typedef struct edge_squashfs_lookup_entry {
    sqfs_inode_id directory_id;
    vfs_inode_t inode;
    char name[VFS_NAME_MAX];
    uint8_t valid;
    uint8_t found;
} edge_squashfs_lookup_entry_t;

typedef struct edge_squashfs_readdir_cursor {
    sqfs_inode_id directory_id;
    sqfs_dir reader;
    uintptr_t owner;
    sqfs_inode_id entry_inode;
    uint32_t entry_inode_number;
    uint32_t next_index;
    uint32_t entry_index;
    uint32_t stamp;
    uint16_t entry_mode;
    uint8_t valid;
    uint8_t active;
    uint8_t entry_valid;
    char entry_name[VFS_NAME_MAX];
} edge_squashfs_readdir_cursor_t;

typedef struct edge_squashfs_mount {
    volatile uint32_t cursor_lock;
    volatile uint64_t cursor_wait_sequence;
    volatile uint32_t cursor_waiters;
    spinlock_t lookup_lock;
    edge_squashfs_lookup_entry_t *lookup_cache;
    uint32_t references;
    uint32_t readdir_stamp;
    uint8_t used;
    uint8_t initialized;
    uint8_t reserved[2];
    sqfs reader;
    block_device_t *device;
    edge_squashfs_readdir_cursor_t
        readdir_cursors[EDGE_SQUASHFS_READDIR_CURSORS];
} edge_squashfs_mount_t;

typedef struct edge_squashfs_read_state {
    uint32_t magic;
    uint8_t active;
    uint8_t inode_loaded;
    uint16_t reserved;
    edge_squashfs_mount_t *mount;
    sqfs_inode_id inode_id;
    uint32_t offset;
    uint32_t length;
    void *buffer;
    sqfs_inode inode;
} edge_squashfs_read_state_t;

typedef char edge_squashfs_read_state_size_check[
    sizeof(edge_squashfs_read_state_t) <=
            KERNEL_TASK_FILESYSTEM_METADATA_WORDS * sizeof(uint64_t) ?
        1 : -1];

static edge_squashfs_mount_t g_squashfs_mounts[EDGE_SQUASHFS_MAX_MOUNTS];
static volatile uint32_t g_squashfs_mount_lock;
static volatile uint64_t g_squashfs_mount_wait_sequence;
static volatile uint32_t g_squashfs_mount_waiters;

static void edge_squashfs_lock(volatile uint32_t *lock,
                               volatile uint64_t *wait_sequence,
                               volatile uint32_t *waiters) {
    while (__atomic_exchange_n(lock, 1u, __ATOMIC_ACQUIRE)) {
        uint64_t observed;

        __atomic_add_fetch(waiters, 1u, __ATOMIC_SEQ_CST);
        observed = __atomic_load_n(wait_sequence, __ATOMIC_ACQUIRE);
        if (__atomic_load_n(lock, __ATOMIC_ACQUIRE)) {
            int waited = kernel_runtime_wait_sequence(
                wait_sequence, observed, UINT64_MAX);

            if (waited <= 0 && !kernel_runtime_yield()) {
                int released = kernel_runtime_contention_begin();

                while (__atomic_load_n(lock, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
                    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
                    __asm__ __volatile__("yield");
#endif
                }
                kernel_runtime_contention_end(released);
            }
        }
        __atomic_sub_fetch(waiters, 1u, __ATOMIC_SEQ_CST);
    }
}

static void edge_squashfs_unlock(volatile uint32_t *lock,
                                 volatile uint64_t *wait_sequence,
                                 volatile uint32_t *waiters) {
    __atomic_store_n(lock, 0u, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(wait_sequence, 1u, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(waiters, __ATOMIC_SEQ_CST))
        kernel_runtime_notify_sequence(wait_sequence);
}

static sqfs_inode_id edge_squashfs_inode_id(const vfs_inode_t *inode) {
    if (!inode) return 0;
    return (sqfs_inode_id)inode->fs_private[0] |
           ((sqfs_inode_id)inode->fs_private[1] << 32);
}

static uint32_t edge_squashfs_lookup_hash(sqfs_inode_id directory_id,
                                          const char *name, size_t length) {
    uint64_t hash = 1469598103934665603ull ^ directory_id;

    for (size_t index = 0; index < length; ++index) {
        hash ^= (uint8_t)name[index];
        hash *= 1099511628211ull;
    }
    return (uint32_t)(hash ^ (hash >> 32)) &
           (EDGE_SQUASHFS_LOOKUP_CACHE_SLOTS - 1u);
}

static int edge_squashfs_lookup_cached(edge_squashfs_mount_t *mount,
                                       sqfs_inode_id directory_id,
                                       const char *name, size_t length,
                                       vfs_inode_t *output, int *result) {
    edge_squashfs_lookup_entry_t *entry;
    uint64_t flags;
    int hit = 0;

    if (!mount->lookup_cache || length >= VFS_NAME_MAX) return 0;
    entry = &mount->lookup_cache[
        edge_squashfs_lookup_hash(directory_id, name, length)];
    flags = spin_lock_irqsave(&mount->lookup_lock);
    if (entry->valid && entry->directory_id == directory_id &&
        memcmp(entry->name, name, length + 1u) == 0) {
        if (entry->found) *output = entry->inode;
        *result = entry->found ? 0 : -1;
        hit = 1;
    }
    spin_unlock_irqrestore(&mount->lookup_lock, flags);
    return hit;
}

static void edge_squashfs_lookup_store(edge_squashfs_mount_t *mount,
                                       sqfs_inode_id directory_id,
                                       const char *name, size_t length,
                                       const vfs_inode_t *inode) {
    edge_squashfs_lookup_entry_t *entry;
    uint64_t flags;

    if (!mount->lookup_cache || length >= VFS_NAME_MAX) return;
    entry = &mount->lookup_cache[
        edge_squashfs_lookup_hash(directory_id, name, length)];
    flags = spin_lock_irqsave(&mount->lookup_lock);
    entry->valid = 0;
    entry->directory_id = directory_id;
    memcpy(entry->name, name, length + 1u);
    entry->found = inode != 0;
    if (inode) entry->inode = *inode;
    entry->valid = 1;
    spin_unlock_irqrestore(&mount->lookup_lock, flags);
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
    VFS_PROFILE_SCOPE(VFS_PROFILE_SQUASHFS_LOOKUP);
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    sqfs_inode inode;
    sqfs_dir_entry entry;
    sqfs_name entry_name;
    bool found = false;
    int result = -1;
    size_t name_length;
    sqfs_inode_id directory_id;

    if (!mount || !directory || !name || !output) return -1;
    if (strcmp(name, ".") == 0) {
        *output = *directory;
        result = 0;
        goto done;
    }
    name_length = strlen(name);
    directory_id = edge_squashfs_inode_id(directory);
    if (edge_squashfs_lookup_cached(mount, directory_id, name,
                                    name_length, output, &result)) {
        vfs_profile_scope.hits = 1;
        goto done;
    }
    vfs_profile_scope.work = 1;
    if (edge_squashfs_inode_load(
            mount, directory_id, &inode, 0) < 0)
        goto done;
    sqfs_dentry_init(&entry, entry_name);
    if (sqfs_dir_lookup(&mount->reader, &inode, name, name_length,
                        &entry, &found) != SQFS_OK)
        goto done;
    if (!found) {
        edge_squashfs_lookup_store(mount, directory_id, name,
                                   name_length, 0);
        goto done;
    }
    if (edge_squashfs_inode_load(
            mount, sqfs_dentry_inode(&entry), &inode, output) < 0)
        goto done;
    result = 0;
    edge_squashfs_lookup_store(mount, directory_id, name,
                               name_length, output);
done:
    return result;
}

static int edge_squashfs_read(vfs_superblock_t *superblock,
                              vfs_inode_t *vfs_inode, uint32_t offset,
                              void *buffer, uint32_t length) {
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_squashfs_read_state_t *state;
    sqfs_inode_id inode_id;
    sqfs_off_t requested = length;
    int result = -1;

    if (!mount || !vfs_inode || (!buffer && length)) return -1;
    state = kernel_task_filesystem_metadata_scratch();
    if (!state) return -1;
    inode_id = edge_squashfs_inode_id(vfs_inode);
    if (state->magic != EDGE_SQUASHFS_READ_MAGIC || !state->active ||
        state->mount != mount || state->inode_id != inode_id ||
        state->offset != offset || state->length != length ||
        state->buffer != buffer) {
        memset(state, 0, sizeof(*state));
        state->magic = EDGE_SQUASHFS_READ_MAGIC;
        state->active = 1u;
        state->mount = mount;
        state->inode_id = inode_id;
        state->offset = offset;
        state->length = length;
        state->buffer = buffer;
    }
    if (!state->inode_loaded) {
        if (edge_squashfs_inode_load(
                mount, inode_id, &state->inode, 0) < 0) {
            memset(state, 0, sizeof(*state));
            return -1;
        }
        state->inode_loaded = 1u;
    }
    if (sqfs_read_range(&mount->reader, &state->inode, offset,
                        &requested, buffer) == SQFS_OK &&
        requested <= INT32_MAX)
        result = (int)requested;
    memset(state, 0, sizeof(*state));
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
    if (edge_squashfs_inode_load(
            mount, edge_squashfs_inode_id(vfs_inode), &inode, 0) == 0 &&
        sqfs_readlink(&mount->reader, &inode, output, &size) == SQFS_OK)
        result = (int)strlen(output);
    return result;
}

static int edge_squashfs_readdir_entry(vfs_superblock_t *superblock,
                                       vfs_inode_t *directory,
                                       uint32_t index, char *name,
                                       vfs_inode_t *output,
                                       uint32_t *inode_number,
                                       uint16_t *mode, int dirent_only) {
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    edge_squashfs_readdir_cursor_t *cursor = 0;
    edge_squashfs_readdir_cursor_t *oldest = 0;
    sqfs_inode_id directory_id;
    sqfs_inode inode;
    sqfs_dir_entry entry;
    sqfs_name entry_name;
    sqfs_err error = SQFS_OK;
    uintptr_t owner;
    uint64_t observed;
    int initialize_cursor = 0;
    int result = -1;

    if (!mount || !directory || !name ||
        (dirent_only ? (!inode_number || !mode) : !output))
        return -1;
    /*
     * SquashFS stores only real children, while the EdgeOS VFS readdir
     * contract exposes dot entries at positions zero and one. OverlayFS and
     * Linux getdents cursors rely on that contract; without this translation
     * every merged SquashFS directory silently loses its first two children.
     */
    if (index < 2u) {
        strcpy(name, index == 0u ? "." : "..");
        if (dirent_only) {
            *inode_number = directory->ino;
            *mode = directory->mode;
        } else {
            *output = *directory;
        }
        return 0;
    }
    index -= 2u;
    directory_id = edge_squashfs_inode_id(directory);
    owner = kernel_current_context_token();

acquire_cursor:
    cursor = 0;
    oldest = 0;
    edge_squashfs_lock(&mount->cursor_lock,
                       &mount->cursor_wait_sequence,
                       &mount->cursor_waiters);
    for (uint32_t slot = 0; slot < EDGE_SQUASHFS_READDIR_CURSORS; ++slot) {
        edge_squashfs_readdir_cursor_t *candidate =
            &mount->readdir_cursors[slot];
        if (candidate->owner == owner &&
            candidate->directory_id == directory_id &&
            (candidate->active ||
             (candidate->valid &&
              candidate->next_index <= index + 1u))) {
            cursor = candidate;
            if (!cursor->valid) initialize_cursor = 1;
            break;
        }
        if (!candidate->active &&
            (!oldest || !candidate->valid ||
            (oldest->valid && candidate->stamp < oldest->stamp))
        )
            oldest = candidate;
    }
    if (!cursor) {
        cursor = oldest;
        if (!cursor) {
            observed = __atomic_load_n(
                &mount->cursor_wait_sequence, __ATOMIC_ACQUIRE);
            __atomic_add_fetch(
                &mount->cursor_waiters, 1u, __ATOMIC_SEQ_CST);
            edge_squashfs_unlock(&mount->cursor_lock,
                                 &mount->cursor_wait_sequence,
                                 &mount->cursor_waiters);
            kernel_runtime_wait_sequence(
                &mount->cursor_wait_sequence, observed, UINT64_MAX);
            __atomic_sub_fetch(
                &mount->cursor_waiters, 1u, __ATOMIC_SEQ_CST);
            goto acquire_cursor;
        }
        memset(cursor, 0, sizeof(*cursor));
        cursor->directory_id = directory_id;
        cursor->owner = owner;
        initialize_cursor = 1;
    }
    cursor->active = 1u;
    edge_squashfs_unlock(&mount->cursor_lock,
                         &mount->cursor_wait_sequence,
                         &mount->cursor_waiters);
    if (initialize_cursor) {
        if (edge_squashfs_inode_load(
                mount, directory_id, &inode, 0) < 0 ||
            sqfs_dir_open(&mount->reader, &inode,
                          &cursor->reader, 0) != SQFS_OK)
            goto done;
        cursor->next_index = 0u;
        cursor->valid = 1u;
        initialize_cursor = 0;
    }
    /*
     * Linux getdents advances directory positions sequentially. Preserve the
     * decoded SquashFS metadata cursor so a complete directory scan remains
     * linear instead of reopening and replaying every preceding entry for
     * each VFS index. A small per-mount cache also covers interleaved scans.
     */
    sqfs_dentry_init(&entry, entry_name);
    while (cursor->next_index <= index) {
        if (!sqfs_dir_next(&mount->reader, &cursor->reader,
                           &entry, &error) || error != SQFS_OK) {
            cursor->valid = 0u;
            goto done;
        }
        if (strlen(sqfs_dentry_name(&entry)) >= VFS_NAME_MAX) {
            cursor->valid = 0u;
            goto done;
        }
        cursor->entry_index = cursor->next_index;
        cursor->entry_inode = sqfs_dentry_inode(&entry);
        cursor->entry_inode_number = sqfs_dentry_inode_num(&entry);
        cursor->entry_mode = sqfs_dentry_mode(&entry);
        strcpy(cursor->entry_name, sqfs_dentry_name(&entry));
        cursor->entry_valid = 1u;
        ++cursor->next_index;
    }
    if (!cursor->entry_valid || cursor->entry_index != index) {
        cursor->valid = 0u;
        goto done;
    }
    strcpy(name, cursor->entry_name);
    if (dirent_only) {
        *inode_number = cursor->entry_inode_number;
        *mode = cursor->entry_mode;
    } else if (edge_squashfs_inode_load(
                   mount, cursor->entry_inode, &inode, output) < 0) {
        goto done;
    }
    result = 0;
done:
    if (cursor) {
        edge_squashfs_lock(&mount->cursor_lock,
                           &mount->cursor_wait_sequence,
                           &mount->cursor_waiters);
        cursor->active = 0u;
        cursor->stamp = ++mount->readdir_stamp;
        edge_squashfs_unlock(&mount->cursor_lock,
                             &mount->cursor_wait_sequence,
                             &mount->cursor_waiters);
    }
    return result;
}

static int edge_squashfs_readdir(vfs_superblock_t *superblock,
                                 vfs_inode_t *directory, uint32_t index,
                                 char *name, vfs_inode_t *output) {
    return edge_squashfs_readdir_entry(
        superblock, directory, index, name, output, 0, 0, 0);
}

static int edge_squashfs_readdir_dirent(vfs_superblock_t *superblock,
                                        vfs_inode_t *directory,
                                        uint32_t index, char *name,
                                        uint32_t *inode_number,
                                        uint16_t *mode) {
    return edge_squashfs_readdir_entry(
        superblock, directory, index, name, 0, inode_number, mode, 1);
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
    VFS_PROFILE_SCOPE(VFS_PROFILE_SQUASHFS_GETXATTR);
    edge_squashfs_mount_t *mount = superblock ? superblock->fs_private : 0;
    sqfs_inode inode;
    size_t size = capacity;
    int result = VFS_XATTR_ERR_NO_DATA;

    if (!mount || !vfs_inode || !name) return VFS_XATTR_ERR_INVALID;
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
    return result;
}

static filesystem_ops_t g_squashfs_ops = {
    .lookup = edge_squashfs_lookup,
    .read = edge_squashfs_read,
    .readlink = edge_squashfs_readlink,
    .readdir = edge_squashfs_readdir,
    .readdir_dirent = edge_squashfs_readdir_dirent,
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
    block_device_t *device;

    if (!mount || __atomic_sub_fetch(
            &mount->references, 1u, __ATOMIC_ACQ_REL) != 0)
        return;
    device = mount->device;
    edge_sqfs_free(mount->lookup_cache);
    mount->lookup_cache = 0;
    if (mount->initialized) sqfs_destroy(&mount->reader);
    memset(&mount->reader, 0, sizeof(mount->reader));
    mount->initialized = 0;
    mount->device = 0;
    edge_squashfs_lock(&g_squashfs_mount_lock,
                       &g_squashfs_mount_wait_sequence,
                       &g_squashfs_mount_waiters);
    mount->used = 0;
    edge_squashfs_unlock(&g_squashfs_mount_lock,
                         &g_squashfs_mount_wait_sequence,
                         &g_squashfs_mount_waiters);
    edge_loop_autoclear_block(device);
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
    edge_squashfs_lock(&g_squashfs_mount_lock,
                       &g_squashfs_mount_wait_sequence,
                       &g_squashfs_mount_waiters);
    for (uint32_t index = 0; index < EDGE_SQUASHFS_MAX_MOUNTS; ++index) {
        if (!g_squashfs_mounts[index].used) {
            mount = &g_squashfs_mounts[index];
            memset(mount, 0, sizeof(*mount));
            mount->used = 1u;
            break;
        }
    }
    edge_squashfs_unlock(&g_squashfs_mount_lock,
                         &g_squashfs_mount_wait_sequence,
                         &g_squashfs_mount_waiters);
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
    mount->lookup_cache = edge_sqfs_calloc(
        EDGE_SQUASHFS_LOOKUP_CACHE_SLOTS,
        sizeof(*mount->lookup_cache));
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
    superblock.runtime_flags |= VFS_SUPERBLOCK_IMMUTABLE_DATA;
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
    edge_sqfs_free(mount->lookup_cache);
    if (mount->initialized) sqfs_destroy(&mount->reader);
    edge_squashfs_lock(&g_squashfs_mount_lock,
                       &g_squashfs_mount_wait_sequence,
                       &g_squashfs_mount_waiters);
    memset(mount, 0, sizeof(*mount));
    edge_squashfs_unlock(&g_squashfs_mount_lock,
                         &g_squashfs_mount_wait_sequence,
                         &g_squashfs_mount_waiters);
    edge_loop_autoclear_block(device);
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
