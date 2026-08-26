/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux mount ABI policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/linux_mount.h"

#include "dev/devtmpfs.h"
#include "fs/cgroupfs.h"
#include "fs/devpts.h"
#include "fs/procfs.h"
#include "fs/sysfs.h"
#include "fs/tmpfs.h"
#include "fs/fuse.h"
#include "kernel/fd_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/vfs_runtime.h"
#include "mm/arch_vm.h"
#include "stdio.h"
#include "string.h"
#include "vfs/vfs.h"

static volatile uint32_t g_linux_mount_operation_lock;
static volatile uintptr_t g_linux_mount_operation_owner;

#define EDGE_LINUX_NAMESPACE_MOUNT_INLINE_CAPACITY 8u
#define EDGE_LINUX_NAMESPACE_MOUNT_PAGE_SIZE 4096u

typedef struct edge_linux_namespace_mount {
    uint32_t references;
    uint32_t generation;
    uint32_t id;
    edge_namespace_kind_t kind;
    uint8_t used;
} edge_linux_namespace_mount_t;

typedef struct edge_linux_namespace_mount_chunk {
    struct edge_linux_namespace_mount_chunk *next;
    uint32_t capacity;
    edge_linux_namespace_mount_t mounts[];
} edge_linux_namespace_mount_chunk_t;

static edge_linux_namespace_mount_t g_linux_namespace_mounts[
    EDGE_LINUX_NAMESPACE_MOUNT_INLINE_CAPACITY];
static edge_linux_namespace_mount_chunk_t *g_linux_namespace_mount_overflow;
static uint32_t g_linux_namespace_mount_generation;
static vfs_superblock_t g_linux_namespace_mount_registration;

static int edge_linux_mount_copy(char *destination, uint32_t capacity,
                                 const char *source);

static int edge_linux_namespace_path_id(const char **cursor,
                                        int32_t *id_out) {
    int32_t id = 0;

    if (!cursor || !*cursor || !id_out ||
        **cursor < '0' || **cursor > '9')
        return -1;
    while (**cursor >= '0' && **cursor <= '9') {
        if (id > (INT32_MAX - (**cursor - '0')) / 10) return -1;
        id = id * 10 + (*(*cursor)++ - '0');
    }
    if (id <= 0) return -1;
    *id_out = id;
    return 0;
}

int kernel_linux_namespace_path_parse(
    const char *path, int32_t self_tgid, int32_t self_tid,
    int32_t *owner_tgid_out, int32_t *target_tid_out,
    edge_namespace_kind_t *kind_out) {
    const char *cursor;
    int32_t owner_tgid;
    int32_t target_tid;

    if (!path || !owner_tgid_out || !target_tid_out || !kind_out ||
        strncmp(path, "/proc/", 6) != 0)
        return 0;
    cursor = path + 6;
    if (strncmp(cursor, "self/", 5) == 0) {
        owner_tgid = self_tgid;
        target_tid = self_tgid;
        cursor += 5;
    } else if (strncmp(cursor, "thread-self/", 12) == 0) {
        owner_tgid = self_tgid;
        target_tid = self_tid;
        cursor += 12;
    } else {
        if (edge_linux_namespace_path_id(&cursor, &owner_tgid) < 0 ||
            *cursor++ != '/')
            return 0;
        target_tid = owner_tgid;
    }
    if (owner_tgid <= 0 || target_tid <= 0) return 0;
    if (strncmp(cursor, "task/", 5) == 0) {
        cursor += 5;
        if (edge_linux_namespace_path_id(&cursor, &target_tid) < 0 ||
            *cursor++ != '/')
            return 0;
    }
    if (strncmp(cursor, "ns/", 3) != 0) return 0;
    cursor += 3;
    for (uint32_t kind = 0; kind < EDGE_NAMESPACE_KIND_COUNT; ++kind) {
        const char *name = edge_namespace_name((edge_namespace_kind_t)kind);
        if (!name || strcmp(cursor, name) != 0) continue;
        *owner_tgid_out = owner_tgid;
        *target_tid_out = target_tid;
        *kind_out = (edge_namespace_kind_t)kind;
        return 1;
    }
    return 0;
}

static void edge_linux_mount_operation_lock(void) {
    uintptr_t owner = kernel_current_context_token();

    /*
     * A deferred filesystem request can replay the owning syscall after the
     * serving task makes progress.  The abandoned kernel stack still owns
     * this transaction, so let that same task resume it instead of waiting on
     * itself.  Other tasks remain serialized until the replay completes.
     */
    if (owner &&
        __atomic_load_n(
            &g_linux_mount_operation_lock, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(
            &g_linux_mount_operation_owner, __ATOMIC_RELAXED) == owner)
        return;
    while (__atomic_exchange_n(
            &g_linux_mount_operation_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(
                &g_linux_mount_operation_lock, __ATOMIC_RELAXED)) {
            __asm__ __volatile__("" ::: "memory");
        }
    }
    __atomic_store_n(
        &g_linux_mount_operation_owner, owner, __ATOMIC_RELEASE);
}

static void edge_linux_mount_operation_unlock(void) {
    __atomic_store_n(
        &g_linux_mount_operation_owner, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(
        &g_linux_mount_operation_lock, 0u, __ATOMIC_RELEASE);
}

static void edge_linux_namespace_mount_retain(void *private_data) {
    edge_linux_namespace_mount_t *mount =
        (edge_linux_namespace_mount_t *)private_data;

    if (!mount || !__atomic_load_n(&mount->used, __ATOMIC_ACQUIRE)) return;
    __atomic_add_fetch(&mount->references, 1u, __ATOMIC_ACQ_REL);
    if (!__atomic_load_n(&mount->used, __ATOMIC_ACQUIRE) ||
        (mount->kind == EDGE_NAMESPACE_MNT ?
             vfs_mount_namespace_retain_locked(mount->id) :
             edge_namespace_handle_retain(mount->kind, mount->id)) < 0) {
        if (__atomic_sub_fetch(
                &mount->references, 1u, __ATOMIC_ACQ_REL) == 0)
            (void)__sync_bool_compare_and_swap(&mount->used, 1u, 0u);
    }
}

static void edge_linux_namespace_mount_release(void *private_data) {
    edge_linux_namespace_mount_t *mount =
        (edge_linux_namespace_mount_t *)private_data;

    if (!mount || !__atomic_load_n(&mount->used, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&mount->references, __ATOMIC_ACQUIRE))
        return;
    edge_namespace_handle_release(mount->kind, mount->id);
    if (__atomic_sub_fetch(&mount->references, 1u, __ATOMIC_ACQ_REL) == 0)
        (void)__sync_bool_compare_and_swap(&mount->used, 1u, 0u);
}

static edge_linux_namespace_mount_t *
edge_linux_namespace_mount_allocate(edge_namespace_kind_t kind,
                                    uint32_t id) {
    edge_linux_namespace_mount_t *mount;
    edge_linux_namespace_mount_chunk_t **link;
    uint32_t generation;

    for (uint32_t index = 0;
         index < EDGE_LINUX_NAMESPACE_MOUNT_INLINE_CAPACITY; ++index) {
        mount = &g_linux_namespace_mounts[index];
        if (!__sync_bool_compare_and_swap(&mount->used, 0u, 1u))
            continue;
        goto initialize;
    }
    link = &g_linux_namespace_mount_overflow;
    while (*link) {
        for (uint32_t index = 0; index < (*link)->capacity; ++index) {
            mount = &(*link)->mounts[index];
            if (!__sync_bool_compare_and_swap(&mount->used, 0u, 1u))
                continue;
            goto initialize;
        }
        link = &(*link)->next;
    }
    {
        uint32_t capacity = (EDGE_LINUX_NAMESPACE_MOUNT_PAGE_SIZE -
            (uint32_t)sizeof(edge_linux_namespace_mount_chunk_t)) /
            (uint32_t)sizeof(edge_linux_namespace_mount_t);
        edge_linux_namespace_mount_chunk_t *chunk;
        if (!capacity) return 0;
        chunk = (edge_linux_namespace_mount_chunk_t *)arch_vm_alloc_pages(1u);
        if (!chunk) return 0;
        memset(chunk, 0, EDGE_LINUX_NAMESPACE_MOUNT_PAGE_SIZE);
        chunk->capacity = capacity;
        *link = chunk;
        mount = &chunk->mounts[0];
        mount->used = 1u;
    }

initialize:
    generation = ++g_linux_namespace_mount_generation;
    if (!generation) generation = ++g_linux_namespace_mount_generation;
    mount->references = 0;
    mount->generation = generation;
    mount->id = id;
    mount->kind = kind;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    return mount;
}

static int edge_linux_namespace_source(
    const char *path, edge_namespace_kind_t *kind_out, uint32_t *id_out) {
    kernel_linux_identity_t identity;
    kernel_proc_task_view_t target;
    uint64_t inode;
    int32_t owner_tgid;
    int32_t target_tid;

    if (!path || !kind_out || !id_out)
        return 0;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!kernel_linux_namespace_path_parse(
            path, identity.global_tgid, identity.global_tid,
            &owner_tgid, &target_tid, kind_out))
        return 0;
    if (kernel_proc_task_view_get(target_tid, &target) < 0 ||
        (target.tgid > 0 ? target.tgid : target.tid) != owner_tgid ||
        arch_proc_namespace_inode(target_tid, (uint32_t)*kind_out, &inode) < 0 ||
        edge_namespace_handle_acquire_inode(*kind_out, inode, id_out) < 0)
        return -EDGE_LINUX_ENOENT;
    return 1;
}

static int edge_linux_namespace_bind_mount(
    const char *target, edge_namespace_kind_t kind, uint32_t id) {
    edge_linux_namespace_mount_t *mount;
    vfs_superblock_t *superblock = &g_linux_namespace_mount_registration;
    vfs_inode_t target_inode;
    int status = -EDGE_LINUX_ENOSPC;

    if (!target || vfs_resolve(target, &target_inode, 0, 0, 0) < 0) {
        status = -EDGE_LINUX_ENOENT;
        goto out_release_source;
    }
    if ((target_inode.mode & 0xf000u) == VFS_INODE_DIR) {
        status = -EDGE_LINUX_ENOTDIR;
        goto out_release_source;
    }
    mount = edge_linux_namespace_mount_allocate(kind, id);
    if (!mount) goto out_release_source;

    memset(superblock, 0, sizeof(*superblock));
    strcpy(superblock->fs_name, "nsfs");
    strcpy(superblock->dev_name, "nsfs");
    if (edge_linux_mount_copy(
            superblock->mountpoint, sizeof(superblock->mountpoint), target) < 0) {
        __atomic_store_n(&mount->used, 0u, __ATOMIC_RELEASE);
        status = -EDGE_LINUX_ENAMETOOLONG;
        goto out_release_source;
    }
    superblock->root.ino = (uint32_t)edge_namespace_handle_inode(kind, id);
    superblock->root.mode = VFS_INODE_FILE | 0444u;
    superblock->root.nlink = 1;
    superblock->root.nlink_valid = 1;
    superblock->fs_private = mount;
    superblock->retain = edge_linux_namespace_mount_retain;
    superblock->release = edge_linux_namespace_mount_release;
    if (vfs_add_superblock(superblock) < 0) {
        __atomic_store_n(&mount->used, 0u, __ATOMIC_RELEASE);
        goto out_release_source;
    }
    status = 0;

out_release_source:
    edge_namespace_handle_release(kind, id);
    return status;
}

int kernel_linux_namespace_mount_acquire(
    const char *path, edge_namespace_kind_t *kind_out, uint32_t *id_out) {
    edge_linux_namespace_mount_t *mount;
    const vfs_superblock_t *stable;
    vfs_superblock_t *superblock;
    vfs_inode_t parent;
    vfs_inode_t inode;
    uint32_t generation;
    uint32_t id;
    edge_namespace_kind_t kind;

    if (!path || !kind_out || !id_out ||
        vfs_resolve(path, &inode, &superblock, &parent, 0) < 0 ||
        !superblock) {
        return 0;
    }
    stable = vfs_superblock_stable_const(superblock);
    if (!stable || strcmp(stable->fs_name, "nsfs") != 0 ||
        !(mount = (edge_linux_namespace_mount_t *)stable->fs_private)) {
        return 0;
    }
    generation = __atomic_load_n(&mount->generation, __ATOMIC_ACQUIRE);
    kind = mount->kind;
    id = mount->id;
    if (!__atomic_load_n(&mount->used, __ATOMIC_ACQUIRE) ||
        edge_namespace_handle_retain(kind, id) < 0)
        return 0;
    if (!__atomic_load_n(&mount->used, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&mount->generation, __ATOMIC_ACQUIRE) != generation ||
        mount->kind != kind || mount->id != id) {
        edge_namespace_handle_release(kind, id);
        return 0;
    }
    *kind_out = kind;
    *id_out = id;
    return 1;
}

static const uint64_t edge_linux_mount_known_flags =
    EDGE_LINUX_MS_RDONLY | EDGE_LINUX_MS_NOSUID | EDGE_LINUX_MS_NODEV |
    EDGE_LINUX_MS_NOEXEC | EDGE_LINUX_MS_SYNCHRONOUS |
    EDGE_LINUX_MS_REMOUNT | EDGE_LINUX_MS_MANDLOCK |
    EDGE_LINUX_MS_DIRSYNC | EDGE_LINUX_MS_NOSYMFOLLOW |
    EDGE_LINUX_MS_NOATIME | EDGE_LINUX_MS_NODIRATIME |
    EDGE_LINUX_MS_BIND | EDGE_LINUX_MS_MOVE | EDGE_LINUX_MS_REC |
    EDGE_LINUX_MS_SILENT | EDGE_LINUX_MS_POSIXACL |
    EDGE_LINUX_MS_UNBINDABLE | EDGE_LINUX_MS_PRIVATE |
    EDGE_LINUX_MS_SLAVE | EDGE_LINUX_MS_SHARED |
    EDGE_LINUX_MS_RELATIME | EDGE_LINUX_MS_I_VERSION |
    EDGE_LINUX_MS_STRICTATIME | EDGE_LINUX_MS_LAZYTIME;

static const uint64_t edge_linux_mount_propagation_flags =
    EDGE_LINUX_MS_UNBINDABLE | EDGE_LINUX_MS_PRIVATE |
    EDGE_LINUX_MS_SLAVE | EDGE_LINUX_MS_SHARED;

static const uint64_t edge_linux_mount_attribute_flags =
    EDGE_LINUX_MS_RDONLY | EDGE_LINUX_MS_NOSUID | EDGE_LINUX_MS_NODEV |
    EDGE_LINUX_MS_NOEXEC | EDGE_LINUX_MS_SYNCHRONOUS |
    EDGE_LINUX_MS_DIRSYNC | EDGE_LINUX_MS_NOSYMFOLLOW |
    EDGE_LINUX_MS_NOATIME | EDGE_LINUX_MS_NODIRATIME |
    EDGE_LINUX_MS_POSIXACL | EDGE_LINUX_MS_RELATIME |
    EDGE_LINUX_MS_I_VERSION | EDGE_LINUX_MS_STRICTATIME |
    EDGE_LINUX_MS_LAZYTIME;

static const uint64_t edge_linux_mount_setattr_known =
    EDGE_LINUX_MOUNT_ATTR_RDONLY | EDGE_LINUX_MOUNT_ATTR_NOSUID |
    EDGE_LINUX_MOUNT_ATTR_NODEV | EDGE_LINUX_MOUNT_ATTR_NOEXEC |
    EDGE_LINUX_MOUNT_ATTR_ATIME | EDGE_LINUX_MOUNT_ATTR_NODIRATIME |
    EDGE_LINUX_MOUNT_ATTR_IDMAP |
    EDGE_LINUX_MOUNT_ATTR_NOSYMFOLLOW;

static uint32_t edge_linux_mount_vfs_flags(uint64_t flags) {
    uint32_t result = 0;
    if (flags & EDGE_LINUX_MS_RDONLY) result |= VFS_MOUNT_READONLY;
    if (flags & EDGE_LINUX_MS_NOSUID) result |= VFS_MOUNT_NOSUID;
    if (flags & EDGE_LINUX_MS_NODEV) result |= VFS_MOUNT_NODEV;
    if (flags & EDGE_LINUX_MS_NOEXEC) result |= VFS_MOUNT_NOEXEC;
    if (flags & EDGE_LINUX_MS_SYNCHRONOUS)
        result |= VFS_MOUNT_SYNCHRONOUS;
    if (flags & EDGE_LINUX_MS_DIRSYNC) result |= VFS_MOUNT_DIRSYNC;
    if (flags & EDGE_LINUX_MS_NOSYMFOLLOW)
        result |= VFS_MOUNT_NOSYMFOLLOW;
    if (flags & EDGE_LINUX_MS_NOATIME) result |= VFS_MOUNT_NOATIME;
    if (flags & EDGE_LINUX_MS_NODIRATIME)
        result |= VFS_MOUNT_NODIRATIME;
    if (flags & EDGE_LINUX_MS_POSIXACL) result |= VFS_MOUNT_POSIXACL;
    if (flags & EDGE_LINUX_MS_RELATIME) result |= VFS_MOUNT_RELATIME;
    if (flags & EDGE_LINUX_MS_I_VERSION) result |= VFS_MOUNT_I_VERSION;
    if (flags & EDGE_LINUX_MS_STRICTATIME)
        result |= VFS_MOUNT_STRICTATIME;
    if (flags & EDGE_LINUX_MS_LAZYTIME) result |= VFS_MOUNT_LAZYTIME;
    return result;
}

static uint32_t edge_linux_mount_attr_vfs_flags(uint64_t attributes) {
    uint32_t result = 0;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_RDONLY)
        result |= VFS_MOUNT_READONLY;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NOSUID)
        result |= VFS_MOUNT_NOSUID;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NODEV)
        result |= VFS_MOUNT_NODEV;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NOEXEC)
        result |= VFS_MOUNT_NOEXEC;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NODIRATIME)
        result |= VFS_MOUNT_NODIRATIME;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NOSYMFOLLOW)
        result |= VFS_MOUNT_NOSYMFOLLOW;
    return result;
}

static int edge_linux_mount_setattr_propagation(
    uint64_t propagation, uint32_t *vfs_propagation) {
    if (!vfs_propagation) return -EDGE_LINUX_EINVAL;
    switch (propagation) {
        case 0:
            *vfs_propagation = 0;
            return 0;
        case EDGE_LINUX_MS_SHARED:
            *vfs_propagation = VFS_MOUNT_SHARED;
            return 0;
        case EDGE_LINUX_MS_PRIVATE:
            *vfs_propagation = VFS_MOUNT_PRIVATE;
            return 0;
        case EDGE_LINUX_MS_SLAVE:
            *vfs_propagation = VFS_MOUNT_SLAVE;
            return 0;
        case EDGE_LINUX_MS_UNBINDABLE:
            *vfs_propagation = VFS_MOUNT_UNBINDABLE;
            return 0;
        default:
            return -EDGE_LINUX_EINVAL;
    }
}

static int64_t edge_linux_mount_setattr_locked(
    const char *target, uint64_t attr_set, uint64_t attr_clear,
    uint64_t propagation, int recursive) {
    uint64_t set_atime;
    uint64_t clear_atime;
    uint32_t set_flags;
    uint32_t clear_flags;
    uint32_t vfs_propagation;
    int status;

    if (!target || target[0] != '/')
        return -EDGE_LINUX_EINVAL;
    if ((attr_set | attr_clear) & ~edge_linux_mount_setattr_known)
        return -EDGE_LINUX_EINVAL;
    if ((attr_set | attr_clear) & EDGE_LINUX_MOUNT_ATTR_IDMAP)
        return -EDGE_LINUX_EOPNOTSUPP;
    if ((attr_set & attr_clear) & ~EDGE_LINUX_MOUNT_ATTR_ATIME)
        return -EDGE_LINUX_EINVAL;

    set_atime = attr_set & EDGE_LINUX_MOUNT_ATTR_ATIME;
    clear_atime = attr_clear & EDGE_LINUX_MOUNT_ATTR_ATIME;
    if (set_atime != 0 &&
        set_atime != EDGE_LINUX_MOUNT_ATTR_NOATIME &&
        set_atime != EDGE_LINUX_MOUNT_ATTR_STRICTATIME)
        return -EDGE_LINUX_EINVAL;
    if (clear_atime != 0 &&
        clear_atime != EDGE_LINUX_MOUNT_ATTR_ATIME)
        return -EDGE_LINUX_EINVAL;
    if (set_atime && clear_atime != EDGE_LINUX_MOUNT_ATTR_ATIME)
        return -EDGE_LINUX_EINVAL;
    status = edge_linux_mount_setattr_propagation(
        propagation, &vfs_propagation);
    if (status < 0) return status;

    set_flags = edge_linux_mount_attr_vfs_flags(
        attr_set & ~EDGE_LINUX_MOUNT_ATTR_ATIME);
    clear_flags = edge_linux_mount_attr_vfs_flags(
        attr_clear & ~EDGE_LINUX_MOUNT_ATTR_ATIME);
    if (clear_atime == EDGE_LINUX_MOUNT_ATTR_ATIME) {
        clear_flags |= VFS_MOUNT_NOATIME | VFS_MOUNT_RELATIME |
                       VFS_MOUNT_STRICTATIME;
        if (set_atime == EDGE_LINUX_MOUNT_ATTR_NOATIME)
            set_flags |= VFS_MOUNT_NOATIME;
        else if (set_atime == EDGE_LINUX_MOUNT_ATTR_STRICTATIME)
            set_flags |= VFS_MOUNT_STRICTATIME;
        else
            set_flags |= VFS_MOUNT_RELATIME;
    }

    if (vfs_propagation &&
        vfs_set_mount_propagation(
            target, vfs_propagation, recursive) < 0)
        return -EDGE_LINUX_EINVAL;
    if (vfs_set_mount_attributes(
            target, set_flags, clear_flags, recursive) < 0)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static int edge_linux_mount_copy(char *destination, uint32_t capacity,
                                 const char *source) {
    uint32_t length = 0;
    if (!destination || !source || !capacity) return -EDGE_LINUX_EINVAL;
    while (source[length]) {
        if (length + 1u >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
        ++length;
    }
    for (uint32_t index = 0; index <= length; ++index)
        destination[index] = source[index];
    return 0;
}

static int edge_linux_mount_procfd(const char *path, int32_t *descriptor) {
    static const char self_prefix[] = "/proc/self/fd/";
    static const char thread_self_prefix[] = "/proc/thread-self/fd/";
    const char *cursor;
    uint32_t value = 0;
    uint32_t index = 0;

    if (!path || !descriptor) return 0;
    cursor = path;
    while (self_prefix[index] && cursor[index] == self_prefix[index])
        ++index;
    if (!self_prefix[index]) {
        cursor += index;
    } else {
        index = 0;
        while (thread_self_prefix[index] &&
               cursor[index] == thread_self_prefix[index])
            ++index;
        if (thread_self_prefix[index]) return 0;
        cursor += index;
    }
    if (*cursor < '0' || *cursor > '9') return 0;
    while (*cursor >= '0' && *cursor <= '9') {
        if (value > (uint32_t)INT32_MAX / 10u) return 0;
        value = value * 10u + (uint32_t)(*cursor++ - '0');
        if (value > INT32_MAX) return 0;
    }
    if (*cursor) return 0;
    *descriptor = (int32_t)value;
    return 1;
}

static int edge_linux_mount_resolve(char *path, char *workspace,
                                    uint32_t capacity) {
    kernel_vfs_target_t descriptor_target;
    int32_t descriptor;
    int status;
    if (!path || !path[0]) return -EDGE_LINUX_ENOENT;
    /*
     * Resolve procfd mount targets before applying the task root. Container
     * runtimes keep an O_PATH descriptor to a target while pivoting their
     * root; rebasing the procfd spelling first loses the magic-link identity.
     */
    if (edge_linux_mount_procfd(path, &descriptor)) {
        status = kernel_vfs_resolve_fd(descriptor, &descriptor_target);
        if (status < 0) return status;
        if (!descriptor_target.inode || !descriptor_target.resolved_path ||
            descriptor_target.resolved_path[0] != '/')
            return -EDGE_LINUX_ENOENT;
        status = edge_linux_mount_copy(
            workspace, capacity, descriptor_target.resolved_path);
        if (status < 0) return status;
        return edge_linux_mount_copy(path, capacity, workspace);
    }
    status = kernel_vfs_resolve_current_path(path, workspace, capacity);
    if (status < 0) return status;
    /*
     * mount(2) follows /proc/self/fd/N magic links to the opened mountpoint.
     * Service managers use this form to avoid pathname replacement races.
     * The EdgeOS VFS stores an absolute mountpoint rather than a dentry, so
     * retain the descriptor's real path instead of the procfs link spelling.
     */
    if (edge_linux_mount_procfd(workspace, &descriptor)) {
        status = kernel_vfs_resolve_fd(descriptor, &descriptor_target);
        if (status < 0) return status;
        if (!descriptor_target.inode ||
            !descriptor_target.resolved_path ||
            descriptor_target.resolved_path[0] != '/')
            return -EDGE_LINUX_ENOENT;
        status = edge_linux_mount_copy(
            workspace, capacity, descriptor_target.resolved_path);
        if (status < 0) return status;
    }
    return edge_linux_mount_copy(path, capacity, workspace);
}

static int64_t edge_linux_mount_finish(const char *target,
                                       uint32_t vfs_flags, int status) {
    if (status < 0) return -EDGE_LINUX_EINVAL;
    if (vfs_flags && vfs_remount(target, vfs_flags) < 0) {
        (void)vfs_umount(target, 1);
        return -EDGE_LINUX_EINVAL;
    }
    return 0;
}

static int edge_linux_mount_is(const char *filesystem, const char *name) {
    return filesystem && name && strcmp(filesystem, name) == 0;
}

#ifdef CONFIG_FUSE_FS
static int edge_linux_mount_fuse_fd(const char *options, int32_t *fd_out) {
    const char *cursor = options;
    if (!options || !fd_out) return -1;
    while (*cursor) {
        if ((cursor == options || cursor[-1] == ',') &&
            cursor[0] == 'f' && cursor[1] == 'd' && cursor[2] == '=') {
            int32_t value = 0;
            cursor += 3;
            if (*cursor < '0' || *cursor > '9') return -1;
            while (*cursor >= '0' && *cursor <= '9') {
                if (value > (INT32_MAX - (*cursor - '0')) / 10) return -1;
                value = value * 10 + (*cursor++ - '0');
            }
            if (*cursor && *cursor != ',') return -1;
            *fd_out = value;
            return 0;
        }
        while (*cursor && *cursor != ',') ++cursor;
        if (*cursor == ',') ++cursor;
    }
    return -1;
}

static int edge_linux_mount_is_fuse(const char *filesystem) {
    return filesystem &&
        (strcmp(filesystem, "fuse") == 0 ||
         strcmp(filesystem, "fuseblk") == 0 ||
         strncmp(filesystem, "fuse.", 5u) == 0);
}
#endif

int kernel_linux_mount_monitor_target(const char *path, int32_t current_pid,
                                      int32_t *target_pid) {
    const char *component;
    uint64_t parsed_pid = 0;

    if (!path || !target_pid || current_pid <= 0 ||
        strncmp(path, "/proc/", 6) != 0)
        return 0;
    component = path + 6;
    if (strncmp(component, "self/", 5) == 0) {
        component += 5;
        parsed_pid = (uint32_t)current_pid;
    } else if (strncmp(component, "thread-self/", 12) == 0) {
        component += 12;
        parsed_pid = (uint32_t)current_pid;
    } else if (strcmp(component, "mounts") == 0 ||
               strcmp(component, "mountinfo") == 0) {
        *target_pid = current_pid;
        return 1;
    } else {
        if (*component < '0' || *component > '9') return 0;
        while (*component >= '0' && *component <= '9') {
            parsed_pid = parsed_pid * 10u + (uint32_t)(*component - '0');
            if (parsed_pid > INT32_MAX) return 0;
            ++component;
        }
        if (*component++ != '/') return 0;
    }
    if (strcmp(component, "mounts") != 0 &&
        strcmp(component, "mountinfo") != 0)
        return 0;
    *target_pid = (int32_t)parsed_pid;
    return 1;
}

static int64_t edge_linux_mount_locked(
    char *source, char *target, const char *filesystem, uint64_t flags,
    const char *data, char *workspace, uint32_t workspace_capacity) {
    vfs_inode_t inode;
    vfs_inode_t target_inode;
    block_device_t *block_device = 0;
    uint64_t propagation_flags;
    uint32_t vfs_flags;
    int status;

    if ((flags & EDGE_LINUX_MS_MGC_MSK) == EDGE_LINUX_MS_MGC_VAL)
        flags &= ~EDGE_LINUX_MS_MGC_MSK;
    if ((flags & ~edge_linux_mount_known_flags) ||
        (flags & EDGE_LINUX_MS_MANDLOCK))
        return -EDGE_LINUX_EINVAL;
    if (!target || !workspace || workspace_capacity < VFS_PATH_MAX)
        return -EDGE_LINUX_EFAULT;
    status = edge_linux_mount_resolve(
        target, workspace, workspace_capacity);
    if (status < 0) return status;

    propagation_flags = flags & edge_linux_mount_propagation_flags;
    if (propagation_flags) {
        uint32_t propagation;
        if ((propagation_flags & (propagation_flags - 1u)) != 0 ||
            (flags & ~(edge_linux_mount_propagation_flags |
                       EDGE_LINUX_MS_REC | EDGE_LINUX_MS_SILENT)) != 0)
            return -EDGE_LINUX_EINVAL;
        if (propagation_flags == EDGE_LINUX_MS_SHARED)
            propagation = VFS_MOUNT_SHARED;
        else if (propagation_flags == EDGE_LINUX_MS_SLAVE)
            propagation = VFS_MOUNT_SLAVE;
        else if (propagation_flags == EDGE_LINUX_MS_UNBINDABLE)
            propagation = VFS_MOUNT_UNBINDABLE;
        else
            propagation = VFS_MOUNT_PRIVATE;
        return vfs_set_mount_propagation(
                   target, propagation,
                   (flags & EDGE_LINUX_MS_REC) != 0) < 0 ?
            -EDGE_LINUX_EINVAL : 0;
    }

    vfs_flags = edge_linux_mount_vfs_flags(flags);
    if (flags & EDGE_LINUX_MS_REMOUNT) {
        uint64_t allowed = EDGE_LINUX_MS_REMOUNT | EDGE_LINUX_MS_BIND |
                           EDGE_LINUX_MS_REC |
                           EDGE_LINUX_MS_SILENT |
                           edge_linux_mount_attribute_flags;
        if (flags & ~allowed) return -EDGE_LINUX_EINVAL;
        if ((flags & EDGE_LINUX_MS_REC) &&
            !(flags & EDGE_LINUX_MS_BIND))
            return -EDGE_LINUX_EINVAL;
        if (vfs_resolve(target, &target_inode, 0, 0, 0) < 0)
            return -EDGE_LINUX_EINVAL;
        if ((flags & (EDGE_LINUX_MS_BIND | EDGE_LINUX_MS_REC)) ==
            (EDGE_LINUX_MS_BIND | EDGE_LINUX_MS_REC)) {
            uint32_t all_attributes = edge_linux_mount_vfs_flags(
                edge_linux_mount_attribute_flags);
            return vfs_set_mount_attributes(
                       target, vfs_flags,
                       all_attributes & ~vfs_flags, 1) < 0 ?
                -EDGE_LINUX_EINVAL : 0;
        }
        return vfs_remount(target, vfs_flags) < 0 ?
            -EDGE_LINUX_EINVAL : 0;
    }

    if (flags & EDGE_LINUX_MS_BIND) {
        uint64_t allowed = EDGE_LINUX_MS_BIND | EDGE_LINUX_MS_REC |
                           EDGE_LINUX_MS_SILENT |
                           edge_linux_mount_attribute_flags;
        edge_namespace_kind_t namespace_kind;
        uint32_t namespace_id;
        if ((flags & ~allowed) || !source || !source[0])
            return -EDGE_LINUX_EINVAL;
        status = edge_linux_mount_resolve(
            source, workspace, workspace_capacity);
        if (status < 0) return status;
        status = edge_linux_namespace_source(
            source, &namespace_kind, &namespace_id);
        if (status < 0) return status;
        if (status > 0)
            return edge_linux_namespace_bind_mount(
                target, namespace_kind, namespace_id);
        if (vfs_resolve(source, &inode, 0, 0, 0) < 0 ||
            vfs_resolve(target, &target_inode, 0, 0, 0) < 0)
            return -EDGE_LINUX_ENOENT;
        /*
         * Linux reports ENOTDIR when a bind mount crosses the directory
         * boundary in either direction.  Container runtimes intentionally
         * use that result to distinguish a directory mask from a file mask
         * and retry with the appropriate mount type.
         */
        if (((inode.mode & 0xf000u) == VFS_INODE_DIR) !=
            ((target_inode.mode & 0xf000u) == VFS_INODE_DIR))
            return -EDGE_LINUX_ENOTDIR;
        if (vfs_bind_mount(source, target,
                           (flags & EDGE_LINUX_MS_REC) != 0) < 0)
            return -EDGE_LINUX_EINVAL;
        /* Initial bind mounts ignore per-mount attribute flags on Linux. */
        return 0;
    }

    if (flags & EDGE_LINUX_MS_MOVE) {
        uint64_t allowed = EDGE_LINUX_MS_MOVE | EDGE_LINUX_MS_SILENT;
        uint32_t namespace_id;
        if ((flags & ~allowed) || !source || !source[0] ||
            (filesystem && filesystem[0]))
            return -EDGE_LINUX_EINVAL;
        status = edge_linux_mount_resolve(
            source, workspace, workspace_capacity);
        if (status < 0) return status;
        status = vfs_move_mount(source, target);
        if (status == VFS_PATH_ERR_NOT_FOUND)
            return -EDGE_LINUX_ENOENT;
        if (status == VFS_PATH_ERR_NOT_DIRECTORY)
            return -EDGE_LINUX_ENOTDIR;
        if (status < 0) return -EDGE_LINUX_EINVAL;
        if (arch_vfs_current_mount_namespace(&namespace_id) == 0)
            arch_vfs_rebase_mount_move_paths(
                namespace_id, source, target);
        return 0;
    }

    if (flags & EDGE_LINUX_MS_REC)
        return -EDGE_LINUX_EINVAL;
    if (vfs_resolve(target, &target_inode, 0, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    if ((target_inode.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;

    if ((!filesystem || !filesystem[0]) && source &&
        (edge_linux_mount_is(source, "proc") ||
         edge_linux_mount_is(source, "sysfs")))
        filesystem = source;
    if (!filesystem || !filesystem[0]) filesystem = "ext4";

    if (edge_linux_mount_is(filesystem, "proc")) {
        status = procfs_mount(source && source[0] ? source : "proc", target);
        return edge_linux_mount_finish(target, vfs_flags, status);
    }
    if (edge_linux_mount_is(filesystem, "sysfs")) {
        if (vfs_mount_exists(target, "sysfs", 0))
            return -EDGE_LINUX_EBUSY;
        status = sysfs_mount(source && source[0] ? source : "sysfs", target);
        return edge_linux_mount_finish(target, vfs_flags, status);
    }
    if (edge_linux_mount_is(filesystem, "cgroup2")) {
        if (vfs_mount_exists(target, "cgroup2", 0))
            return -EDGE_LINUX_EBUSY;
        status = cgroupfs_mount(
            source && source[0] ? source : "cgroup2", target);
        return edge_linux_mount_finish(target, vfs_flags, status);
    }
    if (edge_linux_mount_is(filesystem, "tmpfs")) {
        status = tmpfs_mount_type_options(
            source && source[0] ? source : "tmpfs", target, "tmpfs", data);
        status = (int)edge_linux_mount_finish(target, vfs_flags, status);
        if (status == 0 && strcmp(target, "/dev") == 0 &&
            devtmpfs_populate_standard_nodes(target) < 0) {
            (void)vfs_umount(target, 1);
            return -EDGE_LINUX_EIO;
        }
        return status;
    }
    if (edge_linux_mount_is(filesystem, "bpf")) {
#ifdef CONFIG_BPF_SYSCALL
        if (vfs_mount_exists(target, "bpf", 0))
            return -EDGE_LINUX_EBUSY;
        status = tmpfs_mount_type_options(
            source && source[0] ? source : "bpf", target, "bpf", data);
        return edge_linux_mount_finish(target, vfs_flags, status);
#else
        return -EDGE_LINUX_ENODEV;
#endif
    }
    if (edge_linux_mount_is(filesystem, "ramfs")) {
        /*
         * EdgeOS has no swap, so ramfs and tmpfs use the same resident-page
         * implementation.  Keep a distinct filesystem identity and mount
         * instance because Linux service sandboxes rely on ramfs mount and
         * propagation semantics even though both backends are unswappable
         * here.
         */
        status = tmpfs_mount_type_options(
            source && source[0] ? source : "ramfs", target, "ramfs", data);
        return edge_linux_mount_finish(target, vfs_flags, status);
    }
    if (edge_linux_mount_is(filesystem, "mqueue")) {
        /*
         * Keep a distinct mount identity for the POSIX message queue
         * namespace.  Queue inode operations are supplied by the shared
         * message queue service; the mount topology and namespace storage
         * use the same resident-page backend as tmpfs.
         */
        status = tmpfs_mount_type_options(
            source && source[0] ? source : "mqueue", target, "mqueue", data);
        return edge_linux_mount_finish(target, vfs_flags, status);
    }
    if (edge_linux_mount_is(filesystem, "devtmpfs")) {
        if (vfs_mount_exists(target, "devtmpfs", 0))
            return -EDGE_LINUX_EBUSY;
        status = devtmpfs_mount(
            source && source[0] ? source : "devtmpfs", target);
        return edge_linux_mount_finish(target, vfs_flags, status);
    }
    if (edge_linux_mount_is(filesystem, "devpts")) {
        if (vfs_mount_exists(target, "devpts", 0))
            return -EDGE_LINUX_EBUSY;
        status = devpts_mount(
            source && source[0] ? source : "devpts", target,
            data ? data : "");
        return edge_linux_mount_finish(target, vfs_flags, status);
    }
    if (edge_linux_mount_is(filesystem, "overlay")) {
#ifdef CONFIG_OVERLAY_FS
        status = vfs_mount(data && data[0] ? data : source,
                           target, "overlay");
        return edge_linux_mount_finish(target, vfs_flags, status);
#else
        return -EDGE_LINUX_ENODEV;
#endif
    }

#ifdef CONFIG_FUSE_FS
    if (edge_linux_mount_is_fuse(filesystem)) {
        kernel_fd_operation_lease_t lease = {0};
        uint64_t description_identity = 0;
        int32_t descriptor;

        if (edge_linux_mount_fuse_fd(data, &descriptor) < 0)
            return -EDGE_LINUX_EINVAL;
        if (kernel_fd_operation_acquire(descriptor, &lease) < 0)
            return -EDGE_LINUX_EBADF;
        status = kernel_fd_operation_description_id(
            &lease, &description_identity);
        (void)kernel_fd_operation_release(&lease);
        if (status < 0 || !description_identity)
            return -EDGE_LINUX_EBADF;
        status = edge_fuse_mount(description_identity, target,
                                 filesystem, data);
        if (status == -EDGE_LINUX_EBUSY)
            return -EDGE_LINUX_EBUSY;
        if (status < 0) return -EDGE_LINUX_EIO;
        return edge_linux_mount_finish(target, vfs_flags, status);
    }
#endif

    if (!source || !source[0]) return -EDGE_LINUX_EINVAL;
    status = edge_linux_mount_resolve(
        source, workspace, workspace_capacity);
    if (status < 0) return status;
    if (vfs_resolve(source, &inode, 0, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    if (vfs_inode_get_block_device(&inode, &block_device) < 0)
        return -EDGE_LINUX_ENOTBLK;
    status = vfs_mount_blockdev(block_device, target, filesystem);
    if (status < 0) return -EDGE_LINUX_ENODEV;
    return edge_linux_mount_finish(target, vfs_flags, status);
}

static int64_t edge_linux_umount_locked(
    char *target, uint64_t flags, char *workspace,
    uint32_t workspace_capacity) {
    vfs_inode_t inode;
    int status;
    if (flags & ~(uint64_t)(EDGE_LINUX_MNT_FORCE |
                            EDGE_LINUX_MNT_DETACH |
                            EDGE_LINUX_MNT_EXPIRE |
                            EDGE_LINUX_UMOUNT_NOFOLLOW))
        return -EDGE_LINUX_EINVAL;
    if ((flags & EDGE_LINUX_MNT_EXPIRE) &&
        (flags & (EDGE_LINUX_MNT_FORCE | EDGE_LINUX_MNT_DETACH)))
        return -EDGE_LINUX_EINVAL;
    /* VFS has neither forced-unmount nor expiry state to apply truthfully. */
    if (flags & (EDGE_LINUX_MNT_FORCE | EDGE_LINUX_MNT_EXPIRE))
        return -EDGE_LINUX_EINVAL;
    if (!target || !workspace || workspace_capacity < VFS_PATH_MAX)
        return -EDGE_LINUX_EFAULT;
    status = edge_linux_mount_resolve(
        target, workspace, workspace_capacity);
    if (status < 0) return status;
    if (flags & EDGE_LINUX_UMOUNT_NOFOLLOW) {
        if (vfs_resolve_nofollow(target, &inode, 0) < 0)
            return -EDGE_LINUX_EINVAL;
        if ((inode.mode & 0xf000u) == VFS_INODE_LNK)
            return -EDGE_LINUX_EINVAL;
    }
    status = vfs_umount(
        target, (flags & EDGE_LINUX_MNT_DETACH) != 0);
    if (status == -2) return -EDGE_LINUX_EBUSY;
    return status < 0 ? -EDGE_LINUX_EINVAL : 0;
}

static int64_t edge_linux_pivot_root_locked(
    char *new_root, char *put_old, char *workspace,
    uint32_t workspace_capacity) {
    int status;
    if (!new_root || !put_old || !workspace ||
        workspace_capacity < VFS_PATH_MAX)
        return -EDGE_LINUX_EFAULT;
    status = edge_linux_mount_resolve(
        new_root, workspace, workspace_capacity);
    if (status < 0) return status;
    status = edge_linux_mount_resolve(
        put_old, workspace, workspace_capacity);
    if (status < 0) return status;
    status = kernel_vfs_pivot_root(new_root, put_old);
    return status < 0 ? status : 0;
}

int64_t kernel_linux_mount(char *source, char *target,
                           const char *filesystem, uint64_t flags,
                           const char *data, char *workspace,
                           uint32_t workspace_capacity) {
    int64_t result;
    edge_linux_mount_operation_lock();
    result = edge_linux_mount_locked(
        source, target, filesystem, flags, data, workspace,
        workspace_capacity);
    edge_linux_mount_operation_unlock();
    return result;
}

int64_t kernel_linux_mount_setattr(const char *target, uint64_t attr_set,
                                   uint64_t attr_clear,
                                   uint64_t propagation, int recursive) {
    int64_t result;
    edge_linux_mount_operation_lock();
    result = edge_linux_mount_setattr_locked(
        target, attr_set, attr_clear, propagation, recursive);
    edge_linux_mount_operation_unlock();
    return result;
}

int64_t kernel_linux_umount(char *target, uint64_t flags, char *workspace,
                            uint32_t workspace_capacity) {
    int64_t result;
    edge_linux_mount_operation_lock();
    result = edge_linux_umount_locked(
        target, flags, workspace, workspace_capacity);
    edge_linux_mount_operation_unlock();
    return result;
}

int64_t kernel_linux_pivot_root(char *new_root, char *put_old,
                                char *workspace,
                                uint32_t workspace_capacity) {
    int64_t result;
    edge_linux_mount_operation_lock();
    result = edge_linux_pivot_root_locked(
        new_root, put_old, workspace, workspace_capacity);
    edge_linux_mount_operation_unlock();
    return result;
}
