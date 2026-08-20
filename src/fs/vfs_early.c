/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 early VFS mount core.
 * Copyright (c) EdgeOS Contributors.
 *
 * This is the mount-table portion of the shared VFS contract.  It is used
 * during ARM64 bring-up before the complete Linux-facing device/proc/sysfs
 * dispatch module is linked.  Superblocks and their filesystem operations are
 * retained exactly as normal VFS objects; only the optional path-cache
 * acceleration is absent until the full VFS module becomes architecture-ready.
 */

#include "vfs/vfs.h"
#include "vfs/filesystem_registry.h"
#include "vfs/mount_namespace.h"
#include "vfs/path_cache.h"
#include "dev/devtmpfs.h"
#include "ext4/ext4.h"
#include "fs/cgroupfs.h"
#include "fs/devpts.h"
#include "fs/procfs.h"
#include "fs/sysfs.h"
#include "fs/squashfs.h"
#include "fs/erofs.h"
#include "fs/xfs.h"
#include "fs/btrfs.h"
#include "fs/tmpfs.h"
#include "kernel/linux_errno.h"
#include "kernel/fs_context.h"
#include "kernel/process_runtime.h"
#include "kernel/vfs_runtime.h"
#include "stdio.h"
#include "string.h"

extern int ext4_settimes(vfs_superblock_t *sb, const vfs_inode_t *inode,
                         uint32_t atime, uint32_t mtime, int set_atime, int set_mtime);
extern int ext4_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                        uint16_t mode, uint32_t uid, uint32_t gid,
                        uint32_t mask);

#define g_mount_table (*vfs_mount_namespace_active_table())
#define g_mount_at(index) \
    (*vfs_mount_table_at(&g_mount_table, (uint32_t)(index)))
#define g_mount_count (g_mount_table.mount_count)
#define g_next_peer_group (g_mount_table.next_peer_group)
#define g_next_mount_id (g_mount_table.next_mount_id)

typedef struct {
    char normalized[VFS_PATH_MAX];
    char resolved_prefix[VFS_PATH_MAX];
    char target[VFS_PATH_MAX];
    char redirected[VFS_PATH_MAX];
} vfs_resolve_workspace_t;

typedef struct {
    char old_normalized[VFS_PATH_MAX];
    char new_normalized[VFS_PATH_MAX];
    char new_parent[VFS_PATH_MAX];
} vfs_rename_workspace_t;

typedef struct {
    vfs_superblock_t mount;
} vfs_bind_workspace_t;

typedef struct {
    volatile uint32_t locked;
    uintptr_t owner;
} vfs_replayable_lock_t;

/* Used only before the scheduler has a current task and per-task scratch. */
static vfs_resolve_workspace_t g_boot_resolve_workspace;
static volatile uint32_t g_boot_resolve_lock;
static vfs_rename_workspace_t g_rename_workspace;
static vfs_replayable_lock_t g_rename_lock;
/*
 * A superblock contains a full VFS_PATH_MAX mountpoint.  Recursive bind
 * mounting previously kept two superblocks and another path buffer in one
 * kernel stack frame.  Serialize this infrequent namespace mutation and reuse
 * one static staging object so a userspace mount request cannot exhaust the
 * small per-task kernel stack.
 */
static vfs_bind_workspace_t g_bind_workspace;
static vfs_replayable_lock_t g_bind_lock;
static char g_parent_path[VFS_PATH_MAX];
static vfs_replayable_lock_t g_parent_path_lock;

static void vfs_replayable_lock(vfs_replayable_lock_t *lock) {
    uintptr_t owner = kernel_current_context_token();
    if (owner && __atomic_load_n(&lock->locked, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&lock->owner, __ATOMIC_RELAXED) == owner)
        return;
    while (__atomic_exchange_n(&lock->locked, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&lock->locked, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
    __atomic_store_n(&lock->owner, owner, __ATOMIC_RELEASE);
}

static void vfs_replayable_unlock(vfs_replayable_lock_t *lock) {
    __atomic_store_n(&lock->owner, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&lock->locked, 0u, __ATOMIC_RELEASE);
}

static void vfs_boot_resolve_lock(void) {
    while (__atomic_exchange_n(
            &g_boot_resolve_lock, 1u, __ATOMIC_ACQUIRE))
        __asm__ __volatile__("yield");
}

static void vfs_boot_resolve_unlock(void) {
    __atomic_store_n(&g_boot_resolve_lock, 0u, __ATOMIC_RELEASE);
}

static int mount_path_is_at_or_below(const char *mountpoint,
                                     const char *target);
static int path_copy_join(char out[VFS_PATH_MAX], const char *prefix,
                          const char *suffix);
static vfs_superblock_t *vfs_find_visible_mount(const char *path);

static int text_equal(const char *a, const char *b) {
    while (*a && *b && *a == *b) { ++a; ++b; }
    return *a == 0 && *b == 0;
}

static int component_copy(const char **path, char name[VFS_NAME_MAX]) {
    const char *p = *path;
    uint32_t n = 0;
    while (*p == '/') ++p;
    if (!*p) {
        *path = p;
        return 0;
    }
    while (*p && *p != '/') {
        if (n + 1u >= VFS_NAME_MAX) return -1;
        name[n++] = *p++;
    }
    name[n] = 0;
    *path = p;
    return 1;
}

static int normalize_absolute_path(const char *path, char out[VFS_PATH_MAX]) {
    uint32_t length = 1u;
    uint32_t position = 0;
    if (!path || path[0] != '/') return -1;
    out[0] = '/';
    out[1] = 0;
    while (path[position]) {
        uint32_t start;
        uint32_t count;
        while (path[position] == '/') ++position;
        if (!path[position]) break;
        start = position;
        while (path[position] && path[position] != '/') ++position;
        count = position - start;
        if (count == 1u && path[start] == '.') continue;
        if (count == 2u && path[start] == '.' && path[start + 1u] == '.') {
            if (length > 1u) {
                while (length > 1u && out[length - 1u] != '/') --length;
                if (length > 1u) --length;
            }
            out[length] = 0;
            continue;
        }
        if (length > 1u) {
            if (length + 1u >= VFS_PATH_MAX) return -1;
            out[length++] = '/';
        }
        if (count >= VFS_NAME_MAX || length + count >= VFS_PATH_MAX) return -1;
        for (uint32_t i = 0; i < count; ++i) out[length++] = path[start + i];
        out[length] = 0;
    }
    return 0;
}

static int append_component(char path[VFS_PATH_MAX], const char *component) {
    uint32_t length = 0;
    uint32_t count = 0;
    while (path[length]) ++length;
    while (component[count]) ++count;
    if (length > 1u && length + 1u >= VFS_PATH_MAX) return -1;
    if (length > 1u) path[length++] = '/';
    if (length + count >= VFS_PATH_MAX) return -1;
    for (uint32_t i = 0; i < count; ++i) path[length++] = component[i];
    path[length] = 0;
    return 0;
}

void vfs_bootstrap_init(void) {
    vfs_mount_namespace_bootstrap();
    vfs_path_cache_runtime_reset();
    vfs_filesystem_registry_reset();
    vfs_register("proc", procfs_mount);
    vfs_register("sysfs", sysfs_mount);
    vfs_register("tmpfs", tmpfs_mount);
    vfs_register("devtmpfs", devtmpfs_mount);
    vfs_register("cgroup2", cgroupfs_mount);
#ifdef CONFIG_OVERLAY_FS
    {
        extern int overlayfs_mount(const char *dev, const char *mountpoint);
        vfs_register("overlay", overlayfs_mount);
    }
#endif
}

int vfs_register(const char *name,
                 int (*mount_fn)(const char *device, const char *target)) {
    return vfs_filesystem_registry_register(name, mount_fn);
}

int vfs_mount(const char *device, const char *target,
              const char *filesystem) {
    if (!device || !target || !filesystem) return -1;
    return vfs_filesystem_registry_mount(filesystem, device, target);
}

int vfs_mount_blockdev(block_device_t *device, const char *target,
                       const char *filesystem) {
    if (!device || !target || !filesystem) return -1;
#ifdef CONFIG_FS_EXT4
    if (text_equal(filesystem, "ext4"))
        return ext4_mount_block(device, target);
#endif
#ifdef CONFIG_FS_SQUASHFS
    if (text_equal(filesystem, "squashfs"))
        return squashfs_mount_block(device, target);
#endif
#ifdef CONFIG_FS_EROFS
    if (text_equal(filesystem, "erofs"))
        return erofs_mount_block(device, target);
#endif
#ifdef CONFIG_FS_XFS
    if (text_equal(filesystem, "xfs"))
        return xfs_mount_block(device, target);
#endif
#ifdef CONFIG_FS_BTRFS
    if (text_equal(filesystem, "btrfs"))
        return btrfs_mount_block(device, target);
#endif
    return -1;
}

int vfs_inode_get_block_device(const vfs_inode_t *inode,
                               block_device_t **output) {
    if (!inode || !output ||
        (inode->mode & 0xf000u) != VFS_INODE_BLK)
        return -1;
    *output = block_find_linux_device(inode->rdev);
    return *output ? 0 : -1;
}

static int vfs_superblock_index(const vfs_superblock_t *sb) {
    if (!sb) return -1;
    for (int index = 0; index < g_mount_count; ++index) {
        if (&g_mount_at(index) == sb) return index;
    }
    return -1;
}

static int vfs_path_cache_allowed(const char *path) {
    vfs_superblock_t *sb = path ? vfs_find_visible_mount(path) : 0;
    return !sb || !(sb->runtime_flags & VFS_SUPERBLOCK_DYNAMIC_LOOKUP);
}

static int vfs_path_cache_lookup(const char *path, vfs_inode_t *inode,
                                 vfs_superblock_t **sb, int *miss) {
    vfs_path_cache_result_t result;
    vfs_mount_table_t *table;

    if (!vfs_path_cache_allowed(path) ||
        !vfs_path_cache_runtime_lookup(
            path, vfs_mount_namespace_current(), &result))
        return 0;
    if (miss) *miss = result.miss != 0;
    if (result.miss) return 1;
    table = vfs_mount_namespace_active_table();
    if (result.superblock_index >= (uint32_t)table->mount_count)
        return 0;
    if (inode) *inode = result.inode;
    if (sb)
        *sb = vfs_mount_table_at(table, result.superblock_index);
    return 1;
}

static void vfs_path_cache_store(const char *path, int miss,
                                 const vfs_inode_t *inode,
                                 const vfs_superblock_t *sb) {
    int sb_index = 0;
    if (!vfs_path_cache_allowed(path)) return;
    if (!miss) {
        if (!inode || !sb) return;
        sb_index = vfs_superblock_index(sb);
        if (sb_index < 0) return;
    }
    vfs_path_cache_runtime_store(
        path, vfs_mount_namespace_current(), miss, inode,
        (uint32_t)sb_index);
}

void vfs_path_cache_invalidate(const char *path) {
    (void)path;
    vfs_path_cache_invalidate_all();
}

static int mount_path_matches(const char *path, const char *mountpoint) {
    uint32_t length = 0;
    while (mountpoint[length] && path[length] == mountpoint[length]) ++length;
    if (mountpoint[length]) return 0;
    return length == 1u || path[length] == 0 || path[length] == '/';
}

static vfs_superblock_t *vfs_find_visible_mount(const char *path) {
    vfs_superblock_t *current = 0;
    int current_index = -1;
    int index;
    if (!path || path[0] != '/') return 0;
    for (index = 0; index < g_mount_count; ++index) {
        if (!g_mount_at(index).parent_mount_id &&
            text_equal(g_mount_at(index).mountpoint, "/")) {
            current = &g_mount_at(index);
            current_index = index;
        }
    }
    if (!current) return 0;
    for (int depth = 0; depth < g_mount_count; ++depth) {
        int child = -1;
        for (index = 0; index < g_mount_count; ++index) {
            if (index == current_index ||
                g_mount_at(index).parent_mount_id != current->mount_id ||
                !mount_path_matches(path, g_mount_at(index).mountpoint))
                continue;
            child = index;
        }
        if (child < 0) break;
        current = &g_mount_at(child);
        current_index = child;
    }
    return current;
}

static int vfs_mount_has_ancestor(const vfs_superblock_t *mount,
                                  uint64_t ancestor_mount_id) {
    uint64_t parent_mount_id;
    int index;
    if (!mount || !ancestor_mount_id) return 0;
    parent_mount_id = mount->parent_mount_id;
    for (int depth = 0; depth < g_mount_count && parent_mount_id; ++depth) {
        vfs_superblock_t *parent = 0;
        if (parent_mount_id == ancestor_mount_id) return 1;
        for (index = 0; index < g_mount_count; ++index) {
            if (g_mount_at(index).mount_id != parent_mount_id) continue;
            parent = &g_mount_at(index);
            break;
        }
        if (!parent || parent->parent_mount_id == parent_mount_id) break;
        parent_mount_id = parent->parent_mount_id;
    }
    return 0;
}

static int vfs_add_superblock_internal(vfs_superblock_t *sb,
                                       int notify_change) {
    vfs_superblock_t *covered;
    uint64_t parent_mount_id = 0;
    uint32_t n;
    uint8_t *dst;
    const uint8_t *src;
    if (!sb || g_mount_count < 0 ||
        vfs_mount_table_reserve(
            &g_mount_table, (uint32_t)g_mount_count + 1u) < 0)
        return -1;
    covered = vfs_find_visible_mount(sb->mountpoint);
    if (covered) {
        parent_mount_id = text_equal(covered->mountpoint, sb->mountpoint) ?
            covered->parent_mount_id : covered->mount_id;
    }
    dst = (uint8_t *)&g_mount_at(g_mount_count);
    src = (const uint8_t *)sb;
    for (n = 0; n < sizeof(*sb); ++n) dst[n] = src[n];
    if (!g_mount_at(g_mount_count).propagation)
        g_mount_at(g_mount_count).propagation = VFS_MOUNT_PRIVATE;
    if (!g_mount_at(g_mount_count).mount_id) {
        if (!g_next_mount_id) g_next_mount_id = 1u;
        g_mount_at(g_mount_count).mount_id = g_next_mount_id++;
    }
    g_mount_at(g_mount_count).parent_mount_id = parent_mount_id;
    if (!vfs_superblock_acquire(&g_mount_at(g_mount_count))) {
        memset(&g_mount_at(g_mount_count), 0, sizeof(g_mount_at(g_mount_count)));
        return -1;
    }
    sb->instance = g_mount_at(g_mount_count).instance;
    sb->instance_generation =
        g_mount_at(g_mount_count).instance_generation;
    ++g_mount_count;
    vfs_path_cache_runtime_invalidate_subtree(sb->mountpoint);
    if (notify_change) vfs_mount_namespace_note_change();
    return 0;
}

int vfs_add_superblock(vfs_superblock_t *sb) {
    return vfs_add_superblock_internal(sb, 1);
}

static int mount_path_is_at_or_below(const char *mountpoint, const char *target) {
    uint32_t index = 0;
    while (target[index] && mountpoint[index] == target[index]) ++index;
    if (target[index]) return 0;
    if (index == 1u && target[0] == '/') return 1;
    return !mountpoint[index] || mountpoint[index] == '/';
}

int vfs_set_mount_propagation(const char *target, uint32_t propagation,
                              int recursive) {
    int changed = 0;
    int index;
    vfs_superblock_t *selected;
    if (!target || target[0] != '/' || propagation < VFS_MOUNT_SHARED ||
        propagation > VFS_MOUNT_UNBINDABLE) return -1;
    selected = vfs_find_visible_mount(target);
    if (!selected) return -1;
    for (index = 0; index < g_mount_count; ++index) {
        vfs_superblock_t *mount = &g_mount_at(index);
        if (mount != selected &&
            (!recursive ||
             !vfs_mount_has_ancestor(mount, selected->mount_id))) continue;
        mount->propagation = propagation;
        if (propagation == VFS_MOUNT_SHARED) {
            if (!mount->peer_group) mount->peer_group = g_next_peer_group++;
            mount->master_group = 0;
        } else if (propagation == VFS_MOUNT_SLAVE) {
            mount->master_group = mount->peer_group;
            mount->peer_group = 0;
        } else {
            mount->peer_group = 0;
            mount->master_group = 0;
        }
        ++changed;
    }
    if (changed) {
        vfs_mount_namespace_note_change();
    }
    return changed ? 0 : -1;
}

int vfs_bind_mount(const char *source, const char *target, int recursive) {
    vfs_inode_t source_inode;
    vfs_inode_t target_inode;
    vfs_superblock_t *source_sb = 0;
    uint32_t length = 0;
    int original_mount_count;
    int result = -1;
    int source_result;
    int target_result;
    if (!source || !target || source[0] != '/' || target[0] != '/') return -1;
    vfs_replayable_lock(&g_bind_lock);
    source_result = vfs_resolve(source, &source_inode, &source_sb, 0, 0);
    target_result = vfs_resolve(target, &target_inode, 0, 0, 0);
    if (source_result < 0 || !source_sb || target_result < 0) goto out;
    if (((source_inode.mode & 0xf000u) == VFS_INODE_DIR) !=
        ((target_inode.mode & 0xf000u) == VFS_INODE_DIR)) goto out;
    if (source_sb->propagation == VFS_MOUNT_UNBINDABLE) goto out;
    original_mount_count = g_mount_count;
    g_bind_workspace.mount = *source_sb;
    g_bind_workspace.mount.root = source_inode;
    while (target[length]) {
        if (length + 1u >= sizeof(g_bind_workspace.mount.mountpoint)) goto out;
        g_bind_workspace.mount.mountpoint[length] = target[length];
        ++length;
    }
    g_bind_workspace.mount.mountpoint[length] = 0;
    g_bind_workspace.mount.propagation = VFS_MOUNT_PRIVATE;
    g_bind_workspace.mount.peer_group = 0;
    g_bind_workspace.mount.master_group = 0;
    g_bind_workspace.mount.mount_id = 0;
    g_bind_workspace.mount.parent_mount_id = 0;
    if (vfs_add_superblock_internal(&g_bind_workspace.mount, 0) < 0) goto out;
    if (recursive) {
        uint32_t source_length = 0;
        while (source[source_length]) ++source_length;
        for (int index = 0; index < original_mount_count; ++index) {
            const char *suffix;
            if (!mount_path_is_at_or_below(g_mount_at(index).mountpoint,
                                            source) ||
                text_equal(g_mount_at(index).mountpoint, source) ||
                g_mount_at(index).propagation == VFS_MOUNT_UNBINDABLE)
                continue;
            suffix = g_mount_at(index).mountpoint +
                     (source_length == 1u ? 0u : source_length);
            g_bind_workspace.mount = g_mount_at(index);
            if (path_copy_join(g_bind_workspace.mount.mountpoint,
                               target, suffix) < 0)
                goto rollback;
            g_bind_workspace.mount.mount_id = 0;
            g_bind_workspace.mount.parent_mount_id = 0;
            if (vfs_add_superblock_internal(&g_bind_workspace.mount, 0) < 0)
                goto rollback;
        }
    }
    vfs_mount_namespace_note_change();
    result = 0;
    goto out;

rollback:
    for (int index = original_mount_count; index < g_mount_count; ++index) {
        vfs_superblock_release(&g_mount_at(index));
    }
    g_mount_count = original_mount_count;
    vfs_path_cache_invalidate_all();
out:
    vfs_replayable_unlock(&g_bind_lock);
    return result;
}

int vfs_mount_id_for_superblock(const vfs_superblock_t *sb,
                                uint64_t *mount_id_out) {
    if (!sb || !mount_id_out) return -1;
    for (int index = 0; index < g_mount_count; ++index) {
        if (&g_mount_at(index) != sb &&
            !vfs_superblock_same_filesystem(&g_mount_at(index), sb))
            continue;
        *mount_id_out = g_mount_at(index).mount_id;
        return 0;
    }
    return -1;
}

vfs_superblock_t *vfs_superblock_for_mount_id(uint64_t mount_id) {
    if (!mount_id) return 0;
    for (int index = 0; index < g_mount_count; ++index)
        if (g_mount_at(index).mount_id == mount_id) return &g_mount_at(index);
    return 0;
}

vfs_superblock_t *vfs_superblock_for_device_name(const char *device_name) {
    const char *basename;
    if (!device_name || !device_name[0]) return 0;
    basename = device_name;
    for (const char *cursor = device_name; *cursor; ++cursor)
        if (*cursor == '/' && cursor[1]) basename = cursor + 1;
    for (int index = g_mount_count - 1; index >= 0; --index)
        if (g_mount_at(index).dev_name[0] &&
            (text_equal(g_mount_at(index).dev_name, device_name) ||
             text_equal(g_mount_at(index).dev_name, basename)))
            return &g_mount_at(index);
    return 0;
}

int vfs_remount(const char *target, uint32_t mount_flags) {
    vfs_superblock_t *mount;
    if (!target || target[0] != '/') return -1;
    mount = vfs_find_visible_mount(target);
    if (!mount || !text_equal(mount->mountpoint, target)) return -1;
    mount->mount_flags = mount_flags;
    vfs_mount_namespace_note_change();
    return 0;
}

int vfs_umount(const char *target, int detach) {
    vfs_superblock_t *selected_mount;
    uint64_t selected_mount_id;
    int selected = -1;
    int index;
    int output = 0;
    if (!target || target[0] != '/') return -1;
    if (text_equal(target, "/")) {
        if (!detach) return -1;
        target = "/.edgeos-pivot-old";
    }
    selected_mount = vfs_find_visible_mount(target);
    if (!selected_mount || !text_equal(selected_mount->mountpoint, target))
        return -1;
    selected_mount_id = selected_mount->mount_id;
    for (index = 0; index < g_mount_count; ++index)
        if (&g_mount_at(index) == selected_mount) selected = index;
    if (selected < 0 || !selected_mount_id) return -1;
    if (!detach) {
        for (index = 0; index < g_mount_count; ++index) {
            if (vfs_mount_has_ancestor(&g_mount_at(index), selected_mount_id))
                return -2;
        }
    }
    for (index = 0; index < g_mount_count; ++index) {
        int remove = index == selected;
        if (detach &&
            vfs_mount_has_ancestor(&g_mount_at(index), selected_mount_id))
            remove = 1;
        if (remove) {
            vfs_superblock_release(&g_mount_at(index));
            continue;
        }
        if (output != index) g_mount_at(output) = g_mount_at(index);
        ++output;
    }
    g_mount_count = output;
    vfs_path_cache_invalidate_all();
    vfs_mount_namespace_note_change();
    return 0;
}

static int path_copy_join(char out[VFS_PATH_MAX], const char *prefix,
                          const char *suffix) {
    uint32_t length = 0;
    uint32_t index = 0;
    while (prefix[length]) {
        if (length + 1u >= VFS_PATH_MAX) return -1;
        out[length] = prefix[length];
        ++length;
    }
    if (length && out[length - 1u] == '/' && suffix[0] == '/') ++suffix;
    while (suffix[index]) {
        if (length + 1u >= VFS_PATH_MAX) return -1;
        out[length++] = suffix[index++];
    }
    out[length] = 0;
    return 0;
}

int vfs_pivot_root(const char *new_root, const char *put_old) {
    static const char detached_old_root[] = "/.edgeos-pivot-old";
    vfs_inode_t new_inode;
    vfs_inode_t old_inode;
    vfs_superblock_t *new_root_mount;
    vfs_superblock_t *old_root_mount;
    uint32_t new_length = 0;
    uint32_t workspace_pages = 0;
    const char *old_relative;
    char *workspace;
    int index;
    if (!new_root || !put_old || new_root[0] != '/' || put_old[0] != '/' ||
        text_equal(new_root, "/")) return -1;
    while (new_root[new_length]) ++new_length;
    if (!text_equal(new_root, put_old) &&
        (!mount_path_is_at_or_below(put_old, new_root) ||
         put_old[new_length] != '/')) return -1;
    if (vfs_resolve(new_root, &new_inode, 0, 0, 0) < 0 ||
        vfs_resolve(put_old, &old_inode, 0, 0, 0) < 0 ||
        (new_inode.mode & 0xf000u) != VFS_INODE_DIR ||
        (old_inode.mode & 0xf000u) != VFS_INODE_DIR) return -1;
    new_root_mount = vfs_find_visible_mount(new_root);
    old_root_mount = vfs_find_visible_mount("/");
    if (!new_root_mount || !old_root_mount ||
        !text_equal(new_root_mount->mountpoint, new_root)) return -1;
    old_relative = text_equal(new_root, put_old) ? detached_old_root :
                   put_old + new_length;
    workspace = vfs_mount_path_workspace_allocate(
        (uint32_t)g_mount_count, &workspace_pages);
    if (!workspace) return -1;
    for (index = 0; index < g_mount_count; ++index) {
        char *rebased = workspace + (uint64_t)index * VFS_PATH_MAX;
        const char *mountpoint = g_mount_at(index).mountpoint;
        if (&g_mount_at(index) == new_root_mount ||
            vfs_mount_has_ancestor(&g_mount_at(index),
                                   new_root_mount->mount_id)) {
            const char *suffix = mountpoint + new_length;
            if (!suffix[0]) suffix = "/";
            if (path_copy_join(rebased, "/", suffix) < 0) {
                vfs_mount_path_workspace_release(
                    workspace, workspace_pages);
                return -1;
            }
        } else {
            const char *suffix = text_equal(mountpoint, "/") ? "" : mountpoint;
            if (path_copy_join(rebased, old_relative, suffix) < 0) {
                vfs_mount_path_workspace_release(
                    workspace, workspace_pages);
                return -1;
            }
        }
    }
    for (index = 0; index < g_mount_count; ++index) {
        const char *rebased =
            workspace + (uint64_t)index * VFS_PATH_MAX;
        uint32_t length = 0;
        while (rebased[length]) {
            g_mount_at(index).mountpoint[length] = rebased[length];
            ++length;
        }
        g_mount_at(index).mountpoint[length] = 0;
    }
    new_root_mount->parent_mount_id = 0;
    old_root_mount->parent_mount_id = new_root_mount->mount_id;
    vfs_mount_path_workspace_release(workspace, workspace_pages);
    vfs_path_cache_invalidate_all();
    vfs_mount_namespace_note_change();
    return 0;
}

int vfs_mount_exists(const char *target, const char *fsname, const char *dev) {
    int i;
    if (!target || !fsname) return 0;
    for (i = 0; i < g_mount_count; ++i) {
        const char *mounted_dev = g_mount_at(i).dev_name[0] ? g_mount_at(i).dev_name : "";
        const char *a = g_mount_at(i).mountpoint;
        const char *b = target;
        while (*a && *b && *a == *b) { ++a; ++b; }
        if (*a || *b) continue;
        a = g_mount_at(i).fs_name;
        b = fsname;
        while (*a && *b && *a == *b) { ++a; ++b; }
        if (*a || *b) continue;
        if (dev && dev[0]) {
            a = mounted_dev;
            b = dev;
            while (*a && *b && *a == *b) { ++a; ++b; }
            if (*a || *b) continue;
        }
        return 1;
    }
    return 0;
}

static int vfs_resolve_inner(const char *path, vfs_inode_t *out_inode,
                             vfs_superblock_t **out_sb, vfs_inode_t *out_parent,
                             char *leaf, uint32_t depth,
                             int follow_final_symlink,
                             vfs_resolve_workspace_t *workspace,
                             const char *resolution_root) {
    const char *p;
    vfs_superblock_t *sb = 0;
    vfs_inode_t current;
    vfs_inode_t parent;
    char component[VFS_NAME_MAX];
    char *resolved_prefix = workspace->resolved_prefix;
    uint32_t selected_length = 0;

    if (!path || path[0] != '/' ||
        depth > VFS_MAX_SYMLINK_FOLLOWS) return -1;
    sb = vfs_find_visible_mount(path);
    if (sb)
        while (sb->mountpoint[selected_length]) ++selected_length;
    if (!sb) return -1;
    current = sb->root;
    parent = current;
    if (selected_length > 1u) {
        uint32_t n;
        if (selected_length >= VFS_PATH_MAX) return -1;
        for (n = 0; n < selected_length; ++n) resolved_prefix[n] = path[n];
        resolved_prefix[selected_length] = 0;
    } else {
        resolved_prefix[0] = '/';
        resolved_prefix[1] = 0;
    }
    p = selected_length > 1u ? path + selected_length : path;
    for (;;) {
        int status = component_copy(&p, component);
        if (status < 0) return -1;
        if (status == 0) break;
        if (!sb->ops || !sb->ops->lookup) return -1;
        parent = current;
        if (sb->ops->lookup(sb, &current, component, &current) < 0) {
            if (leaf) {
                uint32_t n = 0;
                while (component[n] && n + 1u < VFS_NAME_MAX) { leaf[n] = component[n]; ++n; }
                leaf[n] = 0;
            }
            if (out_parent) *out_parent = parent;
            if (out_sb) *out_sb = sb;
            return -1;
        }
        if ((current.mode & 0xf000u) == VFS_INODE_LNK) {
            char *target = workspace->target;
            char *redirected = workspace->redirected;
            char *normalized = workspace->normalized;
            int n;
            uint32_t length = 0;
            const char *remaining = p;
            while (*remaining == '/') ++remaining;
            if (!*remaining && !follow_final_symlink) {
                if (out_inode) *out_inode = current;
                if (out_parent) *out_parent = parent;
                if (out_sb) *out_sb = sb;
                return 0;
            }
            if (!sb->ops->readlink) return -1;
            n = sb->ops->readlink(sb, &current, target, VFS_PATH_MAX - 1u);
            if (n <= 0 || n >= VFS_PATH_MAX) return -1;
            target[n] = 0;
            while (target[length]) ++length;
            if (length >= VFS_PATH_MAX) return -1;
            for (uint32_t index = 0; index <= length; ++index)
                redirected[index] = target[index];
            {
                uint32_t source = 0;
                if (*p && length && redirected[length - 1u] != '/') {
                    if (length + 1u >= VFS_PATH_MAX) return -1;
                    redirected[length++] = '/';
                }
                while (p[source]) {
                    if (length + 1u >= VFS_PATH_MAX) return -1;
                    redirected[length++] = p[source++];
                }
            }
            redirected[length] = 0;
            if (kernel_fs_path_resolve(
                    resolution_root ? resolution_root : "/",
                    resolved_prefix, redirected, target, VFS_PATH_MAX,
                    normalized, VFS_PATH_MAX) < 0)
                return -1;
            return vfs_resolve_inner(normalized, out_inode, out_sb, out_parent, leaf,
                                     depth + 1u, follow_final_symlink,
                                     workspace, resolution_root);
        }
        if (append_component(resolved_prefix, component) < 0) return -1;
    }
    if (out_inode) *out_inode = current;
    if (out_parent) *out_parent = parent;
    if (out_sb) *out_sb = sb;
    return 0;
}

static int vfs_parent_lookup(const char *path, vfs_inode_t *parent,
                             vfs_superblock_t **sb, char leaf[VFS_NAME_MAX]);

static int vfs_resolve_mode(const char *path, vfs_inode_t *out_inode,
                            vfs_superblock_t **out_sb,
                            vfs_inode_t *out_parent, char *leaf,
                            int follow_final_symlink,
                            char *resolved, uint32_t resolved_capacity,
                            const char *resolution_root) {
    vfs_superblock_t *resolved_superblock = 0;
    vfs_superblock_t **effective_superblock =
        out_sb ? out_sb : &resolved_superblock;
    kernel_vfs_current_context_t context;
    vfs_resolve_workspace_t *workspace;
    int boot_workspace = 0;
    int result;
    if (arch_vfs_current_context(&context) == 0 &&
        context.resolve_workspace &&
        context.resolve_workspace_capacity >= sizeof(*workspace)) {
        workspace = (vfs_resolve_workspace_t *)context.resolve_workspace;
    } else {
        vfs_boot_resolve_lock();
        workspace = &g_boot_resolve_workspace;
        boot_workspace = 1;
    }
    if (normalize_absolute_path(path, workspace->normalized) < 0) {
        if (boot_workspace) vfs_boot_resolve_unlock();
        return -1;
    }
    if (follow_final_symlink && !resolved && !out_parent && !leaf) {
        int cached_miss = 0;
        if (vfs_path_cache_lookup(workspace->normalized, out_inode,
                                  effective_superblock, &cached_miss)) {
            if (boot_workspace) vfs_boot_resolve_unlock();
            return cached_miss ? -1 : 0;
        }
    }
    result = vfs_resolve_inner(workspace->normalized, out_inode,
                               effective_superblock,
                               out_parent, leaf, 0, follow_final_symlink,
                               workspace, resolution_root);
    if (result == 0 && resolved) {
        uint32_t length = 0;
        while (workspace->resolved_prefix[length]) ++length;
        if (!resolved_capacity || length >= resolved_capacity) {
            result = -1;
        } else {
            for (uint32_t index = 0; index <= length; ++index)
                resolved[index] = workspace->resolved_prefix[index];
        }
    }
    if (follow_final_symlink && !resolved && !out_parent && !leaf) {
        if (result == 0)
            vfs_path_cache_store(workspace->normalized, 0,
                                 out_inode, *effective_superblock);
        else
            vfs_path_cache_store(workspace->normalized, 1, 0, 0);
    }
    if (boot_workspace) vfs_boot_resolve_unlock();
    return result;
}

int vfs_resolve(const char *path, vfs_inode_t *out_inode,
                vfs_superblock_t **out_sb, vfs_inode_t *out_parent,
                char *leaf) {
    return vfs_resolve_mode(path, out_inode, out_sb, out_parent, leaf, 1,
                            0, 0, "/");
}

int vfs_resolve_nofollow(const char *path, vfs_inode_t *out_inode,
                         vfs_superblock_t **out_sb) {
    return vfs_resolve_mode(path, out_inode, out_sb, 0, 0, 0, 0, 0,
                            "/");
}

int vfs_resolve_canonical(const char *path, char *resolved,
                          uint32_t resolved_capacity,
                          vfs_inode_t *out_inode,
                          vfs_superblock_t **out_sb) {
    if (!resolved || !resolved_capacity) return -1;
    return vfs_resolve_mode(path, out_inode, out_sb, 0, 0, 1,
                            resolved, resolved_capacity, "/");
}

int vfs_resolve_canonical_rooted(const char *path, const char *root,
                                 char *resolved,
                                 uint32_t resolved_capacity,
                                 vfs_inode_t *out_inode,
                                 vfs_superblock_t **out_sb) {
    if (!root || root[0] != '/' || !resolved || !resolved_capacity)
        return -1;
    return vfs_resolve_mode(path, out_inode, out_sb, 0, 0, 1,
                            resolved, resolved_capacity, root);
}

int vfs_resolve_cached(const char *path, vfs_inode_t *out_inode,
                       vfs_superblock_t **out_sb, int *negative) {
    int miss = 0;

    if (!path || path[0] != '/') return 0;
    if (!vfs_path_cache_lookup(path, out_inode, out_sb, &miss))
        return 0;
    if (negative) *negative = miss;
    if (miss && out_sb) *out_sb = 0;
    return 1;
}

int vfs_pread(const char *path, uint32_t off, void *out, uint32_t len) {
    vfs_inode_t inode;
    vfs_superblock_t *sb;
    int n;
    if (!out || vfs_resolve(path, &inode, &sb, 0, 0) < 0 || !sb || !sb->ops || !sb->ops->read) {
        printf("[arm64-vfs] pread resolve failed path=%s\n", path ? path : "(null)");
        return -1;
    }
    if (off >= inode.size) return 0;
    if (len > inode.size - off) len = inode.size - off;
    n = sb->ops->read(sb, &inode, off, out, len);
    if (n != (int)len)
        printf("[arm64-vfs] pread short path=%s fs=%s ino=%u size=%u off=%u len=%u result=%d\n",
               path, sb->fs_name, inode.ino, inode.size, off, len, n);
    return n;
}

int vfs_read_file(const char *path, char *out, uint32_t max) {
    vfs_inode_t inode;
    vfs_superblock_t *sb;
    uint32_t count;
    if (!out || vfs_resolve(path, &inode, &sb, 0, 0) < 0 || !sb || !sb->ops ||
        !sb->ops->read || (inode.mode & 0xf000u) != VFS_INODE_FILE) return -1;
    count = inode.size < max ? inode.size : max;
    return sb->ops->read(sb, &inode, 0, out, count);
}

int vfs_write_file(const char *path, const char *buffer, uint32_t length) {
    vfs_inode_t inode;
    vfs_superblock_t *sb = 0;
    int existed = 0;
    int result;

    if (!path || path[0] != '/' || (!buffer && length != 0))
        return -EDGE_LINUX_EINVAL;
    result = vfs_resolve(path, &inode, &sb, 0, 0);
    if (result < 0) {
        result = vfs_create_file(
            path, (uint16_t)(0666u & (uint16_t)~kernel_current_umask()),
            &inode, &sb);
        if (result < 0) return result;
    } else if (vfs_permission_check(&inode, 2) < 0) {
        return -EDGE_LINUX_EACCES;
    } else {
        existed = 1;
    }
    if ((inode.mode & 0xf000u) != VFS_INODE_FILE)
        return -EDGE_LINUX_EINVAL;
    if (!sb || !sb->ops || !sb->ops->write)
        return -EDGE_LINUX_EROFS;
    if (existed) {
        if (!sb->ops->truncate)
            return -EDGE_LINUX_EROFS;
        result = sb->ops->truncate(sb, &inode, 0);
        if (result < 0) return kernel_vfs_path_result(result);
    }
    result = sb->ops->write(sb, &inode, 0, buffer, length);
    if (result < 0) return kernel_vfs_path_result(result);
    if (vfs_sync_mutation_if_required(sb, 0) < 0)
        return -EDGE_LINUX_EIO;
    vfs_path_cache_invalidate_all();
    return result;
}

int vfs_readlink(const char *path, char *out, uint32_t max) {
    vfs_inode_t inode;
    vfs_superblock_t *sb = 0;
    if (!path || !out || !max ||
        vfs_resolve_nofollow(path, &inode, &sb) < 0 || !sb || !sb->ops ||
        !sb->ops->readlink || (inode.mode & 0xf000u) != VFS_INODE_LNK)
        return -1;
    return sb->ops->readlink(sb, &inode, out, max);
}

static int vfs_parent_path_copy(const char *path,
                                char parent[VFS_PATH_MAX]) {
    uint32_t length = 0;
    uint32_t slash;
    if (!path || path[0] != '/' || !parent) return -1;
    while (path[length]) {
        if (length + 1u >= VFS_PATH_MAX) return -1;
        ++length;
    }
    while (length > 1u && path[length - 1u] == '/') --length;
    slash = length;
    while (slash > 0u && path[slash - 1u] != '/') --slash;
    if (!slash || slash == length) return -1;
    if (slash <= 1u) {
        parent[0] = '/';
        parent[1] = 0;
        return 0;
    }
    for (uint32_t index = 0; index + 1u < slash; ++index)
        parent[index] = path[index];
    parent[slash - 1u] = 0;
    return 0;
}

static int vfs_parent_lookup(const char *path, vfs_inode_t *parent,
                             vfs_superblock_t **sb, char leaf[VFS_NAME_MAX]) {
    kernel_vfs_current_context_t context;
    char *parent_path = g_parent_path;
    int shared_workspace = 1;
    int result;
    uint32_t length = 0;
    uint32_t slash;
    uint32_t i;
    if (!path || path[0] != '/') return -1;
    while (path[length]) {
        if (length + 1u >= VFS_PATH_MAX) return -1;
        ++length;
    }
    while (length > 1u && path[length - 1u] == '/') --length;
    slash = length;
    while (slash > 0u && path[slash - 1u] != '/') --slash;
    if (slash == length || length - slash >= VFS_NAME_MAX) return -1;
    for (i = 0; i < length - slash; ++i) leaf[i] = path[slash + i];
    leaf[length - slash] = 0;
    if (arch_vfs_current_context(&context) == 0 && context.paths[7] &&
        context.path_capacity >= VFS_PATH_MAX) {
        parent_path = context.paths[7];
        shared_workspace = 0;
    } else {
        vfs_replayable_lock(&g_parent_path_lock);
    }
    if (slash <= 1u) {
        parent_path[0] = '/';
        parent_path[1] = 0;
    } else {
        for (i = 0; i + 1u < slash; ++i) parent_path[i] = path[i];
        parent_path[slash - 1u] = 0;
    }
    result = vfs_resolve(parent_path, parent, sb, 0, 0);
    if (shared_workspace) vfs_replayable_unlock(&g_parent_path_lock);
    return result;
}

int vfs_mkdir_mode(const char *path, uint16_t mode) {
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_inode_t created;
    vfs_superblock_t *sb = 0;
    char leaf[VFS_NAME_MAX];
    int result;
    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    if (vfs_resolve(path, &existing, 0, 0, 0) == 0)
        return -EDGE_LINUX_EEXIST;
    if (vfs_parent_lookup(path, &parent, &sb, leaf) < 0)
        return -EDGE_LINUX_ENOENT;
    if (!leaf[0]) return -EDGE_LINUX_EINVAL;
    if ((parent.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (vfs_permission_check(&parent, 3) < 0)
        return -EDGE_LINUX_EACCES;
    if (!sb || !sb->ops || !sb->ops->mkdir)
        return -EDGE_LINUX_EROFS;
    mode = (uint16_t)(VFS_INODE_DIR | (mode & 07777u));
    result = sb->ops->mkdir(sb, &parent, leaf, mode, &created);
    if (result < 0) return kernel_vfs_path_result(result);
    if (vfs_sync_mutation_if_required(sb, 1) < 0)
        return -EDGE_LINUX_EIO;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_mkdir(const char *path) {
    return vfs_mkdir_mode(
        path, (uint16_t)(0755u & (uint16_t)~kernel_current_umask()));
}

int vfs_create_file(const char *path, uint16_t mode, vfs_inode_t *out_inode,
                    vfs_superblock_t **out_sb) {
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_inode_t created;
    vfs_superblock_t *sb = 0;
    char leaf[VFS_NAME_MAX];
    int result;
    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    if (vfs_resolve(path, &existing, 0, 0, 0) == 0)
        return -EDGE_LINUX_EEXIST;
    if (vfs_parent_lookup(path, &parent, &sb, leaf) < 0)
        return -EDGE_LINUX_ENOENT;
    if (!leaf[0]) return -EDGE_LINUX_EINVAL;
    if ((parent.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (vfs_permission_check(&parent, 3) < 0)
        return -EDGE_LINUX_EACCES;
    if (!sb || !sb->ops || !sb->ops->create)
        return -EDGE_LINUX_EROFS;
    result = sb->ops->create(sb, &parent, leaf,
                             (uint16_t)(mode & 07777u), &created);
    if (result < 0) return kernel_vfs_path_result(result);
    if (vfs_sync_mutation_if_required(sb, 1) < 0)
        return -EDGE_LINUX_EIO;
    if (out_inode) *out_inode = created;
    if (out_sb) *out_sb = sb;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_mknod(const char *path, uint16_t mode, uint64_t rdev) {
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_inode_t created;
    vfs_superblock_t *sb = 0;
    char leaf[VFS_NAME_MAX];
    uint16_t kind = mode & 0xf000u;
    int result;
    if (!kind) kind = VFS_INODE_FILE;
    if (kind != VFS_INODE_FILE && kind != VFS_INODE_SOCK &&
        kind != VFS_INODE_FIFO && kind != VFS_INODE_CHR &&
        kind != VFS_INODE_BLK)
        return -EDGE_LINUX_EINVAL;
    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    if (vfs_resolve(path, &existing, 0, 0, 0) == 0)
        return -EDGE_LINUX_EEXIST;
    if (vfs_parent_lookup(path, &parent, &sb, leaf) < 0)
        return -EDGE_LINUX_ENOENT;
    if (!leaf[0]) return -EDGE_LINUX_EINVAL;
    if ((parent.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (vfs_permission_check(&parent, 3) < 0)
        return -EDGE_LINUX_EACCES;
    if (!sb || !sb->ops) return -EDGE_LINUX_ENOENT;
    mode = (uint16_t)(kind | (mode & 07777u));
    if (kind == VFS_INODE_FILE) {
        if (!sb->ops->create) return -EDGE_LINUX_EROFS;
        result = sb->ops->create(sb, &parent, leaf, mode, &created);
    } else if (sb->ops->mknod) {
        result = sb->ops->mknod(sb, &parent, leaf, mode, rdev, &created);
    } else if (sb->ops->create) {
        result = sb->ops->create(sb, &parent, leaf, mode, &created);
    } else {
        return -EDGE_LINUX_EROFS;
    }
    if (result < 0) return kernel_vfs_path_result(result);
    if (vfs_sync_mutation_if_required(sb, 1) < 0)
        return -EDGE_LINUX_EIO;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_create_special_node(const char *path, uint16_t mode) {
    return vfs_mknod(path, mode, 0);
}

int vfs_create_socket_node(const char *path, uint16_t mode) {
    return vfs_create_special_node(path,
            (uint16_t)(VFS_INODE_SOCK | (mode & 07777u)));
}

int vfs_symlink(const char *target, const char *path) {
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_inode_t created;
    vfs_superblock_t *sb = 0;
    char leaf[VFS_NAME_MAX];
    int result;
    if (!target || !target[0] || !path || path[0] != '/')
        return VFS_PATH_ERR_INVALID;
    if (vfs_resolve(path, &existing, 0, 0, 0) == 0)
        return VFS_PATH_ERR_EXISTS;
    if (vfs_parent_lookup(path, &parent, &sb, leaf) < 0)
        return VFS_PATH_ERR_NOT_FOUND;
    if (!leaf[0]) return VFS_PATH_ERR_INVALID;
    if ((parent.mode & 0xf000u) != VFS_INODE_DIR)
        return VFS_PATH_ERR_NOT_DIRECTORY;
    if (vfs_permission_check(&parent, 3) < 0)
        return VFS_PATH_ERR_ACCESS;
    if (!sb || !sb->ops || !sb->ops->symlink) return VFS_PATH_ERR_IO;
    result = sb->ops->symlink(sb, &parent, leaf, target, 0777u, &created);
    if (result < 0) return result;
    if (vfs_sync_mutation_if_required(sb, 1) < 0) return VFS_PATH_ERR_IO;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_link(const char *old_path, const char *new_path, int follow_source) {
    vfs_inode_t inode;
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_superblock_t *old_sb = 0;
    vfs_superblock_t *new_sb = 0;
    char leaf[VFS_NAME_MAX];
    if (!old_path || !new_path ||
        (follow_source ? vfs_resolve(old_path, &inode, &old_sb, 0, 0) :
                         vfs_resolve_nofollow(old_path, &inode, &old_sb)) < 0 ||
        (inode.mode & 0xf000u) == VFS_INODE_DIR ||
        vfs_resolve(new_path, &existing, 0, 0, 0) == 0 ||
        vfs_parent_lookup(new_path, &parent, &new_sb, leaf) < 0 || !leaf[0] ||
        !vfs_superblock_same_filesystem(old_sb, new_sb) ||
        !new_sb || !new_sb->ops || !new_sb->ops->link)
        return -1;
    {
        int result = new_sb->ops->link(new_sb, &inode, &parent, leaf);
        if (result < 0) return result;
    }
    if (vfs_sync_mutation_if_required(new_sb, 1) < 0) return -1;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_link_inode(vfs_superblock_t *source_sb, const vfs_inode_t *source,
                   const char *new_path) {
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_superblock_t *new_sb = 0;
    char leaf[VFS_NAME_MAX];
    if (!source_sb || !source || !new_path ||
        (source->mode & 0xf000u) == VFS_INODE_DIR ||
        vfs_resolve(new_path, &existing, 0, 0, 0) == 0 ||
        vfs_parent_lookup(new_path, &parent, &new_sb, leaf) < 0 || !leaf[0] ||
        !vfs_superblock_same_filesystem(source_sb, new_sb) ||
        !new_sb->ops || !new_sb->ops->link)
        return -1;
    {
        int result = new_sb->ops->link(
            new_sb, (vfs_inode_t *)source, &parent, leaf);
        if (result < 0) return result;
    }
    if (vfs_sync_mutation_if_required(new_sb, 1) < 0) return -1;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_chmod(const char *path, uint16_t mode) {
    vfs_inode_t inode;
    vfs_superblock_t *sb = 0;
    if (!path || vfs_resolve(path, &inode, &sb, 0, 0) < 0 || !sb) return -1;
    return vfs_inode_chmod(sb, &inode, mode);
}

int vfs_chown(const char *path, uint32_t uid, uint32_t gid) {
    vfs_inode_t inode;
    vfs_superblock_t *sb = 0;
    if (!path || vfs_resolve(path, &inode, &sb, 0, 0) < 0 || !sb) return -1;
    return vfs_inode_chown(sb, &inode, uid, gid,
                           VFS_SETATTR_UID | VFS_SETATTR_GID);
}

int vfs_chown_nofollow(const char *path, uint32_t uid, uint32_t gid) {
    vfs_inode_t inode;
    vfs_superblock_t *sb = 0;
    if (!path || vfs_resolve_nofollow(path, &inode, &sb) < 0 || !sb) return -1;
    return vfs_inode_chown(sb, &inode, uid, gid,
                           VFS_SETATTR_UID | VFS_SETATTR_GID);
}

int vfs_lchown(const char *path, uint32_t uid, uint32_t gid) {
    return vfs_chown_nofollow(path, uid, gid);
}

int vfs_utimens(const char *path, uint32_t atime, uint32_t mtime,
                int set_atime, int set_mtime) {
    vfs_inode_t inode;
    vfs_superblock_t *sb = 0;
    if (!path || vfs_resolve(path, &inode, &sb, 0, 0) < 0 || !sb) return -1;
    return vfs_inode_utimens(sb, &inode, atime, mtime,
                             set_atime, set_mtime);
}

int vfs_unlink(const char *path) {
    vfs_inode_t inode;
    vfs_inode_t parent;
    vfs_superblock_t *sb = 0;
    char leaf[VFS_NAME_MAX];
    if (!path || path[0] != '/' || vfs_resolve_nofollow(path, &inode, &sb) < 0 ||
        vfs_parent_lookup(path, &parent, &sb, leaf) < 0 ||
        !leaf[0] || !sb || !sb->ops || !sb->ops->unlink) return -1;
    if (vfs_inode_open(sb, &inode) < 0) return -1;
    {
        int result = sb->ops->unlink(sb, &parent, leaf);
        if (result < 0) {
            vfs_inode_close(sb, &inode);
            return result;
        }
    }
    vfs_inode_lifetime_orphan_inode(sb, &inode);
    vfs_inode_close(sb, &inode);
    if (vfs_sync_mutation_if_required(sb, 1) < 0) return -1;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_rmdir(const char *path) {
    vfs_inode_t inode;
    vfs_inode_t parent;
    vfs_superblock_t *inode_sb = 0;
    vfs_superblock_t *parent_sb = 0;
    char leaf[VFS_NAME_MAX];
    int result;
    if (!path || path[0] != '/') return VFS_PATH_ERR_INVALID;
    if (text_equal(path, "/")) return VFS_PATH_ERR_BUSY;
    if (vfs_resolve_nofollow(path, &inode, &inode_sb) < 0)
        return VFS_PATH_ERR_NOT_FOUND;
    if ((inode.mode & 0xf000u) != VFS_INODE_DIR)
        return VFS_PATH_ERR_NOT_DIRECTORY;
    if (vfs_parent_lookup(path, &parent, &parent_sb, leaf) < 0 ||
        !leaf[0] || !parent_sb)
        return VFS_PATH_ERR_NOT_FOUND;
    if (!vfs_superblock_same_filesystem(inode_sb, parent_sb))
        return VFS_PATH_ERR_CROSS_DEVICE;
    if (!parent_sb->ops || !parent_sb->ops->rmdir)
        return VFS_PATH_ERR_INVALID;
    result = parent_sb->ops->rmdir(parent_sb, &parent, leaf);
    if (result < 0) return result;
    if (vfs_sync_mutation_if_required(parent_sb, 1) < 0)
        return VFS_PATH_ERR_IO;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_rename(const char *old_path, const char *new_path) {
    kernel_vfs_current_context_t context;
    vfs_inode_t source;
    vfs_inode_t target;
    vfs_inode_t old_parent;
    vfs_inode_t new_parent;
    vfs_superblock_t *source_sb = 0;
    vfs_superblock_t *old_sb = 0;
    vfs_superblock_t *new_sb = 0;
    char old_leaf[VFS_NAME_MAX];
    char new_leaf[VFS_NAME_MAX];
    int target_exists;
    int target_pinned = 0;
    int result = VFS_PATH_ERR_INVALID;
    char *old_normalized = g_rename_workspace.old_normalized;
    char *new_normalized = g_rename_workspace.new_normalized;
    char *new_parent_path = g_rename_workspace.new_parent;
    int shared_workspace = 1;

    if (!old_path || !new_path || old_path[0] != '/' || new_path[0] != '/')
        return VFS_PATH_ERR_INVALID;
    if (arch_vfs_current_context(&context) == 0 && context.paths[4] &&
        context.paths[5] && context.paths[6] &&
        context.path_capacity >= VFS_PATH_MAX) {
        old_normalized = context.paths[4];
        new_normalized = context.paths[5];
        new_parent_path = context.paths[6];
        shared_workspace = 0;
    } else {
        vfs_replayable_lock(&g_rename_lock);
    }
    if (normalize_absolute_path(old_path, old_normalized) < 0 ||
        normalize_absolute_path(new_path, new_normalized) < 0)
        goto out;
    if (text_equal(old_normalized, new_normalized)) {
        result = 0;
        goto out;
    }
    if (text_equal(old_normalized, "/") ||
        text_equal(new_normalized, "/")) {
        result = VFS_PATH_ERR_BUSY;
        goto out;
    }
    if (vfs_resolve_nofollow(old_normalized,
                             &source, &source_sb) < 0) {
        result = VFS_PATH_ERR_NOT_FOUND;
        goto out;
    }
    if (vfs_parent_lookup(old_normalized,
                          &old_parent, &old_sb,
                          old_leaf) < 0 ||
        vfs_parent_lookup(new_normalized,
                          &new_parent, &new_sb,
                          new_leaf) < 0 ||
        !old_leaf[0] || !new_leaf[0] || !source_sb || !old_sb || !new_sb) {
        result = VFS_PATH_ERR_NOT_FOUND;
        goto out;
    }
    if (!vfs_superblock_same_filesystem(source_sb, old_sb) ||
        !vfs_superblock_same_filesystem(old_sb, new_sb)) {
        result = VFS_PATH_ERR_CROSS_DEVICE;
        goto out;
    }
    if (!old_sb->ops || !old_sb->ops->lookup || !old_sb->ops->rename)
        goto out;
    if ((source.mode & 0xf000u) == VFS_INODE_DIR) {
        if (vfs_parent_path_copy(new_normalized, new_parent_path) < 0)
            goto out;
        if (mount_path_is_at_or_below(new_parent_path, old_normalized))
            goto out;
    }
    target_exists = old_sb->ops->lookup(old_sb, &new_parent, new_leaf,
                                        &target) == 0;
    if (target_exists &&
        vfs_inode_same_object(old_sb, &source, old_sb, &target)) {
        result = 0;
        goto out;
    }
    if (target_exists) {
        uint16_t source_kind = source.mode & 0xf000u;
        uint16_t target_kind = target.mode & 0xf000u;
        if (source_kind == VFS_INODE_DIR && target_kind != VFS_INODE_DIR) {
            result = VFS_PATH_ERR_NOT_DIRECTORY;
            goto out;
        }
        if (source_kind != VFS_INODE_DIR && target_kind == VFS_INODE_DIR) {
            result = VFS_PATH_ERR_IS_DIRECTORY;
            goto out;
        }
    }
    if (target_exists) {
        if (vfs_inode_open(old_sb, &target) < 0) {
            result = VFS_PATH_ERR_IO;
            goto out;
        }
        target_pinned = 1;
    }
    result = old_sb->ops->rename(old_sb, &old_parent, old_leaf,
                                 &new_parent, new_leaf);
    if (result >= 0) {
        if (target_exists)
            vfs_inode_lifetime_orphan_inode(old_sb, &target);
        if (target_pinned) {
            vfs_inode_close(old_sb, &target);
            target_pinned = 0;
        }
        if (vfs_sync_mutation_if_required(old_sb, 1) < 0) {
            result = VFS_PATH_ERR_IO;
            goto out;
        }
        vfs_path_cache_invalidate_all();
        result = 0;
    }
out:
    if (target_pinned) vfs_inode_close(old_sb, &target);
    if (shared_workspace) vfs_replayable_unlock(&g_rename_lock);
    return result;
}
