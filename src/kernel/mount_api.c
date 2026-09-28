/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent descriptor mount API.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/mount_api.h"
#include "fs/tmpfs.h"

#include "kernel/linux_errno.h"
#include "kernel/linux_mount.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "vfs/vfs.h"

typedef enum kernel_mount_api_object_type {
    KERNEL_MOUNT_API_CONTEXT_NEW = 1,
    KERNEL_MOUNT_API_CONTEXT_PICKED,
    KERNEL_MOUNT_API_MOUNT_NEW,
    KERNEL_MOUNT_API_MOUNT_TREE,
} kernel_mount_api_object_type_t;

typedef struct kernel_mount_api_object {
    struct kernel_mount_api_object *next;
    uint32_t id;
    uint32_t references;
    uint64_t mount_flags;
    uint64_t mount_flags_mask;
    uint64_t attr_set;
    uint64_t attr_clear;
    uint64_t propagation;
    char filesystem[64];
    char *source;
    char *options;
    char *path;
    kernel_mount_api_file_reference_t *upper_file;
    kernel_mount_api_file_reference_t *work_file;
    vfs_superblock_t *tree_superblock;
    vfs_inode_t tree_inode;
    uint32_t tree_propagation;
    uint8_t type;
    uint8_t ready;
    uint8_t recursive;
    uint8_t attached;
    uint8_t operating;
    uint8_t post_mount;
} kernel_mount_api_object_t;

_Static_assert(sizeof(kernel_mount_api_object_t) <= 4096u,
               "mount API objects must fit in one kernel page");

static volatile uint32_t g_mount_api_lock;
static uint32_t g_mount_api_next_id;
static kernel_mount_api_object_t *g_mount_api_objects;

static void mount_api_lock(void) {
    while (__atomic_exchange_n(
            &g_mount_api_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_mount_api_lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void mount_api_unlock(void) {
    __atomic_store_n(&g_mount_api_lock, 0u, __ATOMIC_RELEASE);
}

static int mount_api_file_reference_retain(kernel_mount_api_file_reference_t *file) {
    uint32_t count;
    if (!file || !file->destroy) return -EDGE_LINUX_EINVAL;
    count = __atomic_load_n(&file->references, __ATOMIC_ACQUIRE);
    while (count && count != UINT32_MAX) {
        if (__atomic_compare_exchange_n(&file->references, &count, count + 1u,
                                        0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return 0;
    }
    return -EDGE_LINUX_EOVERFLOW;
}

void kernel_mount_api_file_reference_release(kernel_mount_api_file_reference_t *file) {
    if (file && __atomic_fetch_sub(&file->references, 1u, __ATOMIC_ACQ_REL) == 1u)
        file->destroy(file);
}

static int mount_api_file_reference_copy(kernel_mount_api_file_reference_t **out,
                                         kernel_mount_api_file_reference_t *file) {
    int status;
    if (!file) return 0;
    status = mount_api_file_reference_retain(file);
    if (status < 0) return status;
    *out = file;
    return 0;
}

static int mount_api_copy(char *destination, uint32_t capacity,
                          const char *source) {
    uint32_t length = 0;

    if (!destination || !source || !capacity)
        return -EDGE_LINUX_EINVAL;
    while (source[length]) {
        if (length + 1u >= capacity)
            return -EDGE_LINUX_ENAMETOOLONG;
        ++length;
    }
    memcpy(destination, source, length + 1u);
    return 0;
}

static char *mount_api_string_allocate(const char *source) {
    char *copy;

    if (!source) return 0;
    copy = (char *)arch_vm_alloc_page();
    if (!copy) return 0;
    if (mount_api_copy(copy, VFS_PATH_MAX, source) < 0) {
        arch_vm_free_page(copy);
        return 0;
    }
    return copy;
}

static int mount_api_string_replace(char **slot, const char *source) {
    char *replacement;

    if (!slot || !source) return -EDGE_LINUX_EINVAL;
    replacement = mount_api_string_allocate(source);
    if (!replacement) return -EDGE_LINUX_ENOMEM;
    if (*slot) arch_vm_free_page(*slot);
    *slot = replacement;
    return 0;
}

static kernel_mount_api_object_t *mount_api_find_locked(int object_id) {
    kernel_mount_api_object_t *object = g_mount_api_objects;

    if (object_id <= 0) return 0;
    while (object) {
        if (object->id == (uint32_t)object_id) return object;
        object = object->next;
    }
    return 0;
}

static kernel_mount_api_object_t *mount_api_allocate_locked(uint8_t type) {
    kernel_mount_api_object_t *object;
    uint32_t id;

    object = (kernel_mount_api_object_t *)arch_vm_alloc_page();
    if (!object) return 0;
    memset(object, 0, 4096u);
    do {
        id = ++g_mount_api_next_id;
        if (!id || id > INT32_MAX) {
            g_mount_api_next_id = 0;
            id = ++g_mount_api_next_id;
        }
    } while (mount_api_find_locked((int)id));
    object->id = id;
    object->references = 1u;
    object->type = type;
    object->next = g_mount_api_objects;
    g_mount_api_objects = object;
    return object;
}

static void mount_api_destroy(kernel_mount_api_object_t *object) {
    if (!object) return;
    kernel_mount_api_file_reference_release(object->upper_file);
    kernel_mount_api_file_reference_release(object->work_file);
    if (object->source) arch_vm_free_page(object->source);
    if (object->options) arch_vm_free_page(object->options);
    if (object->path) arch_vm_free_page(object->path);
    if (object->tree_superblock)
        vfs_superblock_release(object->tree_superblock);
    arch_vm_free_page(object);
}

static int mount_api_name_is(const char *name, const char *expected) {
    return name && expected && strcmp(name, expected) == 0;
}

int kernel_mount_api_filesystem_supported(const char *filesystem) {
    static const char *const names[] = {
        "ext2", "ext4", "fat32", "vfat", "exfat", "ntfs",
        "iso9660", "udf", "proc", "sysfs", "cgroup2", "tmpfs",
        "ramfs", "mqueue", "devtmpfs", "devpts", "overlay", "squashfs",
        "erofs", "xfs", "btrfs",
    };

    if (!filesystem || !filesystem[0]) return 0;
    for (uint32_t index = 0;
         index < sizeof(names) / sizeof(names[0]); ++index) {
        if (strcmp(filesystem, names[index]) == 0) return 1;
    }
    return 0;
}

int kernel_mount_api_context_create(const char *filesystem) {
    kernel_mount_api_object_t *object;
    int result;

    if (!kernel_mount_api_filesystem_supported(filesystem))
        return -EDGE_LINUX_ENODEV;
    mount_api_lock();
    object = mount_api_allocate_locked(KERNEL_MOUNT_API_CONTEXT_NEW);
    if (!object) {
        mount_api_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    result = mount_api_copy(
        object->filesystem, sizeof(object->filesystem), filesystem);
    if (result < 0) {
        g_mount_api_objects = object->next;
        mount_api_unlock();
        mount_api_destroy(object);
        return result;
    }
    result = (int)object->id;
    mount_api_unlock();
    return result;
}

int kernel_mount_api_context_pick(const char *path) {
    kernel_mount_api_object_t *object;
    int result;

    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    mount_api_lock();
    object = mount_api_allocate_locked(KERNEL_MOUNT_API_CONTEXT_PICKED);
    if (!object) {
        mount_api_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    object->path = mount_api_string_allocate(path);
    if (!object->path) {
        g_mount_api_objects = object->next;
        mount_api_unlock();
        mount_api_destroy(object);
        return -EDGE_LINUX_ENOMEM;
    }
    result = (int)object->id;
    mount_api_unlock();
    return result;
}

int kernel_mount_api_context_pick_object(int object_id) {
    kernel_mount_api_object_t *source;
    kernel_mount_api_object_t *object;
    int result;

    mount_api_lock();
    source = mount_api_find_locked(object_id);
    if (!source || !source->path) {
        mount_api_unlock();
        return -EDGE_LINUX_EBADF;
    }
    object = mount_api_allocate_locked(KERNEL_MOUNT_API_CONTEXT_PICKED);
    if (!object) {
        mount_api_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    object->path = mount_api_string_allocate(source->path);
    if (!object->path ||
        mount_api_copy(object->filesystem, sizeof(object->filesystem),
                       source->filesystem) < 0) {
        g_mount_api_objects = object->next;
        mount_api_unlock();
        mount_api_destroy(object);
        return -EDGE_LINUX_ENOMEM;
    }
    result = (int)object->id;
    mount_api_unlock();
    return result;
}

static int mount_api_append_option(kernel_mount_api_object_t *object,
                                   const char *key, const char *value) {
    uint32_t used = 0;
    uint32_t key_length = 0;
    uint32_t value_length = 0;

    if (!object || !key || !key[0]) return -EDGE_LINUX_EINVAL;
    if (!object->options) {
        object->options = (char *)arch_vm_alloc_page();
        if (!object->options) return -EDGE_LINUX_ENOMEM;
        object->options[0] = 0;
    }
    while (object->options[used]) ++used;
    while (key[key_length]) ++key_length;
    if (value)
        while (value[value_length]) ++value_length;
    if (used + (used ? 1u : 0u) + key_length +
            (value ? 1u + value_length : 0u) + 1u > VFS_PATH_MAX)
        return -EDGE_LINUX_E2BIG;
    if (used) object->options[used++] = ',';
    memcpy(object->options + used, key, key_length);
    used += key_length;
    if (value) {
        object->options[used++] = '=';
        memcpy(object->options + used, value, value_length);
        used += value_length;
    }
    object->options[used] = 0;
    return 0;
}

/* Replace a serialized option atomically; file-valued options cannot append
 * a stale first occurrence or inject another option through a comma. */
static int mount_api_replace_option(kernel_mount_api_object_t *object,
                                    const char *key, const char *value) {
    char *replacement;
    const char *cursor = object->options;
    uint32_t used = 0;
    uint32_t key_length = (uint32_t)strlen(key);
    uint32_t value_length = (uint32_t)strlen(value);
    if (strrchr(key, ',') || strrchr(key, '=') || strrchr(value, ','))
        return -EDGE_LINUX_EINVAL;
    if ((uint64_t)key_length + value_length + 2u > VFS_PATH_MAX)
        return -EDGE_LINUX_E2BIG;
    replacement = arch_vm_alloc_page();
    if (!replacement) return -EDGE_LINUX_ENOMEM;
    while (cursor && *cursor) {
        const char *end = cursor;
        uint32_t length;
        while (*end && *end != ',') ++end;
        length = (uint32_t)(end - cursor);
        if (!(length > key_length && cursor[key_length] == '=' &&
              memcmp(cursor, key, key_length) == 0)) {
            if ((uint64_t)used + length + (used ? 1u : 0u) +
                key_length + value_length + 3u > VFS_PATH_MAX) {
                arch_vm_free_page(replacement);
                return -EDGE_LINUX_E2BIG;
            }
            if (used) replacement[used++] = ',';
            memcpy(replacement + used, cursor, length);
            used += length;
        }
        cursor = *end ? end + 1 : end;
    }
    if (used) replacement[used++] = ',';
    memcpy(replacement + used, key, key_length);
    used += key_length;
    replacement[used++] = '=';
    memcpy(replacement + used, value, value_length + 1u);
    if (object->options) arch_vm_free_page(object->options);
    object->options = replacement;
    return 0;
}

static int mount_api_context_check_locked(kernel_mount_api_object_t *object) {
    if (!object) return -EDGE_LINUX_EBADF;
    if (object->type != KERNEL_MOUNT_API_CONTEXT_NEW &&
        object->type != KERNEL_MOUNT_API_CONTEXT_PICKED)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

int kernel_mount_api_context_check(int object_id) {
    int status;
    mount_api_lock();
    status = mount_api_context_check_locked(mount_api_find_locked(object_id));
    mount_api_unlock();
    return status;
}

static int mount_api_file_option_check_locked(kernel_mount_api_object_t *object,
                                               const char *key) {
    int status = mount_api_context_check_locked(object);
    if (status < 0) return status;
    if (object->ready) return -EDGE_LINUX_EBUSY;
    if (!key || !key[0]) return -EDGE_LINUX_EINVAL;
    if (mount_api_name_is(object->filesystem, "overlay")) {
        if (mount_api_name_is(key, "upperdir") || mount_api_name_is(key, "workdir"))
            return 0;
        if (mount_api_name_is(key, "lowerdir+") || mount_api_name_is(key, "datadir+"))
            return -EDGE_LINUX_EOPNOTSUPP;
    }
    if (mount_api_name_is(object->filesystem, "proc") && mount_api_name_is(key, "pidns"))
        return -EDGE_LINUX_EOPNOTSUPP;
    /* Numeric/string and flag parameters do not accept a file value. */
    return -EDGE_LINUX_EINVAL;
}

int kernel_mount_api_context_file_option_check(int object_id, const char *key) {
    int status;
    mount_api_lock();
    status = mount_api_file_option_check_locked(mount_api_find_locked(object_id), key);
    mount_api_unlock();
    return status;
}

int kernel_mount_api_context_configure_file(
    int object_id, const char *key, kernel_mount_api_file_reference_t *file) {
    kernel_mount_api_object_t *object;
    kernel_mount_api_file_reference_t *old = 0;
    kernel_mount_api_file_reference_t **slot;
    int status;
    if (!file) return -EDGE_LINUX_EINVAL;
    mount_api_lock();
    object = mount_api_find_locked(object_id);
    status = mount_api_file_option_check_locked(object, key);
    if (status < 0) goto out;
    if (!file->snapshot.inode ||
        (file->snapshot.inode->mode & 0xf000u) != VFS_INODE_DIR) {
        status = -EDGE_LINUX_ENOTDIR;
        goto out;
    }
    if (!file->snapshot.superblock || !file->snapshot.path ||
        file->snapshot.path[0] != '/') {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    status = mount_api_file_reference_retain(file);
    if (status < 0) goto out;
    status = mount_api_replace_option(object, key, file->snapshot.path);
    if (status < 0) {
        old = file;
        goto out;
    }
    slot = mount_api_name_is(key, "upperdir") ? &object->upper_file : &object->work_file;
    old = *slot;
    *slot = file;
out:
    mount_api_unlock();
    kernel_mount_api_file_reference_release(old);
    return status;
}

static int mount_api_is_vfs_flag_name(const char *key) {
    static const char *const names[] = {
        "ro", "rw", "nosuid", "suid", "nodev", "dev",
        "noexec", "exec", "sync", "async", "dirsync", "noatime",
        "atime", "nodiratime", "diratime", "lazytime", "nolazytime",
        "iversion", "noiversion",
    };

    for (uint32_t index = 0;
         index < sizeof(names) / sizeof(names[0]); ++index)
        if (mount_api_name_is(key, names[index])) return 1;
    return 0;
}

static int mount_api_apply_superblock_flag(kernel_mount_api_object_t *object,
                                             const char *key) {
    uint64_t mask;
    int clear = 0;
    if (mount_api_name_is(key, "ro") || mount_api_name_is(key, "rw")) {
        mask = EDGE_LINUX_MS_RDONLY;
        clear = mount_api_name_is(key, "rw");
    } else if (mount_api_name_is(key, "sync") || mount_api_name_is(key, "async")) {
        mask = EDGE_LINUX_MS_SYNCHRONOUS;
        clear = mount_api_name_is(key, "async");
    } else if (mount_api_name_is(key, "dirsync")) {
        mask = EDGE_LINUX_MS_DIRSYNC;
    } else if (mount_api_name_is(key, "lazytime") || mount_api_name_is(key, "nolazytime")) {
        mask = EDGE_LINUX_MS_LAZYTIME;
        clear = mount_api_name_is(key, "nolazytime");
    } else {
        return mount_api_is_vfs_flag_name(key) ? -EDGE_LINUX_EINVAL : 0;
    }
    object->mount_flags_mask |= mask;
    if (clear) object->mount_flags &= ~mask;
    else object->mount_flags |= mask;
    return 1;
}

static int mount_api_option_type_valid(kernel_mount_api_object_t *object,
                                        uint32_t command, const char *key) {
    if (!key || !key[0]) return 0;
    if (mount_api_is_vfs_flag_name(key))
        return command == KERNEL_MOUNT_API_SET_FLAG;
    if (mount_api_name_is(key, "source"))
        return command == KERNEL_MOUNT_API_SET_STRING;
    if (mount_api_name_is(object->filesystem, "tmpfs")) {
        if (mount_api_name_is(key, "noswap"))
            return command == KERNEL_MOUNT_API_SET_FLAG;
        if (mount_api_name_is(key, "mode") || mount_api_name_is(key, "uid") ||
            mount_api_name_is(key, "gid") || mount_api_name_is(key, "size") ||
            mount_api_name_is(key, "nr_inodes"))
            return command == KERNEL_MOUNT_API_SET_STRING;
        return 0;
    }
    /* The cgroup2 mount backend does not implement filesystem options. */
    if (mount_api_name_is(object->filesystem, "cgroup2")) return 0;
    return 1;
}

int kernel_mount_api_context_configure(
    int object_id, uint32_t command, const char *key, const char *value,
    int32_t auxiliary, char *workspace, uint32_t workspace_capacity) {
    kernel_mount_api_object_t *object;
    int64_t mount_result;
    int result = 0;
    kernel_mount_api_file_reference_t *old_file = 0;

    mount_api_lock();
    object = mount_api_find_locked(object_id);
    if (!object || (object->type != KERNEL_MOUNT_API_CONTEXT_NEW &&
                    object->type != KERNEL_MOUNT_API_CONTEXT_PICKED)) {
        mount_api_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (command <= KERNEL_MOUNT_API_SET_FD && object->ready) {
        mount_api_unlock();
        return -EDGE_LINUX_EBUSY;
    }
    if (command <= KERNEL_MOUNT_API_SET_FD &&
        (command == KERNEL_MOUNT_API_SET_FD || !mount_api_option_type_valid(object, command, key))) {
        mount_api_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    switch (command) {
        case KERNEL_MOUNT_API_SET_FLAG:
            if (!key || value || auxiliary) result = -EDGE_LINUX_EINVAL;
            else {
                result = mount_api_apply_superblock_flag(object, key);
                if (!result) result = mount_api_append_option(object, key, 0);
                else if (result > 0) result = 0;
            }
            break;
        case KERNEL_MOUNT_API_SET_STRING:
            if (auxiliary) {
                result = -EDGE_LINUX_EINVAL;
                break;
            }
            /* fall through */
        case KERNEL_MOUNT_API_SET_PATH:
        case KERNEL_MOUNT_API_SET_PATH_EMPTY:
        case KERNEL_MOUNT_API_SET_FD:
            if (!key || !value) {
                result = -EDGE_LINUX_EINVAL;
            } else if (mount_api_name_is(key, "source")) {
                result = mount_api_string_replace(&object->source, value);
            } else if (mount_api_name_is(object->filesystem, "overlay") &&
                       (mount_api_name_is(key, "upperdir") || mount_api_name_is(key, "workdir"))) {
                result = mount_api_replace_option(object, key, value);
                if (!result) {
                    kernel_mount_api_file_reference_t **slot = mount_api_name_is(key, "upperdir") ?
                        &object->upper_file : &object->work_file;
                    old_file = *slot;
                    *slot = 0;
                }
            } else {
                result = mount_api_append_option(object, key, value);
            }
            break;
        case KERNEL_MOUNT_API_SET_BINARY:
            result = -EDGE_LINUX_EOPNOTSUPP;
            break;
        case KERNEL_MOUNT_API_CREATE:
        case KERNEL_MOUNT_API_CREATE_EXCLUSIVE:
            if (key || value || auxiliary ||
                object->type != KERNEL_MOUNT_API_CONTEXT_NEW || object->post_mount)
                result = -EDGE_LINUX_EINVAL;
            else
                object->ready = 1u;
            break;
        case KERNEL_MOUNT_API_RECONFIGURE:
            if (key || value || auxiliary ||
                (object->type != KERNEL_MOUNT_API_CONTEXT_PICKED && !object->post_mount) ||
                (!object->path && !object->tree_superblock) || !workspace ||
                workspace_capacity < VFS_PATH_MAX) {
                result = -EDGE_LINUX_EINVAL;
                break;
            }
            if (object->post_mount && object->tree_superblock) {
                result = tmpfs_reconfigure_detached(object->tree_superblock,
                    object->options ? object->options : "");
                if (!result) {
                    object->tree_superblock->mount_flags &= ~(uint32_t)object->mount_flags_mask;
                    object->tree_superblock->mount_flags |= (uint32_t)(object->mount_flags & object->mount_flags_mask);
                }
            } else {
                mount_result = kernel_linux_mount(
                    0, object->path, 0,
                    EDGE_LINUX_MS_REMOUNT | object->mount_flags,
                    object->options ? object->options : "",
                    workspace, workspace_capacity);
                result = mount_result < 0 ? (int)mount_result : 0;
            }
            if (!result) {
                object->ready = 0u;
                object->mount_flags_mask = 0;
                if (object->options) { arch_vm_free_page(object->options); object->options = 0; }
            }
            break;
        default:
            result = -EDGE_LINUX_EINVAL;
            break;
    }
    mount_api_unlock();
    kernel_mount_api_file_reference_release(old_file);
    return result;
}

static uint64_t mount_api_attributes_to_legacy(uint64_t attributes);

int kernel_mount_api_context_mount(int context_id, uint64_t attributes) {
    kernel_mount_api_object_t *context;
    kernel_mount_api_object_t *mount;
    int result;

    mount_api_lock();
    context = mount_api_find_locked(context_id);
    if (!context || (context->type != KERNEL_MOUNT_API_CONTEXT_NEW &&
                     context->type != KERNEL_MOUNT_API_CONTEXT_PICKED)) {
        mount_api_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (context->post_mount) {
        mount_api_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    if (context->type == KERNEL_MOUNT_API_CONTEXT_NEW && !context->ready) {
        mount_api_unlock();
        return -EDGE_LINUX_EBUSY;
    }
    mount = mount_api_allocate_locked(
        context->type == KERNEL_MOUNT_API_CONTEXT_NEW ?
            KERNEL_MOUNT_API_MOUNT_NEW : KERNEL_MOUNT_API_MOUNT_TREE);
    if (!mount) {
        mount_api_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    mount->mount_flags = context->mount_flags;
    mount->attr_set = attributes;
    mount->recursive = context->recursive;
    if (context->type == KERNEL_MOUNT_API_CONTEXT_PICKED)
        mount->ready = 1u;
    if (mount_api_file_reference_copy(&mount->upper_file, context->upper_file) < 0 ||
        mount_api_file_reference_copy(&mount->work_file, context->work_file) < 0 ||
        mount_api_copy(
            mount->filesystem, sizeof(mount->filesystem),
            context->filesystem) < 0 ||
        (context->source &&
         !(mount->source = mount_api_string_allocate(context->source))) ||
        (context->options &&
         !(mount->options = mount_api_string_allocate(context->options))) ||
        (context->path &&
         !(mount->path = mount_api_string_allocate(context->path)))) {
        g_mount_api_objects = mount->next;
        mount_api_unlock();
        mount_api_destroy(mount);
        return -EDGE_LINUX_ENOMEM;
    }
    result = (int)mount->id;
    mount_api_unlock();
    if (mount->type == KERNEL_MOUNT_API_MOUNT_NEW &&
        strcmp(mount->filesystem, "tmpfs") == 0) {
        vfs_superblock_t *superblock;
        if (tmpfs_create_detached(mount->source ? mount->source : "tmpfs",
                                  mount->options, &superblock) < 0) {
            kernel_mount_api_release(result);
            return -EDGE_LINUX_ENOMEM;
        }
        superblock->mount_flags = (uint32_t)(mount->mount_flags |
            mount_api_attributes_to_legacy(mount->attr_set));
        mount_api_lock();
        mount->tree_superblock = superblock;
        mount->tree_inode = superblock->root;
        mount->tree_propagation = VFS_MOUNT_PRIVATE;
        mount->ready = 1u;
        context = mount_api_find_locked(context_id);
        if (context) {
            context->tree_superblock = vfs_superblock_acquire(superblock);
            context->tree_inode = superblock->root;
            context->ready = 0;
            context->post_mount = 1;
            context->mount_flags = superblock->mount_flags;
            context->mount_flags_mask = 0;
            if (context->options) { arch_vm_free_page(context->options); context->options = 0; }
        }
        mount_api_unlock();
    }
    return result;
}

int kernel_mount_api_tree_open(const char *path, int clone, int recursive) {
    return kernel_mount_api_tree_open_resolved(
        path, 0, 0, 0, clone, recursive);
}

int kernel_mount_api_tree_open_resolved(
    const char *path, vfs_superblock_t *superblock,
    const vfs_inode_t *inode, uint32_t propagation,
    int clone, int recursive) {
    kernel_mount_api_object_t *object;
    vfs_superblock_t *retained = 0;
    int result;

    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    if ((superblock == 0) != (inode == 0)) return -EDGE_LINUX_EINVAL;
    if (superblock) {
        retained = vfs_superblock_acquire(superblock);
        if (!retained) return -EDGE_LINUX_ENOMEM;
    }
    mount_api_lock();
    object = mount_api_allocate_locked(KERNEL_MOUNT_API_MOUNT_TREE);
    if (!object) {
        mount_api_unlock();
        if (retained) vfs_superblock_release(retained);
        return -EDGE_LINUX_ENOMEM;
    }
    object->path = mount_api_string_allocate(path);
    if (!object->path) {
        g_mount_api_objects = object->next;
        mount_api_unlock();
        mount_api_destroy(object);
        if (retained) vfs_superblock_release(retained);
        return -EDGE_LINUX_ENOMEM;
    }
    object->tree_superblock = retained;
    if (inode) object->tree_inode = *inode;
    object->tree_propagation = propagation;
    object->ready = clone ? 1u : 0u;
    object->recursive = recursive ? 1u : 0u;
    result = (int)object->id;
    mount_api_unlock();
    return result;
}

static uint64_t mount_api_attributes_to_legacy(uint64_t attributes) {
    uint64_t flags = 0;

    if (attributes & EDGE_LINUX_MOUNT_ATTR_RDONLY)
        flags |= EDGE_LINUX_MS_RDONLY;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NOSUID)
        flags |= EDGE_LINUX_MS_NOSUID;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NODEV)
        flags |= EDGE_LINUX_MS_NODEV;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NOEXEC)
        flags |= EDGE_LINUX_MS_NOEXEC;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NOATIME)
        flags |= EDGE_LINUX_MS_NOATIME;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_STRICTATIME)
        flags |= EDGE_LINUX_MS_STRICTATIME;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NODIRATIME)
        flags |= EDGE_LINUX_MS_NODIRATIME;
    if (attributes & EDGE_LINUX_MOUNT_ATTR_NOSYMFOLLOW)
        flags |= EDGE_LINUX_MS_NOSYMFOLLOW;
    return flags;
}

int kernel_mount_api_mount_attach(
    int object_id, char *target, char *workspace,
    uint32_t workspace_capacity) {
    vfs_inode_t target_inode;
    if (vfs_resolve(target, &target_inode, 0, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    return kernel_mount_api_mount_attach_resolved(
        object_id, target, &target_inode, workspace, workspace_capacity);
}

int kernel_mount_api_mount_attach_resolved(
    int object_id, char *target, const vfs_inode_t *target_inode,
    char *workspace, uint32_t workspace_capacity) {
    kernel_mount_api_object_t *object;
    char *attached_path;
    char *source;
    const char *filesystem;
    const char *options;
    char *path;
    vfs_superblock_t *tree_superblock;
    vfs_inode_t tree_inode;
    uint32_t tree_propagation;
    uint64_t flags;
    uint64_t attr_set;
    uint64_t attr_clear;
    uint64_t propagation;
    uint8_t type;
    uint8_t recursive;
    uint8_t attached;
    uint8_t ready;
    int64_t result;

    if (!target || !workspace || workspace_capacity < VFS_PATH_MAX)
        return -EDGE_LINUX_EFAULT;
    attached_path = mount_api_string_allocate(target);
    if (!attached_path) return -EDGE_LINUX_ENOMEM;
    mount_api_lock();
    object = mount_api_find_locked(object_id);
    if (!object || (object->type != KERNEL_MOUNT_API_MOUNT_NEW &&
                    object->type != KERNEL_MOUNT_API_MOUNT_TREE)) {
        mount_api_unlock();
        arch_vm_free_page(attached_path);
        return -EDGE_LINUX_EBADF;
    }
    if (object->operating || object->references == UINT32_MAX) {
        mount_api_unlock();
        arch_vm_free_page(attached_path);
        return -EDGE_LINUX_EBUSY;
    }
    object->operating = 1u;
    ++object->references;
    flags = object->mount_flags |
            mount_api_attributes_to_legacy(object->attr_set);
    type = object->type;
    recursive = object->recursive;
    attached = object->attached;
    ready = object->ready;
    source = object->source;
    filesystem = object->filesystem;
    options = object->options;
    path = object->path;
    tree_superblock = object->tree_superblock;
    tree_inode = object->tree_inode;
    tree_propagation = object->tree_propagation;
    attr_set = object->attr_set;
    attr_clear = object->attr_clear;
    propagation = object->propagation;
    mount_api_unlock();

    if (attached) {
        result = kernel_linux_mount(path, target, "", EDGE_LINUX_MS_MOVE,
                                    "", workspace, workspace_capacity);
    } else if (type == KERNEL_MOUNT_API_MOUNT_NEW && tree_superblock && target_inode) {
        result = vfs_bind_mount_resolved("/", tree_superblock, &tree_inode,
            tree_propagation, target, target_inode, 0) < 0 ? -EDGE_LINUX_EINVAL : 0;
        if (result >= 0 && (attr_set || attr_clear || propagation))
            result = kernel_linux_mount_setattr(target, attr_set, attr_clear,
                                                propagation, recursive);
    } else if (type == KERNEL_MOUNT_API_MOUNT_NEW) {
        result = kernel_linux_mount(
            source ? source : "", target,
            filesystem, flags,
            options ? options : "",
            workspace, workspace_capacity);
    } else if (attached || !ready) {
        result = kernel_linux_mount(
            path, target, "", EDGE_LINUX_MS_MOVE,
            "", workspace, workspace_capacity);
    } else if (tree_superblock && target_inode) {
        result = vfs_bind_mount_resolved(
            path, tree_superblock, &tree_inode, tree_propagation,
            target, target_inode, recursive) < 0 ?
            -EDGE_LINUX_EINVAL : 0;
        if (result >= 0 && (attr_set || attr_clear || propagation))
            result = kernel_linux_mount_setattr(
                target, attr_set, attr_clear, propagation, recursive);
    } else {
        result = kernel_linux_mount(
            path, target, "",
            EDGE_LINUX_MS_BIND |
                (recursive ? EDGE_LINUX_MS_REC : 0u),
            "", workspace, workspace_capacity);
        if (result >= 0 &&
            (attr_set || attr_clear || propagation))
            result = kernel_linux_mount_setattr(
                target, attr_set, attr_clear,
                propagation, recursive);
    }

    mount_api_lock();
    object = mount_api_find_locked(object_id);
    if (!object) {
        mount_api_unlock();
        arch_vm_free_page(attached_path);
        return -EDGE_LINUX_EBADF;
    }
    if (result >= 0) {
        if (object->path) arch_vm_free_page(object->path);
        object->path = attached_path;
        attached_path = 0;
        object->attached = 1u;
    }
    object->operating = 0u;
    mount_api_unlock();
    kernel_mount_api_release(object_id);
    if (attached_path) arch_vm_free_page(attached_path);
    return result < 0 ? (int)result : 0;
}

int kernel_mount_api_mount_setattr(
    int object_id, uint64_t attr_set, uint64_t attr_clear,
    uint64_t propagation, int recursive) {
    kernel_mount_api_object_t *object;
    int result = 0;

    mount_api_lock();
    object = mount_api_find_locked(object_id);
    if (!object || (object->type != KERNEL_MOUNT_API_MOUNT_NEW &&
                    object->type != KERNEL_MOUNT_API_MOUNT_TREE)) {
        mount_api_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (object->operating) {
        mount_api_unlock();
        return -EDGE_LINUX_EBUSY;
    }
    object->attr_set &= ~attr_clear;
    object->attr_set |= attr_set;
    object->attr_clear &= ~attr_set;
    object->attr_clear |= attr_clear;
    object->propagation = propagation;
    if (recursive) object->recursive = 1u;
    if (!object->attached && object->type == KERNEL_MOUNT_API_MOUNT_NEW &&
        object->tree_superblock) {
        object->tree_superblock->mount_flags &=
            ~(uint32_t)mount_api_attributes_to_legacy(attr_clear);
        object->tree_superblock->mount_flags |=
            (uint32_t)mount_api_attributes_to_legacy(attr_set);
    }
    if (object->attached && object->path)
        result = (int)kernel_linux_mount_setattr(
            object->path, attr_set, attr_clear, propagation, recursive);
    mount_api_unlock();
    return result;
}

int kernel_mount_api_root(int object_id, vfs_superblock_t **superblock_out,
                           vfs_inode_t *inode_out) {
    kernel_mount_api_object_t *object;
    int result = -EDGE_LINUX_ENOENT;
    if (!superblock_out || !inode_out) return -EDGE_LINUX_EINVAL;
    mount_api_lock();
    object = mount_api_find_locked(object_id);
    if (!object) result = -EDGE_LINUX_EBADF;
    else if (object->tree_superblock &&
             (object->type == KERNEL_MOUNT_API_MOUNT_NEW || object->type == KERNEL_MOUNT_API_MOUNT_TREE)) {
        *superblock_out = object->tree_superblock;
        *inode_out = object->tree_inode;
        result = 0;
    }
    mount_api_unlock();
    return result;
}

int kernel_mount_api_resolve_relative(
    int object_id, const char *relative_path, int nofollow,
    char *resolved_path, uint32_t resolved_capacity,
    vfs_superblock_t **superblock_out, vfs_inode_t *inode_out) {
    kernel_mount_api_object_t *object;
    vfs_superblock_t *superblock;
    vfs_inode_t current;
    const char *cursor;
    uint32_t resolved_length;
    int result = 0;

    if (!relative_path || relative_path[0] == '/' || !resolved_path ||
        !resolved_capacity || !superblock_out || !inode_out)
        return -EDGE_LINUX_EINVAL;
    mount_api_lock();
    object = mount_api_find_locked(object_id);
    if (!object || object->type != KERNEL_MOUNT_API_MOUNT_TREE ||
        !object->tree_superblock || !object->path ||
        object->references == UINT32_MAX) {
        mount_api_unlock();
        return -EDGE_LINUX_EBADF;
    }
    ++object->references;
    superblock = object->tree_superblock;
    current = object->tree_inode;
    result = mount_api_copy(
        resolved_path, resolved_capacity, object->path);
    mount_api_unlock();
    if (result < 0) goto out;
    if ((current.mode & 0xf000u) != VFS_INODE_DIR) {
        result = -EDGE_LINUX_ENOTDIR;
        goto out;
    }

    resolved_length = (uint32_t)strlen(resolved_path);
    cursor = relative_path;
    while (*cursor) {
        char component[VFS_NAME_MAX];
        uint32_t component_length = 0;
        int final_component;

        while (*cursor == '/') ++cursor;
        if (!*cursor) break;
        while (*cursor && *cursor != '/') {
            if (component_length + 1u >= sizeof(component)) {
                result = -EDGE_LINUX_ENAMETOOLONG;
                goto out;
            }
            component[component_length++] = *cursor++;
        }
        component[component_length] = 0;
        while (*cursor == '/') ++cursor;
        final_component = *cursor == 0;
        if (strcmp(component, ".") == 0) continue;
        if (strcmp(component, "..") == 0) {
            result = -EDGE_LINUX_EXDEV;
            goto out;
        }
        if (!superblock->ops || !superblock->ops->lookup ||
            superblock->ops->lookup(
                superblock, &current, component, &current) < 0) {
            result = -EDGE_LINUX_ENOENT;
            goto out;
        }
        if ((current.mode & 0xf000u) == VFS_INODE_LNK &&
            !(nofollow && final_component)) {
            result = -EDGE_LINUX_ELOOP;
            goto out;
        }
        if (!final_component &&
            (current.mode & 0xf000u) != VFS_INODE_DIR) {
            result = -EDGE_LINUX_ENOTDIR;
            goto out;
        }
        if (resolved_length > 1u) {
            if (resolved_length + 1u >= resolved_capacity) {
                result = -EDGE_LINUX_ENAMETOOLONG;
                goto out;
            }
            resolved_path[resolved_length++] = '/';
        }
        if (resolved_length + component_length >= resolved_capacity) {
            result = -EDGE_LINUX_ENAMETOOLONG;
            goto out;
        }
        memcpy(resolved_path + resolved_length, component,
               component_length);
        resolved_length += component_length;
        resolved_path[resolved_length] = 0;
    }
    *superblock_out = superblock;
    *inode_out = current;
out:
    kernel_mount_api_release(object_id);
    return result;
}

int kernel_mount_api_resolve(
    int object_id, char *path, uint32_t path_capacity,
    uint64_t *attributes) {
    kernel_mount_api_object_t *object;
    int result;

    if (!path || !path_capacity) return -EDGE_LINUX_EINVAL;
    mount_api_lock();
    object = mount_api_find_locked(object_id);
    if (!object ||
        (object->type != KERNEL_MOUNT_API_MOUNT_NEW &&
         object->type != KERNEL_MOUNT_API_MOUNT_TREE)) {
        mount_api_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (!object->path) {
        mount_api_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    result = mount_api_copy(path, path_capacity, object->path);
    if (result >= 0 && attributes) *attributes = object->attr_set;
    mount_api_unlock();
    return result;
}

int kernel_mount_api_retain(int object_id) {
    kernel_mount_api_object_t *object;
    int result = 0;

    mount_api_lock();
    object = mount_api_find_locked(object_id);
    if (!object) result = -EDGE_LINUX_EBADF;
    else if (object->references == UINT32_MAX)
        result = -EDGE_LINUX_EOVERFLOW;
    else
        ++object->references;
    mount_api_unlock();
    return result;
}

void kernel_mount_api_release(int object_id) {
    kernel_mount_api_object_t **link;
    kernel_mount_api_object_t *object = 0;

    mount_api_lock();
    link = &g_mount_api_objects;
    while (*link) {
        if ((*link)->id == (uint32_t)object_id) {
            object = *link;
            if (object->references && --object->references == 0u)
                *link = object->next;
            else
                object = 0;
            break;
        }
        link = &(*link)->next;
    }
    mount_api_unlock();
    if (object) mount_api_destroy(object);
}
