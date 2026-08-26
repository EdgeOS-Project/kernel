/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent descriptor mount API.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/mount_api.h"

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
    uint64_t attr_set;
    uint64_t attr_clear;
    uint64_t propagation;
    char filesystem[64];
    char *source;
    char *options;
    char *path;
    uint8_t type;
    uint8_t ready;
    uint8_t recursive;
    uint8_t attached;
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
    if (object->source) arch_vm_free_page(object->source);
    if (object->options) arch_vm_free_page(object->options);
    if (object->path) arch_vm_free_page(object->path);
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

int kernel_mount_api_context_configure(
    int object_id, uint32_t command, const char *key, const char *value,
    int32_t auxiliary, char *workspace, uint32_t workspace_capacity) {
    kernel_mount_api_object_t *object;
    int64_t mount_result;
    int result = 0;

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
    switch (command) {
        case KERNEL_MOUNT_API_SET_FLAG:
            if (!key || value || auxiliary) result = -EDGE_LINUX_EINVAL;
            else if (mount_api_is_vfs_flag_name(key))
                result = -EDGE_LINUX_EINVAL;
            else
                result = mount_api_append_option(object, key, 0);
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
                object->type != KERNEL_MOUNT_API_CONTEXT_NEW)
                result = -EDGE_LINUX_EINVAL;
            else
                object->ready = 1u;
            break;
        case KERNEL_MOUNT_API_RECONFIGURE:
            if (key || value || auxiliary ||
                object->type != KERNEL_MOUNT_API_CONTEXT_PICKED ||
                !object->path || !workspace ||
                workspace_capacity < VFS_PATH_MAX) {
                result = -EDGE_LINUX_EINVAL;
                break;
            }
            mount_result = kernel_linux_mount(
                0, object->path, 0,
                EDGE_LINUX_MS_REMOUNT | object->mount_flags,
                object->options ? object->options : "",
                workspace, workspace_capacity);
            result = mount_result < 0 ? (int)mount_result : 0;
            if (!result) object->ready = 1u;
            break;
        default:
            result = -EDGE_LINUX_EINVAL;
            break;
    }
    mount_api_unlock();
    return result;
}

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
    if (mount_api_copy(
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
    return result;
}

int kernel_mount_api_tree_open(const char *path, int clone, int recursive) {
    kernel_mount_api_object_t *object;
    int result;

    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    mount_api_lock();
    object = mount_api_allocate_locked(KERNEL_MOUNT_API_MOUNT_TREE);
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
    kernel_mount_api_object_t *object;
    char *attached_path;
    uint64_t flags;
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
    flags = object->mount_flags |
            mount_api_attributes_to_legacy(object->attr_set);
    if (object->type == KERNEL_MOUNT_API_MOUNT_NEW) {
        result = kernel_linux_mount(
            object->source ? object->source : "", target,
            object->filesystem, flags,
            object->options ? object->options : "",
            workspace, workspace_capacity);
    } else if (object->attached || !object->ready) {
        result = kernel_linux_mount(
            object->path, target, "", EDGE_LINUX_MS_MOVE,
            "", workspace, workspace_capacity);
    } else {
        result = kernel_linux_mount(
            object->path, target, "",
            EDGE_LINUX_MS_BIND |
                (object->recursive ? EDGE_LINUX_MS_REC : 0u),
            "", workspace, workspace_capacity);
        if (result >= 0 &&
            (object->attr_set || object->attr_clear ||
             object->propagation))
            result = kernel_linux_mount_setattr(
                target, object->attr_set, object->attr_clear,
                object->propagation, object->recursive);
    }
    if (result >= 0) {
        if (object->path) arch_vm_free_page(object->path);
        object->path = attached_path;
        attached_path = 0;
        object->attached = 1u;
    }
    mount_api_unlock();
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
    object->attr_set &= ~attr_clear;
    object->attr_set |= attr_set;
    object->attr_clear &= ~attr_set;
    object->attr_clear |= attr_clear;
    object->propagation = propagation;
    if (recursive) object->recursive = 1u;
    if (object->attached && object->path)
        result = (int)kernel_linux_mount_setattr(
            object->path, attr_set, attr_clear, propagation, recursive);
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
