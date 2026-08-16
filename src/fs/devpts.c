/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux devpts mount policy and PTY slave inode lifetime.  Terminal transport
 * remains in the TTY layer, while this file owns the filesystem-visible inode
 * that grantpt(), stat(), chmod(), chown(), and descriptor metadata operations
 * observe.  Keeping that inode in the mounted filesystem avoids synthetic
 * success paths and keeps pathname and descriptor behavior coherent.
 */

#include "fs/devpts.h"
#include "fs/tmpfs.h"
#include "string.h"

#define DEVPTS_CONFIG_MAX 128u
#define DEVPTS_DEFAULT_MODE 0600u
#define DEVPTS_DEFAULT_PTMXMODE 0000u
#define DEVPTS_DEFAULT_MAX 1048576u

typedef struct devpts_mount_config {
    uint8_t used;
    uint8_t new_instance;
    uint16_t mode;
    uint16_t ptmx_mode;
    uint16_t padding;
    uint32_t gid;
    uint32_t max_slaves;
    vfs_superblock_t *superblock;
} devpts_mount_config_t;

static devpts_mount_config_t g_devpts_configs[DEVPTS_CONFIG_MAX];
static volatile uint32_t g_devpts_config_lock;

static void devpts_lock(void) {
    while (__sync_lock_test_and_set(&g_devpts_config_lock, 1u)) { }
}

static void devpts_unlock(void) {
    __sync_lock_release(&g_devpts_config_lock);
}

static uint64_t devpts_device_number(uint32_t major, uint32_t minor) {
    return ((uint64_t)(minor & 0xffu)) |
           ((uint64_t)(major & 0xfffu) << 8) |
           ((uint64_t)(minor & ~0xffu) << 12) |
           ((uint64_t)(major & ~0xfffu) << 32);
}

static int devpts_parse_unsigned(const char *text, uint32_t length,
                                 uint32_t base, uint32_t *value) {
    uint64_t result = 0;
    if (!text || !length || !value || (base != 8u && base != 10u)) return -1;
    for (uint32_t index = 0; index < length; ++index) {
        uint32_t digit;
        if (text[index] < '0' || text[index] > '9') return -1;
        digit = (uint32_t)(text[index] - '0');
        if (digit >= base || result > (UINT32_MAX - digit) / base) return -1;
        result = result * base + digit;
    }
    *value = (uint32_t)result;
    return 0;
}

static int devpts_option_equals(const char *option, uint32_t length,
                                const char *name) {
    uint32_t index = 0;
    while (name[index]) {
        if (index >= length || option[index] != name[index]) return 0;
        ++index;
    }
    return index == length;
}

static int devpts_option_value(const char *option, uint32_t length,
                               const char *name, const char **value,
                               uint32_t *value_length) {
    uint32_t index = 0;
    while (name[index]) {
        if (index >= length || option[index] != name[index]) return 0;
        ++index;
    }
    if (index >= length || option[index] != '=') return 0;
    ++index;
    if (index == length) return -1;
    *value = option + index;
    *value_length = length - index;
    return 1;
}

static int devpts_parse_options(const char *options,
                                devpts_mount_config_t *config) {
    const char *cursor = options;
    if (!config) return -1;
    memset(config, 0, sizeof(*config));
    config->mode = DEVPTS_DEFAULT_MODE;
    config->ptmx_mode = DEVPTS_DEFAULT_PTMXMODE;
    config->max_slaves = DEVPTS_DEFAULT_MAX;
    if (!cursor || !cursor[0]) return 0;

    while (*cursor) {
        const char *option = cursor;
        const char *value = 0;
        uint32_t length = 0;
        uint32_t value_length = 0;
        uint32_t parsed;
        int matched;
        while (cursor[length] && cursor[length] != ',') ++length;
        if (!length) return -1;
        if (devpts_option_equals(option, length, "newinstance")) {
            config->new_instance = 1;
        } else if ((matched = devpts_option_value(
                        option, length, "gid", &value, &value_length)) != 0) {
            if (matched < 0 || devpts_parse_unsigned(
                    value, value_length, 10u, &config->gid) < 0)
                return -1;
        } else if ((matched = devpts_option_value(
                        option, length, "mode", &value, &value_length)) != 0) {
            if (matched < 0 || devpts_parse_unsigned(
                    value, value_length, 8u, &parsed) < 0 || parsed > 07777u)
                return -1;
            config->mode = (uint16_t)parsed;
        } else if ((matched = devpts_option_value(
                        option, length, "ptmxmode", &value,
                        &value_length)) != 0) {
            if (matched < 0 || devpts_parse_unsigned(
                    value, value_length, 8u, &parsed) < 0 || parsed > 07777u)
                return -1;
            config->ptmx_mode = (uint16_t)parsed;
        } else if ((matched = devpts_option_value(
                        option, length, "max", &value, &value_length)) != 0) {
            if (matched < 0 || devpts_parse_unsigned(
                    value, value_length, 10u, &config->max_slaves) < 0 ||
                !config->max_slaves)
                return -1;
        } else {
            return -1;
        }
        cursor += length;
        if (*cursor == ',') ++cursor;
    }
    return 0;
}

static int devpts_name(uint32_t index, char *name, uint32_t capacity) {
    char reversed[10];
    uint32_t digits = 0;
    if (!name || capacity < 2u) return -1;
    do {
        reversed[digits++] = (char)('0' + index % 10u);
        index /= 10u;
    } while (index && digits < sizeof(reversed));
    if (digits + 1u > capacity || index) return -1;
    for (uint32_t position = 0; position < digits; ++position)
        name[position] = reversed[digits - position - 1u];
    name[digits] = 0;
    return 0;
}

static int devpts_path(const char *name, char *path, uint32_t capacity) {
    static const char prefix[] = "/dev/pts/";
    uint32_t position = 0;
    if (!name || !path) return -1;
    while (prefix[position]) {
        if (position + 1u >= capacity) return -1;
        path[position] = prefix[position];
        ++position;
    }
    while (*name) {
        if (position + 1u >= capacity) return -1;
        path[position++] = *name++;
    }
    path[position] = 0;
    return 0;
}

static int devpts_create_inode(vfs_superblock_t *superblock,
                               const char *name, uint16_t mode,
                               uint32_t uid, uint32_t gid, uint64_t rdev,
                               vfs_inode_t *inode) {
    vfs_inode_t existing;
    uint32_t valid = VFS_SETATTR_MODE | VFS_SETATTR_UID |
                     VFS_SETATTR_GID | VFS_SETATTR_CTIME;
    if (!superblock || !superblock->ops || !superblock->ops->lookup ||
        !superblock->ops->mknod || !name || !inode)
        return -1;
    if (superblock->ops->lookup(
            superblock, &superblock->root, name, &existing) == 0) {
        if (!superblock->ops->unlink ||
            superblock->ops->unlink(
                superblock, &superblock->root, name) < 0)
            return -1;
    }
    if (superblock->ops->mknod(
            superblock, &superblock->root, name,
            (uint16_t)(VFS_INODE_CHR | mode), rdev, inode) < 0)
        return -1;
    if (vfs_inode_setattr(
            superblock, inode, mode, uid, gid, valid) < 0) {
        if (superblock->ops->unlink)
            (void)superblock->ops->unlink(
                superblock, &superblock->root, name);
        return -1;
    }
    vfs_path_cache_invalidate_all();
    return 0;
}

static int devpts_config_for_superblock(vfs_superblock_t *superblock,
                                        devpts_mount_config_t *config) {
    int found = -1;
    devpts_lock();
    for (uint32_t index = 0; index < DEVPTS_CONFIG_MAX; ++index) {
        if (!g_devpts_configs[index].used ||
            !vfs_superblock_same_filesystem(
                g_devpts_configs[index].superblock, superblock))
            continue;
        if (config) *config = g_devpts_configs[index];
        found = 0;
        break;
    }
    devpts_unlock();
    return found;
}

static int devpts_config_install(vfs_superblock_t *superblock,
                                 const devpts_mount_config_t *config) {
    devpts_mount_config_t *slot = 0;
    if (!superblock || !config) return -1;
    devpts_lock();
    for (uint32_t index = 0; index < DEVPTS_CONFIG_MAX; ++index) {
        if (g_devpts_configs[index].used &&
            vfs_superblock_same_filesystem(
                g_devpts_configs[index].superblock, superblock)) {
            slot = &g_devpts_configs[index];
            break;
        }
        if (!slot && !g_devpts_configs[index].used)
            slot = &g_devpts_configs[index];
    }
    if (slot) {
        *slot = *config;
        slot->used = 1;
        slot->superblock = vfs_superblock_stable(superblock);
    }
    devpts_unlock();
    return slot ? 0 : -1;
}

static void devpts_config_remove(vfs_superblock_t *superblock) {
    if (!superblock) return;
    devpts_lock();
    for (uint32_t index = 0; index < DEVPTS_CONFIG_MAX; ++index) {
        if (!g_devpts_configs[index].used ||
            !vfs_superblock_same_filesystem(
                g_devpts_configs[index].superblock, superblock))
            continue;
        memset(&g_devpts_configs[index], 0,
               sizeof(g_devpts_configs[index]));
        break;
    }
    devpts_unlock();
}

int devpts_mount(const char *device, const char *target,
                 const char *options) {
    devpts_mount_config_t config;
    vfs_inode_t root;
    vfs_inode_t ptmx;
    vfs_superblock_t *superblock = 0;
    int result;
    if (!target || devpts_parse_options(options, &config) < 0) return -1;
    result = tmpfs_mount_type(
        device && device[0] ? device : "devpts", target, "devpts");
    if (result < 0) return result;
    if (vfs_resolve(target, &root, &superblock, 0, 0) < 0 ||
        !superblock || strcmp(superblock->fs_name, "devpts") != 0 ||
        devpts_config_install(superblock, &config) < 0) {
        (void)vfs_umount(target, 1);
        return -1;
    }
    if (devpts_create_inode(
            superblock, "ptmx", config.ptmx_mode, 0, 0,
            devpts_device_number(5u, 2u), &ptmx) < 0) {
        devpts_config_remove(superblock);
        (void)vfs_umount(target, 1);
        return -1;
    }
    return 0;
}

int devpts_slave_create(devpts_slave_handle_t *handle, uint32_t index,
                        uint32_t uid) {
    devpts_mount_config_t config;
    vfs_inode_t root;
    vfs_superblock_t *superblock = 0;
    char name[12];
    if (!handle || devpts_name(index, name, sizeof(name)) < 0)
        return -1;
    memset(handle, 0, sizeof(*handle));
    if (vfs_resolve("/dev/pts", &root, &superblock, 0, 0) < 0 ||
        !superblock || strcmp(superblock->fs_name, "devpts") != 0 ||
        devpts_config_for_superblock(superblock, &config) < 0 ||
        index >= config.max_slaves ||
        devpts_create_inode(
            superblock, name, config.mode, uid, config.gid,
            devpts_device_number(136u, index), &handle->inode) < 0 ||
        devpts_path(name, handle->path, sizeof(handle->path)) < 0)
        return -1;
    handle->linked = 1;
    handle->index = index;
    handle->superblock = vfs_superblock_acquire(superblock);
    if (!handle->superblock) {
        if (superblock->ops && superblock->ops->unlink)
            (void)superblock->ops->unlink(
                superblock, &superblock->root, name);
        memset(handle, 0, sizeof(*handle));
        return -1;
    }
    return 0;
}

int devpts_slave_refresh(devpts_slave_handle_t *handle,
                         vfs_inode_t *inode,
                         vfs_superblock_t **superblock) {
    if (!handle || !handle->linked || !handle->superblock || !inode)
        return -1;
    if (vfs_inode_refresh(handle->superblock, &handle->inode) < 0)
        return -1;
    *inode = handle->inode;
    if (superblock) *superblock = handle->superblock;
    return 0;
}

void devpts_slave_destroy(devpts_slave_handle_t *handle) {
    char name[12];
    vfs_superblock_t *superblock;
    if (!handle || !handle->linked || !handle->superblock) return;
    superblock = handle->superblock;
    if (devpts_name(handle->index, name, sizeof(name)) == 0 &&
        superblock->ops && superblock->ops->unlink)
        (void)superblock->ops->unlink(
            superblock, &superblock->root, name);
    vfs_path_cache_invalidate_all();
    memset(handle, 0, sizeof(*handle));
    vfs_superblock_release(superblock);
}
