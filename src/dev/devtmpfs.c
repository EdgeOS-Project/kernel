/* SPDX-License-Identifier: MPL-2.0 */
/* Common Linux-compatible baseline device-node population. */

#include <stdint.h>
#include "block/block.h"
#include "block/device_mapper.h"
#include "block/loop.h"
#include "dev/alsa.h"
#include "dev/devtmpfs.h"
#include "drivers/nvme.h"
#include "fs/tmpfs.h"
#include "fs/fuse.h"
#include "fb_console.h"
#include "kernel/drm_runtime.h"
#include "kernel/console_device.h"
#include "kernel/input_device.h"
#include "string.h"
#include "vfs/vfs.h"

#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/cdev.h"
#define DEVTMPFS_BSD_NODE_MAX 128u
#endif

typedef struct {
    const char *name;
    uint16_t mode;
    uint16_t kind;
    uint32_t major;
    uint32_t minor;
} devtmpfs_node_t;

static const devtmpfs_node_t g_pointer_nodes[] = {
    { "input/mouse0", 0660u, VFS_INODE_CHR, 13u, 32u },
    { "input/mice", 0660u, VFS_INODE_CHR, 13u, 63u },
};

static const devtmpfs_node_t g_audio_nodes[] = {
    { "snd/controlC0", 0660u, VFS_INODE_CHR, EDGE_ALSA_CARD_MAJOR, 0u },
    { "snd/pcmC0D0p", 0660u, VFS_INODE_CHR, EDGE_ALSA_CARD_MAJOR, 16u },
    { "snd/pcmC0D0c", 0660u, VFS_INODE_CHR, EDGE_ALSA_CARD_MAJOR, 24u },
    { "snd/timer", 0660u, VFS_INODE_CHR, EDGE_ALSA_CARD_MAJOR, 33u },
};

#ifdef CONFIG_LOOP_DEVICE
static const devtmpfs_node_t g_loop_control_node = {
    "loop-control", 0660u, VFS_INODE_CHR, 10u, 237u
};
#endif

#ifdef CONFIG_DEVICE_MAPPER
static const devtmpfs_node_t g_device_mapper_control_node = {
    "mapper/control", 0600u, VFS_INODE_CHR,
    EDGE_DM_CONTROL_MAJOR, EDGE_DM_CONTROL_MINOR
};
static char g_dm_current_names[EDGE_DM_MAX_DEVICES][EDGE_DM_NAME_LEN + 8u];
static char g_dm_previous_names[EDGE_DM_MAX_DEVICES][EDGE_DM_NAME_LEN + 8u];
static uint32_t g_dm_previous_count;
#endif

static char g_devtmpfs_mountpoint[VFS_PATH_MAX];
static int g_devtmpfs_mounted;
static char g_block_current_names[BLOCK_MAX_DEVICES][BLOCK_NAME_MAX];
static char g_block_previous_names[BLOCK_MAX_DEVICES][BLOCK_NAME_MAX];
static uint32_t g_block_previous_count;

#ifdef CONFIG_BSD_DRIVER_BRIDGE
static bsd_bridge_cdev_node_t g_bsd_current_nodes[DEVTMPFS_BSD_NODE_MAX];
static char g_bsd_previous_names[DEVTMPFS_BSD_NODE_MAX][128];
static uint32_t g_bsd_previous_count;
#endif

static uint64_t linux_device_number(uint32_t major, uint32_t minor) {
    return ((uint64_t)(minor & 0xffu)) |
           ((uint64_t)(major & 0xfffu) << 8) |
           ((uint64_t)(minor & ~0xffu) << 12) |
           ((uint64_t)(major & ~0xfffu) << 32);
}

static int devtmpfs_path(char *out, uint32_t capacity,
                         const char *mountpoint, const char *name) {
    uint32_t length = 0;
    if (!out || capacity < 2u || !mountpoint || mountpoint[0] != '/' ||
        !name || !name[0]) return -1;
    while (mountpoint[length]) {
        if (length + 1u >= capacity) return -1;
        out[length] = mountpoint[length];
        ++length;
    }
    if (length > 1u && out[length - 1u] != '/') {
        if (length + 1u >= capacity) return -1;
        out[length++] = '/';
    }
    while (*name) {
        if (length + 1u >= capacity) return -1;
        out[length++] = *name++;
    }
    out[length] = 0;
    return 0;
}

static int __attribute__((noinline))
devtmpfs_ensure_directory(const char *mountpoint, const char *name,
                          uint16_t mode) {
    char path[VFS_PATH_MAX];
    vfs_inode_t inode;
    if (devtmpfs_path(path, sizeof(path), mountpoint, name) < 0) return -1;
    if (vfs_resolve(path, &inode, 0, 0, 0) < 0) {
        if (vfs_mkdir(path) < 0 ||
            vfs_resolve(path, &inode, 0, 0, 0) < 0) return -1;
    }
    if ((inode.mode & 0xf000u) != VFS_INODE_DIR) return -1;
    return vfs_chmod(path, mode);
}

#ifdef CONFIG_BSD_DRIVER_BRIDGE
static int devtmpfs_ensure_parent_directories(const char *mountpoint,
                                               const char *name) {
    char parent[128];
    uint32_t length = 0;

    if (!name || !name[0]) return -1;
    while (name[length]) {
        if (length + 1u >= sizeof(parent)) return -1;
        parent[length] = name[length];
        if (name[length] == '/') {
            if (length == 0) return -1;
            parent[length] = 0;
            if (devtmpfs_ensure_directory(mountpoint, parent, 0755u) < 0)
                return -1;
            parent[length] = '/';
        }
        ++length;
    }
    return 0;
}
#endif

static int __attribute__((noinline))
devtmpfs_ensure_node(const char *mountpoint, const devtmpfs_node_t *node,
                     uint16_t uid, uint16_t gid) {
    char path[VFS_PATH_MAX];
    vfs_inode_t inode;
    if (!node || devtmpfs_path(path, sizeof(path), mountpoint, node->name) < 0)
        return -1;
    if (vfs_mknod(path, (uint16_t)(node->kind | node->mode),
                  linux_device_number(node->major, node->minor)) < 0 &&
        vfs_resolve(path, &inode, 0, 0, 0) < 0) return -1;
    /* Kernel-populated devtmpfs ownership and modes are not caller-umask data. */
    if (vfs_chmod(path, node->mode) < 0 || vfs_chown(path, uid, gid) < 0)
        return -1;
    return 0;
}

static int devtmpfs_remove_path(const char *mountpoint, const char *name) {
    char path[VFS_PATH_MAX];
    vfs_inode_t inode;
    if (devtmpfs_path(path, sizeof(path), mountpoint, name) < 0) return -1;
    if (vfs_resolve(path, &inode, 0, 0, 0) < 0) return 0;
    return vfs_unlink(path);
}

static int devtmpfs_input_event_name(uint32_t event_index,
                                     char *name, uint32_t capacity) {
    static const char prefix[] = "input/event";
    char reverse[10];
    uint32_t length = 0;
    uint32_t digits = 0;

    if (!name || capacity < sizeof(prefix) + 1u) return -1;
    while (prefix[length]) {
        if (length + 1u >= capacity) return -1;
        name[length] = prefix[length];
        ++length;
    }
    do {
        reverse[digits++] = (char)('0' + event_index % 10u);
        event_index /= 10u;
    } while (event_index && digits < sizeof(reverse));
    while (digits) {
        if (length + 1u >= capacity) return -1;
        name[length++] = reverse[--digits];
    }
    name[length] = 0;
    return 0;
}

static int devtmpfs_block_name_is_current(const char *name,
                                          uint32_t current_count) {
    for (uint32_t index = 0; index < current_count; ++index) {
        if (strcmp(g_block_current_names[index], name) == 0)
            return 1;
    }
    return 0;
}

static int devtmpfs_update_block_nodes(const char *mountpoint) {
    uint32_t current_count = (uint32_t)block_count();

    if (current_count > BLOCK_MAX_DEVICES) return -1;
    memset(g_block_current_names, 0, sizeof(g_block_current_names));
    for (uint32_t index = 0; index < current_count; ++index) {
        block_device_t *device = block_get((int)index);

        if (!device || !device->present) return -1;
        strncpy(g_block_current_names[index], device->name,
                BLOCK_NAME_MAX - 1u);
    }
    for (uint32_t index = 0; index < g_block_previous_count; ++index) {
        if (g_block_previous_names[index][0] &&
            !devtmpfs_block_name_is_current(
                g_block_previous_names[index], current_count) &&
            devtmpfs_remove_path(
                mountpoint, g_block_previous_names[index]) < 0)
            return -1;
    }
    for (uint32_t index = 0; index < current_count; ++index) {
        block_device_t *device = block_get((int)index);
        devtmpfs_node_t node;

        if (!device || !device->present ||
            block_linux_major_minor(device, &node.major, &node.minor) < 0)
            continue;
        node.name = device->name;
        node.mode = 0660u;
        node.kind = VFS_INODE_BLK;
        if (devtmpfs_ensure_node(mountpoint, &node, 0, 6) < 0)
            return -1;
    }
    memset(g_block_previous_names, 0, sizeof(g_block_previous_names));
    memcpy(g_block_previous_names, g_block_current_names,
           sizeof(g_block_previous_names));
    g_block_previous_count = current_count;
    return 0;
}

#ifdef CONFIG_DEVICE_MAPPER
static int devtmpfs_dm_alias_is_current(
    const char names[EDGE_DM_MAX_DEVICES][EDGE_DM_NAME_LEN + 8u],
    uint32_t count, const char *name) {
    for (uint32_t index = 0; index < count; ++index)
        if (strcmp(names[index], name) == 0) return 1;
    return 0;
}

static int devtmpfs_update_device_mapper_nodes(const char *mountpoint) {
    uint32_t count = edge_dm_device_count();

    if (count > EDGE_DM_MAX_DEVICES) return -1;
    memset(g_dm_current_names, 0, sizeof(g_dm_current_names));
    for (uint32_t index = 0; index < count; ++index) {
        char name[EDGE_DM_NAME_LEN];
        char node_name[BLOCK_NAME_MAX];
        devtmpfs_node_t node;
        uint32_t minor;

        if (edge_dm_device_identity_at(
                index, name, sizeof(name), node_name, sizeof(node_name),
                &minor) < 0)
            return -1;
        if (strlen(name) + 8u > sizeof(g_dm_current_names[index])) return -1;
        memcpy(g_dm_current_names[index], "mapper/", 7u);
        strcpy(g_dm_current_names[index] + 7u, name);
        node.name = g_dm_current_names[index];
        node.mode = 0660u;
        node.kind = VFS_INODE_BLK;
        node.major = EDGE_DM_BLOCK_MAJOR;
        node.minor = minor;
        if (devtmpfs_ensure_node(mountpoint, &node, 0, 6) < 0)
            return -1;
    }
    for (uint32_t index = 0; index < g_dm_previous_count; ++index)
        if (g_dm_previous_names[index][0] &&
            !devtmpfs_dm_alias_is_current(
                g_dm_current_names, count, g_dm_previous_names[index]) &&
            devtmpfs_remove_path(
                mountpoint, g_dm_previous_names[index]) < 0)
            return -1;
    memset(g_dm_previous_names, 0, sizeof(g_dm_previous_names));
    memcpy(g_dm_previous_names, g_dm_current_names,
           sizeof(g_dm_current_names));
    g_dm_previous_count = count;
    return 0;
}
#endif

int devtmpfs_refresh_block_nodes(void) {
    if (!g_devtmpfs_mounted || !g_devtmpfs_mountpoint[0]) return 0;
    if (devtmpfs_update_block_nodes(g_devtmpfs_mountpoint) < 0) return -1;
#ifdef CONFIG_DEVICE_MAPPER
    return devtmpfs_update_device_mapper_nodes(g_devtmpfs_mountpoint);
#else
    return 0;
#endif
}

static int devtmpfs_update_input_nodes(const char *mountpoint) {
    int any_present = 0;
    int pointer_present = 0;
    for (uint32_t event_index = 0;
         event_index < EDGE_INPUT_DEVICE_MAX; ++event_index) {
        if (input_device_present(event_index)) any_present = 1;
        if (input_device_role(event_index) == EDGE_INPUT_ROLE_POINTER)
            pointer_present = 1;
    }
    if (!any_present) {
        for (uint32_t event_index = 0;
             event_index < EDGE_INPUT_DEVICE_MAX; ++event_index) {
            char name[32];

            if (devtmpfs_input_event_name(
                    event_index, name, sizeof(name)) < 0 ||
                devtmpfs_remove_path(mountpoint, name) < 0)
                return -1;
        }
        for (uint32_t index = 0;
             index < sizeof(g_pointer_nodes) /
                         sizeof(g_pointer_nodes[0]); ++index)
            if (devtmpfs_remove_path(
                    mountpoint, g_pointer_nodes[index].name) < 0)
                return -1;
        return 0;
    }
    if (devtmpfs_ensure_directory(mountpoint, "input", 0755u) < 0)
        return -1;
    for (uint32_t event_index = 0;
         event_index < EDGE_INPUT_DEVICE_MAX; ++event_index) {
        char name[32];
        devtmpfs_node_t node;

        if (devtmpfs_input_event_name(
                event_index, name, sizeof(name)) < 0)
            return -1;
        node.name = name;
        node.mode = 0660u;
        node.kind = VFS_INODE_CHR;
        node.major = 13u;
        node.minor = 64u + event_index;
        if (input_device_present(event_index)) {
            if (devtmpfs_ensure_node(mountpoint, &node, 0, 18) < 0)
                return -1;
        } else if (devtmpfs_remove_path(mountpoint, name) < 0) {
            return -1;
        }
    }
    for (uint32_t index = 0;
         index < sizeof(g_pointer_nodes) / sizeof(g_pointer_nodes[0]);
         ++index) {
        if (pointer_present) {
            if (devtmpfs_ensure_node(
                    mountpoint, &g_pointer_nodes[index], 0, 18) < 0)
                return -1;
        } else if (devtmpfs_remove_path(mountpoint,
                                        g_pointer_nodes[index].name) < 0) {
            return -1;
        }
    }
    return 0;
}

int devtmpfs_refresh_input_nodes(void) {
    if (!g_devtmpfs_mounted || !g_devtmpfs_mountpoint[0]) return 0;
    return devtmpfs_update_input_nodes(g_devtmpfs_mountpoint);
}

static int devtmpfs_update_audio_nodes(const char *mountpoint) {
    int playback = alsa_playback_available();
    int capture = alsa_capture_available();
    int available = playback || capture;

    if (!available) {
        for (uint32_t index = 0;
             index < sizeof(g_audio_nodes) / sizeof(g_audio_nodes[0]);
             ++index) {
            if (devtmpfs_remove_path(
                    mountpoint, g_audio_nodes[index].name) < 0)
                return -1;
        }
        return devtmpfs_remove_path(mountpoint, "snd");
    }
    if (devtmpfs_ensure_directory(mountpoint, "snd", 0755u) < 0)
        return -1;
    for (uint32_t index = 0;
         index < sizeof(g_audio_nodes) / sizeof(g_audio_nodes[0]);
         ++index) {
        int wanted = index == 1u ? playback :
                     index == 2u ? capture : 1;

        if (wanted) {
            if (devtmpfs_ensure_node(
                    mountpoint, &g_audio_nodes[index], 0, 29) < 0)
                return -1;
        } else if (devtmpfs_remove_path(
                       mountpoint, g_audio_nodes[index].name) < 0) {
            return -1;
        }
    }
    return 0;
}

int devtmpfs_refresh_audio_nodes(void) {
    if (!g_devtmpfs_mounted || !g_devtmpfs_mountpoint[0]) return 0;
    return devtmpfs_update_audio_nodes(g_devtmpfs_mountpoint);
}

#ifdef CONFIG_BSD_DRIVER_BRIDGE
static int devtmpfs_bsd_name_is_current(const char *name,
                                        uint32_t current_count) {
    for (uint32_t index = 0; index < current_count; ++index) {
        if (strcmp(g_bsd_current_nodes[index].name, name) == 0)
            return 1;
    }
    return 0;
}

static int devtmpfs_update_bsd_bridge_nodes(const char *mountpoint) {
    uint32_t current_count = bsd_bridge_cdev_node_count();

    if (current_count > DEVTMPFS_BSD_NODE_MAX) return -1;
    memset(g_bsd_current_nodes, 0, sizeof(g_bsd_current_nodes));
    for (uint32_t index = 0; index < current_count; ++index) {
        if (bsd_bridge_cdev_node_at(index, &g_bsd_current_nodes[index]) < 0)
            return -1;
    }
    for (uint32_t index = 0; index < g_bsd_previous_count; ++index) {
        if (g_bsd_previous_names[index][0] &&
            !devtmpfs_bsd_name_is_current(
                g_bsd_previous_names[index], current_count) &&
            devtmpfs_remove_path(
                mountpoint, g_bsd_previous_names[index]) < 0)
            return -1;
    }
    for (uint32_t index = 0; index < current_count; ++index) {
        devtmpfs_node_t node = {
            .name = g_bsd_current_nodes[index].name,
            .mode = g_bsd_current_nodes[index].mode,
            .kind = VFS_INODE_CHR,
            .major = g_bsd_current_nodes[index].major,
            .minor = g_bsd_current_nodes[index].minor,
        };

        if (devtmpfs_ensure_parent_directories(mountpoint, node.name) < 0 ||
            devtmpfs_ensure_node(
                mountpoint, &node, g_bsd_current_nodes[index].uid,
                g_bsd_current_nodes[index].gid) < 0)
            return -1;
    }
    memset(g_bsd_previous_names, 0, sizeof(g_bsd_previous_names));
    for (uint32_t index = 0; index < current_count; ++index)
        strncpy(g_bsd_previous_names[index],
                g_bsd_current_nodes[index].name,
                sizeof(g_bsd_previous_names[index]) - 1u);
    g_bsd_previous_count = current_count;
    return 0;
}

int devtmpfs_refresh_bsd_bridge_nodes(void) {
    if (!g_devtmpfs_mounted || !g_devtmpfs_mountpoint[0]) return 0;
    return devtmpfs_update_bsd_bridge_nodes(g_devtmpfs_mountpoint);
}

void bsd_bridge_devtmpfs_changed(void) {
    (void)devtmpfs_refresh_block_nodes();
    (void)devtmpfs_refresh_bsd_bridge_nodes();
}
#else
int devtmpfs_refresh_bsd_bridge_nodes(void) {
    return 0;
}
#endif

int devtmpfs_populate_standard_nodes(const char *mountpoint) {
    static const devtmpfs_node_t core_nodes[] = {
        { "null", 0666u, VFS_INODE_CHR, 1u, 3u },
        { "zero", 0666u, VFS_INODE_CHR, 1u, 5u },
        { "full", 0666u, VFS_INODE_CHR, 1u, 7u },
        { "random", 0666u, VFS_INODE_CHR, 1u, 8u },
        { "urandom", 0666u, VFS_INODE_CHR, 1u, 9u },
        { "kmsg", 0600u, VFS_INODE_CHR, 1u, 11u },
        { "tty", 0666u, VFS_INODE_CHR, 5u, 0u },
        { "console", 0600u, VFS_INODE_CHR, 5u, 1u },
        { "ptmx", 0666u, VFS_INODE_CHR, 5u, 2u },
        { "tty0", 0620u, VFS_INODE_CHR, 4u, 0u },
        { "fb0", 0660u, VFS_INODE_CHR, 29u, 0u },
        { "dri/card0", 0660u, VFS_INODE_CHR, 226u, 0u },
#ifdef CONFIG_FUSE_FS
        { "fuse", 0666u, VFS_INODE_CHR,
          EDGE_FUSE_DEVICE_MAJOR, EDGE_FUSE_DEVICE_MINOR },
#endif
    };
    static const devtmpfs_node_t render_node =
        { "dri/renderD128", 0660u, VFS_INODE_CHR, 226u, 128u };
    kernel_console_device_t serial;
    devtmpfs_node_t serial_node;
    if (!mountpoint || mountpoint[0] != '/') return -1;
    if (devtmpfs_ensure_directory(mountpoint, "dri", 0755u) < 0)
        return -1;
    for (uint32_t index = 0;
         index < sizeof(core_nodes) / sizeof(core_nodes[0]); ++index) {
        uint16_t group = core_nodes[index].major == 4u &&
                         core_nodes[index].minor <= EDGE_FB_VT_COUNT ? 5u : 0u;
        if (devtmpfs_ensure_node(mountpoint, &core_nodes[index], 0, group) < 0)
            return -1;
    }
    for (uint32_t vt = 1u; vt <= EDGE_FB_VT_COUNT; ++vt) {
        char name[8] = "tty";
        devtmpfs_node_t node;
        uint32_t position = 3u;

        if (vt >= 10u) name[position++] = (char)('0' + vt / 10u);
        name[position++] = (char)('0' + vt % 10u);
        name[position] = 0;
        node.name = name;
        node.mode = 0620u;
        node.kind = VFS_INODE_CHR;
        node.major = 4u;
        node.minor = vt;
        if (devtmpfs_ensure_node(mountpoint, &node, 0, 5u) < 0)
            return -1;
    }
    if (edge_drm_path_is_render("/dev/dri/renderD128") &&
        devtmpfs_ensure_node(mountpoint, &render_node, 0, 0) < 0)
        return -1;
#ifdef CONFIG_NVME
    if (nvme_present()) {
        static const devtmpfs_node_t nvme_nodes[] = {
            { "nvme0", 0600u, VFS_INODE_CHR, 240u, 0u },
            { "ng0n1", 0600u, VFS_INODE_CHR, 241u, 0u },
        };

        for (uint32_t index = 0;
             index < sizeof(nvme_nodes) / sizeof(nvme_nodes[0]); ++index)
            if (devtmpfs_ensure_node(
                    mountpoint, &nvme_nodes[index], 0, 6u) < 0)
                return -1;
    }
#endif
    if (kernel_arch_serial_console_device(&serial) == 0) {
        serial_node.name = serial.name;
        serial_node.mode = 0620u;
        serial_node.kind = VFS_INODE_CHR;
        serial_node.major = serial.major;
        serial_node.minor = serial.minor;
        if (devtmpfs_ensure_node(mountpoint, &serial_node, 0, 5u) < 0)
            return -1;
    }
#ifdef CONFIG_LOOP_DEVICE
    if (devtmpfs_ensure_node(
            mountpoint, &g_loop_control_node, 0, 6) < 0)
        return -1;
    for (uint32_t index = 0; index < EDGE_LOOP_DEVICE_COUNT; ++index) {
        char name[16];
        devtmpfs_node_t node;
        uint32_t position = 4u;

        name[0] = 'l';
        name[1] = 'o';
        name[2] = 'o';
        name[3] = 'p';
        if (index >= 10u) name[position++] = (char)('0' + index / 10u);
        name[position++] = (char)('0' + index % 10u);
        name[position] = 0;
        node.name = name;
        node.mode = 0660u;
        node.kind = VFS_INODE_BLK;
        node.major = 7u;
        node.minor = index;
        if (devtmpfs_ensure_node(mountpoint, &node, 0, 6) < 0)
            return -1;
    }
#endif
#ifdef CONFIG_DEVICE_MAPPER
    if (devtmpfs_ensure_directory(mountpoint, "mapper", 0755u) < 0 ||
        devtmpfs_ensure_node(
            mountpoint, &g_device_mapper_control_node, 0, 6) < 0 ||
        devtmpfs_update_device_mapper_nodes(mountpoint) < 0)
        return -1;
#endif
    if (devtmpfs_update_block_nodes(mountpoint) < 0)
        return -1;
    if (devtmpfs_update_input_nodes(mountpoint) < 0)
        return -1;
    if (devtmpfs_update_audio_nodes(mountpoint) < 0)
        return -1;
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return devtmpfs_update_bsd_bridge_nodes(mountpoint);
#else
    return 0;
#endif
}

int devtmpfs_mount(const char *device, const char *target) {
    int result;
    result = tmpfs_mount_type(device && device[0] ? device : "devtmpfs",
                              target, "devtmpfs");
    if (result < 0) return result;
    strncpy(g_devtmpfs_mountpoint, target,
            sizeof(g_devtmpfs_mountpoint) - 1u);
    g_devtmpfs_mountpoint[sizeof(g_devtmpfs_mountpoint) - 1u] = 0;
    g_devtmpfs_mounted = 1;
    if (devtmpfs_populate_standard_nodes(target) < 0) {
        g_devtmpfs_mounted = 0;
        g_devtmpfs_mountpoint[0] = 0;
        (void)vfs_umount(target, 1);
        return -1;
    }
    return 0;
}
