/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux-compatible sysfs device model. */

#include <stdint.h>
#ifdef CONFIG_LOOP_DEVICE
#include "block/loop.h"
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/cdev.h"
#endif
#ifdef CONFIG_PCI
#include "drivers/pci.h"
#endif
#ifdef CONFIG_VIRTIO_GPU
#include "drivers/virtio_gpu.h"
#endif
#include "fb.h"
#include "fs/sysfs.h"
#include "kernel/console_device.h"
#include "kernel/device_uevent.h"
#include "kernel/input_device.h"
#include "kernel/namespace_runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/virtgpu_runtime.h"
#include "net/lwip_stack.h"
#include "net/network_core.h"
#include "string.h"
#include "vfs/vfs.h"

enum {
    SYS_ROOT = 1, SYS_FS, SYS_CGROUP, SYS_CLASS, SYS_GRAPHICS, SYS_FB0, SYS_FB_DEVICE,
    SYS_FB_SUBSYSTEM, SYS_FB_NAME, SYS_FB_SIZE, SYS_FB_STRIDE, SYS_FB_BPP,
    SYS_FB_DEV, SYS_FB_UEVENT, SYS_BUS, SYS_PLATFORM, SYS_PLATFORM_DEVICES,
    SYS_PLATFORM_DEVICE, SYS_DEVICES, SYS_DEVICES_PLATFORM, SYS_DEVICE,
    SYS_DEVICE_SUBSYSTEM, SYS_DEVICE_GRAPHICS, SYS_DEVICE_FB0, SYS_INPUT_CLASS,
    SYS_DEVICES_VIRTUAL, SYS_DEVICES_VIRTUAL_INPUT, SYS_TTY_CLASS,
    SYS_DEVICES_VIRTUAL_TTY, SYS_VIDEO4LINUX_CLASS, SYS_BSD_CDEV_CLASS,
    SYS_DEVICES_VIRTUAL_VIDEO4LINUX, SYS_DEVICES_VIRTUAL_BSD_CDEV,
    SYS_DEV, SYS_DEV_CHAR, SYS_DEV_BLOCK, SYS_BLOCK,
    SYS_DRM_CLASS, SYS_DRM_CLASS_CARD0, SYS_DRM_CLASS_RENDERD128,
    SYS_DEVICES_VIRTUAL_DRM, SYS_DRM_CARD0, SYS_DRM_CARD0_DEV,
    SYS_DRM_CARD0_UEVENT, SYS_DRM_CARD0_SUBSYSTEM, SYS_DRM_CARD0_STATUS,
    SYS_DRM_CARD0_ENABLED, SYS_DRM_CARD0_MODES, SYS_DRM_CARD0_DEVICE,
    SYS_DRM_RENDERD128, SYS_DRM_RENDERD128_DEV, SYS_DRM_RENDERD128_UEVENT,
    SYS_DRM_RENDERD128_SUBSYSTEM, SYS_DRM_RENDERD128_DEVICE,
    SYS_DRM_PCI_DIRECTORY, SYS_DRM_PCI_CARD0, SYS_DRM_PCI_RENDERD128,
    SYS_DRM_VIRTUAL_DEVICE, SYS_DRM_VIRTUAL_DEVICE_SUBSYSTEM,
    SYS_DRM_VIRTUAL_DEVICE_UEVENT, SYS_DRM_VIRTUAL_DEVICE_DRM,
    SYS_DRM_VIRTUAL_DEVICE_CARD0, SYS_DRM_VIRTUAL_DEVICE_RENDERD128,
    SYS_INPUT0_BASE = 10000,
    SYS_INPUT_DEV_CHAR_BASE = 10400,
    SYS_INPUT_CLASS_BASE = 10500,
    SYS_TTY_DEVICE_BASE = 12000,
    SYS_TTY_DEV_CHAR_BASE = 12500,
    SYS_FB_DEV_CHAR = 600,
    SYS_DRM_CARD0_DEV_CHAR = 601,
    SYS_DRM_RENDERD128_DEV_CHAR = 602,
    SYS_DEVICES_SYSTEM = 700,
    SYS_CPU_ROOT = 701,
    SYS_CPU_POSSIBLE = 702,
    SYS_CPU_PRESENT = 703,
    SYS_CPU_ONLINE = 704,
    SYS_CPU_OFFLINE = 705,
    SYS_CPU_KERNEL_MAX = 706,
    SYS_CPU_NODE_BASE = 720,
    SYS_NET_CLASS = 1400,
    SYS_NET_CLASS_LO = 1401,
    SYS_NET_CLASS_ETH0 = 1402,
    SYS_DEVICES_VIRTUAL_NET = 1403,
    SYS_NET_NODE_BASE = 1420,
    SYS_PCI_BUS = 1500,
    SYS_PCI_DEVICES = 1501,
    SYS_PCI_NODE_BASE = 1600,
    SYS_LOOP_NODE_BASE = 11000,
    SYS_NET_DYNAMIC_NODE_BASE = 20000
};

#ifdef CONFIG_LOOP_DEVICE
enum {
    LOOP_NODE_ROOT = 0,
    LOOP_NODE_DIRECTORY,
    LOOP_NODE_DEV,
    LOOP_NODE_SIZE,
    LOOP_NODE_RO,
    LOOP_NODE_REMOVABLE,
    LOOP_NODE_STAT,
    LOOP_NODE_UEVENT,
    LOOP_NODE_RANGE,
    LOOP_NODE_ALIGNMENT_OFFSET,
    LOOP_NODE_DISCARD_ALIGNMENT,
    LOOP_NODE_CAPABILITY,
    LOOP_NODE_BACKING_FILE,
    LOOP_NODE_OFFSET,
    LOOP_NODE_SIZELIMIT,
    LOOP_NODE_AUTOCLEAR,
    LOOP_NODE_PARTSCAN,
    LOOP_NODE_DIO,
    LOOP_NODE_DEV_LINK,
    LOOP_NODE_COUNT
};

static const char *const g_loop_root_attribute_names[] = {
    "dev", "size", "ro", "removable", "stat", "uevent", "range",
    "alignment_offset", "discard_alignment", "capability"
};

static const char *const g_loop_attribute_names[] = {
    "backing_file", "offset", "sizelimit", "autoclear", "partscan", "dio"
};

#define SYS_LOOP_NODE(device, node) \
    (SYS_LOOP_NODE_BASE + (uint32_t)(device) * LOOP_NODE_COUNT + \
     (uint32_t)(node))

static int sys_loop_node(uint32_t node, uint32_t *device,
                         uint32_t *attribute) {
    uint32_t relative;

    if (node < SYS_LOOP_NODE_BASE ||
        node >= SYS_LOOP_NODE_BASE + EDGE_LOOP_DEVICE_COUNT * LOOP_NODE_COUNT)
        return 0;
    relative = node - SYS_LOOP_NODE_BASE;
    if (device) *device = relative / LOOP_NODE_COUNT;
    if (attribute) *attribute = relative % LOOP_NODE_COUNT;
    return 1;
}

static uint32_t sys_loop_device_name(char *name, uint32_t capacity,
                                     uint32_t device) {
    uint32_t length = 0;

    if (!name || capacity < 6u || device >= EDGE_LOOP_DEVICE_COUNT)
        return 0;
    name[length++] = 'l';
    name[length++] = 'o';
    name[length++] = 'o';
    name[length++] = 'p';
    if (device >= 10u) name[length++] = (char)('0' + device / 10u);
    name[length++] = (char)('0' + device % 10u);
    name[length] = 0;
    return length;
}
#endif

enum {
    CPU_NODE_ROOT = 0,
    CPU_NODE_ONLINE,
    CPU_NODE_TOPOLOGY,
    CPU_NODE_CORE_ID,
    CPU_NODE_PHYSICAL_PACKAGE_ID,
    CPU_NODE_CORE_SIBLINGS_LIST,
    CPU_NODE_THREAD_SIBLINGS_LIST,
    CPU_NODE_CLUSTER_CPUS_LIST,
    CPU_NODE_COUNT
};

#define SYS_CPU_NODE(cpu, node) \
    (SYS_CPU_NODE_BASE + (uint32_t)(cpu) * CPU_NODE_COUNT + \
     (uint32_t)(node))
#define SYS_CPU_MAX 64u

enum {
    NET_NODE_ROOT = 0,
    NET_NODE_IFINDEX,
    NET_NODE_IFLINK,
    NET_NODE_FLAGS,
    NET_NODE_MTU,
    NET_NODE_TYPE,
    NET_NODE_ADDRESS,
    NET_NODE_BROADCAST,
    NET_NODE_OPERSTATE,
    NET_NODE_CARRIER,
    NET_NODE_TX_QUEUE_LEN,
    NET_NODE_ADDR_ASSIGN_TYPE,
    NET_NODE_ADDR_LEN,
    NET_NODE_DEV_ID,
    NET_NODE_DORMANT,
    NET_NODE_LINK_MODE,
    NET_NODE_PROTO_DOWN,
    NET_NODE_UEVENT,
    NET_NODE_SUBSYSTEM,
    NET_NODE_STATISTICS,
    NET_NODE_RX_PACKETS,
    NET_NODE_RX_BYTES,
    NET_NODE_TX_PACKETS,
    NET_NODE_TX_BYTES,
    NET_NODE_CLASS_LINK,
    NET_NODE_COUNT
};

#define SYS_NET_NODE(device, node) \
    (SYS_NET_NODE_BASE + (uint32_t)(device) * NET_NODE_COUNT + \
     (uint32_t)(node))
#define SYS_NET_DYNAMIC_NODE(ifindex, node) \
    (SYS_NET_DYNAMIC_NODE_BASE + (uint32_t)(ifindex) * NET_NODE_COUNT + \
     (uint32_t)(node))
#define SYS_NET_DYNAMIC_IFINDEX_MAX 32768u

#ifdef CONFIG_PCI
enum {
    PCI_NODE_ROOT = 0,
    PCI_NODE_VENDOR,
    PCI_NODE_DEVICE,
    PCI_NODE_SUBSYSTEM_VENDOR,
    PCI_NODE_SUBSYSTEM_DEVICE,
    PCI_NODE_CLASS,
    PCI_NODE_REVISION,
    PCI_NODE_IRQ,
    PCI_NODE_RESOURCE,
    PCI_NODE_MODALIAS,
    PCI_NODE_UEVENT,
    PCI_NODE_SUBSYSTEM,
    PCI_NODE_COUNT
};

#define SYS_PCI_MAX_DEVICES 256u
#define SYS_PCI_NODE(device, node) \
    (SYS_PCI_NODE_BASE + (uint32_t)(device) * PCI_NODE_COUNT + \
     (uint32_t)(node))

static const char *const g_pci_attribute_names[] = {
    "vendor", "device", "subsystem_vendor", "subsystem_device", "class",
    "revision", "irq", "resource", "modalias", "uevent", "subsystem"
};

static const uint16_t g_pci_attribute_modes[] = {
    VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
    VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
    VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
    VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
    VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0644,
    VFS_INODE_LNK | 0777
};
#endif

enum {
    TTY_NODE_CLASS = 0,
    TTY_NODE_ROOT,
    TTY_NODE_DEV,
    TTY_NODE_UEVENT,
    TTY_NODE_SUBSYSTEM,
    TTY_NODE_ACTIVE,
    TTY_NODE_COUNT
};

#define SYS_TTY_NODE(device, node) \
    (SYS_TTY_DEVICE_BASE + (uint32_t)(device) * TTY_NODE_COUNT + \
     (uint32_t)(node))
#define SYS_TTY_DEV_CHAR_NODE(device) \
    (SYS_TTY_DEV_CHAR_BASE + (uint32_t)(device))

enum {
    INPUT_NODE_ROOT = 0,
    INPUT_NODE_NAME,
    INPUT_NODE_PHYS,
    INPUT_NODE_UNIQ,
    INPUT_NODE_PROPERTIES,
    INPUT_NODE_UEVENT,
    INPUT_NODE_SUBSYSTEM,
    INPUT_NODE_ID,
    INPUT_NODE_ID_BUSTYPE,
    INPUT_NODE_ID_VENDOR,
    INPUT_NODE_ID_PRODUCT,
    INPUT_NODE_ID_VERSION,
    INPUT_NODE_CAPABILITIES,
    INPUT_NODE_CAP_EV,
    INPUT_NODE_CAP_KEY,
    INPUT_NODE_CAP_REL,
    INPUT_NODE_CAP_ABS,
    INPUT_NODE_EVENT,
    INPUT_NODE_EVENT_DEV,
    INPUT_NODE_EVENT_UEVENT,
    INPUT_NODE_EVENT_SUBSYSTEM,
    INPUT_NODE_COUNT
};

#define SYS_INPUT_NODE(device, node) \
    (SYS_INPUT0_BASE + (uint32_t)(device) * INPUT_NODE_COUNT + (uint32_t)(node))
#define SYS_INPUT_CLASS_NODE(device, event) \
    (SYS_INPUT_CLASS_BASE + (uint32_t)(device) * 2u + \
     ((event) ? 1u : 0u))

#ifdef CONFIG_BSD_DRIVER_BRIDGE
enum {
    SYS_BSD_CDEV_DEV_CHAR = 0,
    SYS_BSD_CDEV_CLASS_LINK,
    SYS_BSD_CDEV_DEVICE_ROOT,
    SYS_BSD_CDEV_DEVICE_DEV,
    SYS_BSD_CDEV_DEVICE_UEVENT,
    SYS_BSD_CDEV_DEVICE_SUBSYSTEM,
    SYS_BSD_CDEV_DYNAMIC_COUNT
};

#define SYS_BSD_CDEV_DYNAMIC_BASE UINT32_C(0x00100000)
#define SYS_BSD_CDEV_DYNAMIC_NODE(kind) \
    (SYS_BSD_CDEV_DYNAMIC_BASE + (uint32_t)(kind))
#endif

typedef struct {
    uint32_t parent;
    uint32_t node;
    uint16_t mode;
    const char *name;
} sys_entry_t;

static const sys_entry_t g_entries[] = {
    { SYS_ROOT, SYS_FS, VFS_INODE_DIR | 0555, "fs" },
    { SYS_FS, SYS_CGROUP, VFS_INODE_DIR | 0555, "cgroup" },
    { SYS_ROOT, SYS_CLASS, VFS_INODE_DIR | 0555, "class" },
    { SYS_ROOT, SYS_BLOCK, VFS_INODE_DIR | 0555, "block" },
    { SYS_CLASS, SYS_GRAPHICS, VFS_INODE_DIR | 0555, "graphics" },
    { SYS_CLASS, SYS_DRM_CLASS, VFS_INODE_DIR | 0555, "drm" },
    { SYS_CLASS, SYS_INPUT_CLASS, VFS_INODE_DIR | 0555, "input" },
    { SYS_CLASS, SYS_TTY_CLASS, VFS_INODE_DIR | 0555, "tty" },
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    { SYS_CLASS, SYS_VIDEO4LINUX_CLASS, VFS_INODE_DIR | 0555, "video4linux" },
    { SYS_CLASS, SYS_BSD_CDEV_CLASS, VFS_INODE_DIR | 0555, "bsd-cdev" },
#endif
    { SYS_CLASS, SYS_NET_CLASS, VFS_INODE_DIR | 0555, "net" },
    { SYS_NET_CLASS, SYS_NET_CLASS_LO, VFS_INODE_LNK | 0777, "lo" },
    { SYS_NET_CLASS, SYS_NET_CLASS_ETH0, VFS_INODE_LNK | 0777, "eth0" },
    { SYS_GRAPHICS, SYS_FB0, VFS_INODE_LNK | 0777, "fb0" },
    { SYS_DRM_CLASS, SYS_DRM_CLASS_CARD0, VFS_INODE_LNK | 0777, "card0" },
    { SYS_DRM_CLASS, SYS_DRM_CLASS_RENDERD128, VFS_INODE_LNK | 0777, "renderD128" },
    { SYS_ROOT, SYS_BUS, VFS_INODE_DIR | 0555, "bus" },
#ifdef CONFIG_PCI
    { SYS_BUS, SYS_PCI_BUS, VFS_INODE_DIR | 0555, "pci" },
    { SYS_PCI_BUS, SYS_PCI_DEVICES, VFS_INODE_DIR | 0555, "devices" },
#endif
    { SYS_BUS, SYS_PLATFORM, VFS_INODE_DIR | 0555, "platform" },
    { SYS_PLATFORM, SYS_PLATFORM_DEVICES, VFS_INODE_DIR | 0555, "devices" },
    { SYS_PLATFORM_DEVICES, SYS_PLATFORM_DEVICE, VFS_INODE_LNK | 0777, "uefi-framebuffer.0" },
    { SYS_ROOT, SYS_DEVICES, VFS_INODE_DIR | 0555, "devices" },
    { SYS_DEVICES, SYS_DEVICES_SYSTEM, VFS_INODE_DIR | 0555, "system" },
    { SYS_DEVICES_SYSTEM, SYS_CPU_ROOT, VFS_INODE_DIR | 0555, "cpu" },
    { SYS_CPU_ROOT, SYS_CPU_POSSIBLE, VFS_INODE_FILE | 0444, "possible" },
    { SYS_CPU_ROOT, SYS_CPU_PRESENT, VFS_INODE_FILE | 0444, "present" },
    { SYS_CPU_ROOT, SYS_CPU_ONLINE, VFS_INODE_FILE | 0444, "online" },
    { SYS_CPU_ROOT, SYS_CPU_OFFLINE, VFS_INODE_FILE | 0444, "offline" },
    { SYS_CPU_ROOT, SYS_CPU_KERNEL_MAX, VFS_INODE_FILE | 0444, "kernel_max" },
    { SYS_ROOT, SYS_DEV, VFS_INODE_DIR | 0555, "dev" },
    { SYS_DEV, SYS_DEV_BLOCK, VFS_INODE_DIR | 0555, "block" },
    { SYS_DEV, SYS_DEV_CHAR, VFS_INODE_DIR | 0555, "char" },
    { SYS_DEVICES, SYS_DEVICES_VIRTUAL, VFS_INODE_DIR | 0555, "virtual" },
    { SYS_DEVICES_VIRTUAL, SYS_DEVICES_VIRTUAL_TTY, VFS_INODE_DIR | 0555, "tty" },
    { SYS_DEVICES_VIRTUAL, SYS_DEVICES_VIRTUAL_INPUT, VFS_INODE_DIR | 0555, "input" },
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    { SYS_DEVICES_VIRTUAL, SYS_DEVICES_VIRTUAL_VIDEO4LINUX, VFS_INODE_DIR | 0555, "video4linux" },
    { SYS_DEVICES_VIRTUAL, SYS_DEVICES_VIRTUAL_BSD_CDEV, VFS_INODE_DIR | 0555, "bsd-cdev" },
#endif
    { SYS_DEVICES_VIRTUAL, SYS_DEVICES_VIRTUAL_NET, VFS_INODE_DIR | 0555, "net" },
    { SYS_DEVICES_VIRTUAL, SYS_DEVICES_VIRTUAL_DRM, VFS_INODE_DIR | 0555, "drm" },
    { SYS_DRM_VIRTUAL_DEVICE_DRM, SYS_DRM_CARD0, VFS_INODE_DIR | 0555, "card0" },
    { SYS_DRM_CARD0, SYS_DRM_CARD0_DEV, VFS_INODE_FILE | 0444, "dev" },
    { SYS_DRM_CARD0, SYS_DRM_CARD0_UEVENT, VFS_INODE_FILE | 0644, "uevent" },
    { SYS_DRM_CARD0, SYS_DRM_CARD0_SUBSYSTEM, VFS_INODE_LNK | 0777, "subsystem" },
    { SYS_DRM_CARD0, SYS_DRM_CARD0_STATUS, VFS_INODE_FILE | 0444, "status" },
    { SYS_DRM_CARD0, SYS_DRM_CARD0_ENABLED, VFS_INODE_FILE | 0444, "enabled" },
    { SYS_DRM_CARD0, SYS_DRM_CARD0_MODES, VFS_INODE_FILE | 0444, "modes" },
    { SYS_DRM_CARD0, SYS_DRM_CARD0_DEVICE, VFS_INODE_LNK | 0777, "device" },
    { SYS_DRM_VIRTUAL_DEVICE_DRM, SYS_DRM_RENDERD128, VFS_INODE_DIR | 0555, "renderD128" },
    { SYS_DRM_RENDERD128, SYS_DRM_RENDERD128_DEV, VFS_INODE_FILE | 0444, "dev" },
    { SYS_DRM_RENDERD128, SYS_DRM_RENDERD128_UEVENT, VFS_INODE_FILE | 0644, "uevent" },
    { SYS_DRM_RENDERD128, SYS_DRM_RENDERD128_SUBSYSTEM, VFS_INODE_LNK | 0777, "subsystem" },
    { SYS_DRM_RENDERD128, SYS_DRM_RENDERD128_DEVICE, VFS_INODE_LNK | 0777, "device" },
    { SYS_DEVICES_VIRTUAL_DRM, SYS_DRM_VIRTUAL_DEVICE, VFS_INODE_DIR | 0555, "device0" },
    { SYS_DRM_VIRTUAL_DEVICE, SYS_DRM_VIRTUAL_DEVICE_SUBSYSTEM, VFS_INODE_LNK | 0777, "subsystem" },
    { SYS_DRM_VIRTUAL_DEVICE, SYS_DRM_VIRTUAL_DEVICE_UEVENT, VFS_INODE_FILE | 0644, "uevent" },
    { SYS_DRM_VIRTUAL_DEVICE, SYS_DRM_VIRTUAL_DEVICE_DRM, VFS_INODE_DIR | 0555, "drm" },
    { SYS_DRM_VIRTUAL_DEVICE, SYS_DEVICE_GRAPHICS, VFS_INODE_DIR | 0555, "graphics" },
    { SYS_DEVICES_VIRTUAL_NET, SYS_NET_NODE(0, NET_NODE_ROOT), VFS_INODE_DIR | 0555, "lo" },
    { SYS_DEVICES_VIRTUAL_NET, SYS_NET_NODE(1, NET_NODE_ROOT), VFS_INODE_DIR | 0555, "eth0" },
    { SYS_DEVICES, SYS_DEVICES_PLATFORM, VFS_INODE_DIR | 0555, "platform" },
    { SYS_DEVICES_PLATFORM, SYS_DEVICE, VFS_INODE_DIR | 0555, "uefi-framebuffer.0" },
    { SYS_DEVICE, SYS_DEVICE_SUBSYSTEM, VFS_INODE_LNK | 0777, "subsystem" },
    { SYS_DEVICE, SYS_DEVICE_GRAPHICS, VFS_INODE_DIR | 0555, "graphics" },
    { SYS_DEVICE_GRAPHICS, SYS_DEVICE_FB0, VFS_INODE_DIR | 0555, "fb0" },
    { SYS_DEVICE_FB0, SYS_FB_DEVICE, VFS_INODE_LNK | 0777, "device" },
    { SYS_DEVICE_FB0, SYS_FB_SUBSYSTEM, VFS_INODE_LNK | 0777, "subsystem" },
    { SYS_DEVICE_FB0, SYS_FB_NAME, VFS_INODE_FILE | 0444, "name" },
    { SYS_DEVICE_FB0, SYS_FB_SIZE, VFS_INODE_FILE | 0444, "virtual_size" },
    { SYS_DEVICE_FB0, SYS_FB_STRIDE, VFS_INODE_FILE | 0444, "stride" },
    { SYS_DEVICE_FB0, SYS_FB_BPP, VFS_INODE_FILE | 0444, "bits_per_pixel" },
    { SYS_DEVICE_FB0, SYS_FB_DEV, VFS_INODE_FILE | 0444, "dev" },
    { SYS_DEVICE_FB0, SYS_FB_UEVENT, VFS_INODE_FILE | 0644, "uevent" },

};

static vfs_superblock_t g_sys_sb;

static uint32_t sys_input_device_count(void);

static int text_equal(const char *left, const char *right) {
    while (*left && *left == *right) { ++left; ++right; }
    return *left == 0 && *right == 0;
}

static int sys_indexed_name(const char *name, const char *prefix,
                            uint32_t maximum, uint32_t *value_out) {
    uint32_t value = 0;

    if (!name || !prefix || !maximum) return -1;
    while (*prefix) {
        if (*name++ != *prefix++) return -1;
    }
    if (*name < '0' || *name > '9') return -1;
    while (*name) {
        uint32_t digit;

        if (*name < '0' || *name > '9') return -1;
        digit = (uint32_t)(*name++ - '0');
        if (digit >= maximum ||
            value > (maximum - 1u - digit) / 10u)
            return -1;
        value = value * 10u + digit;
        if (value >= maximum) return -1;
    }
    if (value_out) *value_out = value;
    return 0;
}

static int sys_input_class_node(uint32_t node, uint32_t *device,
                                int *event) {
    uint32_t relative;

    if (node < SYS_INPUT_CLASS_BASE ||
        node >= SYS_INPUT_CLASS_BASE + EDGE_INPUT_DEVICE_MAX * 2u)
        return 0;
    relative = node - SYS_INPUT_CLASS_BASE;
    if (device) *device = relative / 2u;
    if (event) *event = (relative & 1u) != 0;
    return 1;
}

static int sys_tty_node(uint32_t node, uint32_t *device,
                        uint32_t *attribute) {
    uint32_t relative;
    if (node < SYS_TTY_DEVICE_BASE || node >= SYS_TTY_DEV_CHAR_BASE)
        return 0;
    relative = node - SYS_TTY_DEVICE_BASE;
    if (relative / TTY_NODE_COUNT >= kernel_console_device_count()) return 0;
    if (device) *device = relative / TTY_NODE_COUNT;
    if (attribute) *attribute = relative % TTY_NODE_COUNT;
    return 1;
}

static int sys_tty_dev_char_node(uint32_t node, uint32_t *device) {
    if (node < SYS_TTY_DEV_CHAR_BASE ||
        node >= SYS_TTY_DEV_CHAR_BASE + kernel_console_device_count())
        return 0;
    if (device) *device = node - SYS_TTY_DEV_CHAR_BASE;
    return 1;
}

static int sys_input_dev_char_node(uint32_t node, uint32_t *device) {
    if (node < SYS_INPUT_DEV_CHAR_BASE ||
        node >= SYS_INPUT_DEV_CHAR_BASE + EDGE_INPUT_DEVICE_MAX)
        return 0;
    if (device) *device = node - SYS_INPUT_DEV_CHAR_BASE;
    return 1;
}

static uint64_t sys_cpu_online_mask(void) {
    uint64_t mask = kernel_scheduler_online_cpu_mask();
    return mask ? mask : 1u;
}

static int sys_cpu_node(uint32_t node, uint32_t *cpu,
                        uint32_t *attribute) {
    uint32_t relative;

    if (node < SYS_CPU_NODE_BASE ||
        node >= SYS_CPU_NODE_BASE + SYS_CPU_MAX * CPU_NODE_COUNT)
        return 0;
    relative = node - SYS_CPU_NODE_BASE;
    if (cpu) *cpu = relative / CPU_NODE_COUNT;
    if (attribute) *attribute = relative % CPU_NODE_COUNT;
    return 1;
}

static int sys_net_node(uint32_t node, uint32_t *device,
                        uint32_t *attribute) {
    uint32_t relative;
    uint32_t ifindex;

    if (node >= SYS_NET_NODE_BASE &&
        node < SYS_NET_NODE_BASE + 2u * NET_NODE_COUNT) {
        relative = node - SYS_NET_NODE_BASE;
        if (device) *device = relative / NET_NODE_COUNT;
        if (attribute) *attribute = relative % NET_NODE_COUNT;
        return 1;
    }
    if (node < SYS_NET_DYNAMIC_NODE_BASE ||
        node >= SYS_NET_DYNAMIC_NODE_BASE +
            SYS_NET_DYNAMIC_IFINDEX_MAX * NET_NODE_COUNT)
        return 0;
    relative = node - SYS_NET_DYNAMIC_NODE_BASE;
    ifindex = relative / NET_NODE_COUNT;
    if (ifindex <= 2u) return 0;
    if (device) *device = ifindex - 1u;
    if (attribute) *attribute = relative % NET_NODE_COUNT;
    return 1;
}

static uint32_t sys_net_device_node(
    uint32_t device, uint32_t attribute) {
    return device < 2u ? SYS_NET_NODE(device, attribute) :
        SYS_NET_DYNAMIC_NODE(device + 1u, attribute);
}

#ifdef CONFIG_PCI
static int sys_pci_node(uint32_t node, uint32_t *device,
                        uint32_t *attribute) {
    uint32_t relative;

    if (node < SYS_PCI_NODE_BASE ||
        node >= SYS_PCI_NODE_BASE + SYS_PCI_MAX_DEVICES * PCI_NODE_COUNT)
        return 0;
    relative = node - SYS_PCI_NODE_BASE;
    if (device) *device = relative / PCI_NODE_COUNT;
    if (attribute) *attribute = relative % PCI_NODE_COUNT;
    return 1;
}

static int sys_pci_device_find_name(const char *name,
                                    uint32_t *device_out) {
    char candidate[24];

    for (uint32_t device = 0; device < SYS_PCI_MAX_DEVICES; ++device) {
        if (pci_device_name_by_index(device, candidate,
                                     sizeof(candidate)) < 0)
            break;
        if (!text_equal(candidate, name)) continue;
        if (device_out) *device_out = device;
        return 0;
    }
    return -1;
}

static int sys_pci_build_path(uint32_t device, uint32_t attribute,
                              char *path, uint32_t capacity) {
    static const char prefix[] = "/sys/bus/pci/devices/";
    char name[24];
    uint32_t length = 0;

    if (!path || attribute == PCI_NODE_ROOT ||
        attribute >= PCI_NODE_COUNT ||
        pci_device_name_by_index(device, name, sizeof(name)) < 0)
        return -1;
    while (prefix[length] && length + 1u < capacity) {
        path[length] = prefix[length];
        ++length;
    }
    for (uint32_t index = 0; name[index] && length + 1u < capacity;
         ++index)
        path[length++] = name[index];
    if (length + 1u >= capacity) return -1;
    path[length++] = '/';
    for (const char *text = g_pci_attribute_names[attribute - 1u];
         *text && length + 1u < capacity; ++text)
        path[length++] = *text;
    if (length >= capacity) return -1;
    path[length] = 0;
    return 0;
}
#endif

static uint32_t sys_net_current_namespace(void) {
    edge_namespace_set_t *namespaces = kernel_arch_current_namespace_set();

    return namespaces ? namespaces->net : 0u;
}

static int sys_net_device_snapshot(
    uint32_t device, edge_net_device_snapshot_t *snapshot) {
    uint32_t network_namespace = sys_net_current_namespace();

    if (!snapshot || device < 2u) return -1;
    if (edge_net_device_snapshot((int32_t)(device + 1u), snapshot) !=
            EDGE_NET_OK ||
        snapshot->configuration.network_namespace != network_namespace)
        return -1;
    return 0;
}

static int sys_net_device_available(uint32_t device) {
    edge_net_device_snapshot_t snapshot;

    if (device == 0u) return 1;
    if (device == 1u)
        return sys_net_current_namespace() == 0u && lwip_stack_is_ready();
    return sys_net_device_snapshot(device, &snapshot) == 0;
}

static int sys_net_device_name(
    uint32_t device, char *name, uint32_t capacity) {
    edge_net_device_snapshot_t snapshot;
    const char *source;
    uint32_t length;

    if (!name || !capacity) return -1;
    if (device == 0u)
        source = "lo";
    else if (device == 1u && sys_net_current_namespace() == 0u)
        source = "eth0";
    else {
        if (sys_net_device_snapshot(device, &snapshot) < 0) return -1;
        source = snapshot.configuration.name;
    }
    length = (uint32_t)strlen(source);
    if (length >= capacity) return -1;
    memcpy(name, source, length + 1u);
    return 0;
}

static int sys_drm_render_available(void) {
    return edge_virtgpu_available();
}

static int sys_drm_pci_device_name(char *out, uint32_t capacity) {
#if defined(CONFIG_PCI) && defined(CONFIG_VIRTIO_GPU)
    return virtio_gpu_pci_device_name(out, capacity);
#else
    (void)out;
    (void)capacity;
    return -1;
#endif
}

#ifdef CONFIG_PCI
static int sys_drm_pci_device_matches(uint32_t device) {
    char candidate[16];
    char gpu[16];

    return sys_drm_pci_device_name(gpu, sizeof(gpu)) == 0 &&
        pci_device_name_by_index(device, candidate, sizeof(candidate)) == 0 &&
        text_equal(candidate, gpu);
}
#endif

static int sys_cpu_parse_name(const char *name, uint32_t *cpu_out) {
    uint32_t cpu = 0;
    uint32_t index = 3u;

    if (!name || name[0] != 'c' || name[1] != 'p' || name[2] != 'u' ||
        name[index] < '0' || name[index] > '9')
        return -1;
    while (name[index]) {
        if (name[index] < '0' || name[index] > '9' || cpu >= SYS_CPU_MAX)
            return -1;
        cpu = cpu * 10u + (uint32_t)(name[index] - '0');
        ++index;
    }
    if (cpu >= SYS_CPU_MAX || !(sys_cpu_online_mask() & (1ULL << cpu)))
        return -1;
    if (cpu_out) *cpu_out = cpu;
    return 0;
}

static int sys_dev_char_special_lookup(const char *name, uint32_t *node) {
    if (text_equal(name, "29:0") && fb.addr && fb.width && fb.height) {
        if (node) *node = SYS_FB_DEV_CHAR;
        return 0;
    }
    if (text_equal(name, "226:0") && fb.addr && fb.width && fb.height) {
        if (node) *node = SYS_DRM_CARD0_DEV_CHAR;
        return 0;
    }
    if (text_equal(name, "226:128") && sys_drm_render_available()) {
        if (node) *node = SYS_DRM_RENDERD128_DEV_CHAR;
        return 0;
    }
    if (name[0] == '1' && name[1] == '3' && name[2] == ':') {
        uint32_t minor = 0;
        uint32_t index = 3u;

        if (name[index] < '0' || name[index] > '9') return -1;
        while (name[index]) {
            uint32_t digit;

            if (name[index] < '0' || name[index] > '9') return -1;
            digit = (uint32_t)(name[index] - '0');
            if (minor > (UINT32_MAX - digit) / 10u) return -1;
            minor = minor * 10u + digit;
            ++index;
        }
        if (minor >= 64u &&
            minor < 64u + EDGE_INPUT_DEVICE_MAX) {
            uint32_t device = minor - 64u;
            if (!input_device_present(device)) return -1;
            if (node) *node = SYS_INPUT_DEV_CHAR_BASE + device;
            return 0;
        }
    }
    return -1;
}

static int sys_console_device_find_name(const char *name,
                                        uint32_t *ordinal_out) {
    kernel_console_device_t device;
    uint32_t count = kernel_console_device_count();
    for (uint32_t ordinal = 0; ordinal < count; ++ordinal) {
        if (kernel_console_device_at(ordinal, &device) == 0 &&
            text_equal(name, device.name)) {
            if (ordinal_out) *ordinal_out = ordinal;
            return 0;
        }
    }
    return -1;
}

static int sys_console_device_find_number(const char *name,
                                          uint32_t *ordinal_out) {
    kernel_console_device_t device;
    char number[24];
    uint32_t count = kernel_console_device_count();
    for (uint32_t ordinal = 0; ordinal < count; ++ordinal) {
        uint32_t length = 0;
        char reverse[10];
        uint32_t digits = 0;
        uint32_t value;
        if (kernel_console_device_at(ordinal, &device) < 0) continue;
        value = device.major;
        do {
            reverse[digits++] = (char)('0' + value % 10u);
            value /= 10u;
        } while (value && digits < sizeof(reverse));
        while (digits) number[length++] = reverse[--digits];
        number[length++] = ':';
        value = device.minor;
        digits = 0;
        do {
            reverse[digits++] = (char)('0' + value % 10u);
            value /= 10u;
        } while (value && digits < sizeof(reverse));
        while (digits) number[length++] = reverse[--digits];
        number[length] = 0;
        if (text_equal(name, number)) {
            if (ordinal_out) *ordinal_out = ordinal;
            return 0;
        }
    }
    return -1;
}

static int sys_console_device_is_vt_master(uint32_t ordinal) {
    kernel_console_device_t device;
    return kernel_console_device_at(ordinal, &device) == 0 &&
           device.major == 4u && device.minor == 0u &&
           text_equal(device.name, "tty0");
}

static int sys_console_device_has_active(uint32_t ordinal) {
    kernel_console_device_t device;

    if (kernel_console_device_at(ordinal, &device) < 0) return 0;
    return sys_console_device_is_vt_master(ordinal) ||
           text_equal(device.name, "console");
}

static uint32_t sys_input_device_count(void) {
    uint32_t count = 0;
    for (uint32_t device = 0; device < EDGE_INPUT_DEVICE_MAX; ++device)
        if (input_device_present(device)) ++count;
    return count;
}

static int sys_input_device_at_ordinal(uint32_t ordinal,
                                       uint32_t *device_out) {
    for (uint32_t device = 0; device < EDGE_INPUT_DEVICE_MAX; ++device) {
        if (!input_device_present(device)) continue;
        if (ordinal-- == 0u) {
            if (device_out) *device_out = device;
            return 0;
        }
    }
    return -1;
}

static int sys_input_node(uint32_t node, uint32_t *device,
                          uint32_t *attribute) {
    uint32_t relative;
    if (node < SYS_INPUT0_BASE ||
        node >= SYS_INPUT0_BASE +
                    EDGE_INPUT_DEVICE_MAX * INPUT_NODE_COUNT) return 0;
    relative = node - SYS_INPUT0_BASE;
    if (device) *device = relative / INPUT_NODE_COUNT;
    if (attribute) *attribute = relative % INPUT_NODE_COUNT;
    return 1;
}

#ifdef CONFIG_BSD_DRIVER_BRIDGE
static int
sys_bsd_cdev_is_video(const bsd_bridge_cdev_node_t *node)
{
    uint32_t index = 5u;

    if (!node || node->alias ||
        node->name[0] != 'v' || node->name[1] != 'i' ||
        node->name[2] != 'd' || node->name[3] != 'e' ||
        node->name[4] != 'o' ||
        node->name[index] < '0' || node->name[index] > '9')
        return 0;
    while (node->name[index]) {
        if (node->name[index] < '0' || node->name[index] > '9')
            return 0;
        ++index;
    }
    return 1;
}

static const char *
sys_bsd_cdev_class_name(const bsd_bridge_cdev_node_t *node)
{
    return sys_bsd_cdev_is_video(node) ? "video4linux" : "bsd-cdev";
}

static int
sys_bsd_cdev_find_identity(uint32_t major, uint32_t minor,
    bsd_bridge_cdev_node_t *node_out)
{
    uint32_t count = bsd_bridge_cdev_node_count();

    for (uint32_t ordinal = 0; ordinal < count; ++ordinal) {
        bsd_bridge_cdev_node_t node;

        if (bsd_bridge_cdev_node_at(ordinal, &node) == 0 &&
            node.major == major && node.minor == minor) {
            if (node_out)
                *node_out = node;
            return 0;
        }
    }
    return -1;
}

static int
sys_bsd_cdev_find_name(const char *name, int video,
    bsd_bridge_cdev_node_t *node_out)
{
    uint32_t count = bsd_bridge_cdev_node_count();

    for (uint32_t ordinal = 0; ordinal < count; ++ordinal) {
        bsd_bridge_cdev_node_t node;

        if (bsd_bridge_cdev_node_at(ordinal, &node) != 0 ||
            node.alias || sys_bsd_cdev_is_video(&node) != video ||
            !text_equal(node.name, name))
            continue;
        if (node_out)
            *node_out = node;
        return 0;
    }
    return -1;
}

static int
sys_bsd_cdev_parse_number(const char *name,
    uint32_t *major_out, uint32_t *minor_out)
{
    uint64_t major = 0;
    uint64_t minor = 0;
    uint32_t index = 0;

    if (!name || name[0] < '0' || name[0] > '9')
        return -1;
    while (name[index] >= '0' && name[index] <= '9') {
        major = major * 10u + (uint32_t)(name[index] - '0');
        if (major > UINT32_MAX)
            return -1;
        ++index;
    }
    if (name[index++] != ':' ||
        name[index] < '0' || name[index] > '9')
        return -1;
    while (name[index] >= '0' && name[index] <= '9') {
        minor = minor * 10u + (uint32_t)(name[index] - '0');
        if (minor > UINT32_MAX)
            return -1;
        ++index;
    }
    if (name[index])
        return -1;
    if (major_out)
        *major_out = (uint32_t)major;
    if (minor_out)
        *minor_out = (uint32_t)minor;
    return 0;
}

static int
sys_bsd_cdev_find_number(const char *name,
    bsd_bridge_cdev_node_t *node_out)
{
    uint32_t major;
    uint32_t minor;

    if (sys_bsd_cdev_parse_number(name, &major, &minor) != 0)
        return -1;
    return sys_bsd_cdev_find_identity(major, minor, node_out);
}

static int
sys_bsd_cdev_identity_is_primary(uint32_t ordinal,
    const bsd_bridge_cdev_node_t *node)
{
    for (uint32_t previous = 0; previous < ordinal; ++previous) {
        bsd_bridge_cdev_node_t candidate;

        if (bsd_bridge_cdev_node_at(previous, &candidate) == 0 &&
            candidate.major == node->major &&
            candidate.minor == node->minor)
            return 0;
    }
    return 1;
}

static int
sys_bsd_cdev_at_unique_ordinal(uint32_t requested,
    bsd_bridge_cdev_node_t *node_out)
{
    uint32_t count = bsd_bridge_cdev_node_count();

    for (uint32_t ordinal = 0; ordinal < count; ++ordinal) {
        bsd_bridge_cdev_node_t node;

        if (bsd_bridge_cdev_node_at(ordinal, &node) != 0 ||
            !sys_bsd_cdev_identity_is_primary(ordinal, &node))
            continue;
        if (requested-- != 0)
            continue;
        if (node_out)
            *node_out = node;
        return 0;
    }
    return -1;
}

static int
sys_bsd_cdev_at_class_ordinal(int video, uint32_t requested,
    bsd_bridge_cdev_node_t *node_out)
{
    uint32_t count = bsd_bridge_cdev_node_count();

    for (uint32_t ordinal = 0; ordinal < count; ++ordinal) {
        bsd_bridge_cdev_node_t node;

        if (bsd_bridge_cdev_node_at(ordinal, &node) != 0 ||
            node.alias || sys_bsd_cdev_is_video(&node) != video)
            continue;
        if (requested-- != 0)
            continue;
        if (node_out)
            *node_out = node;
        return 0;
    }
    return -1;
}
#endif

static int sys_node_available(uint32_t node) {
    uint32_t device;
    uint32_t cpu;
    int input_event;
    if (sys_tty_node(node, &device, 0) ||
        sys_tty_dev_char_node(node, &device))
        return device < kernel_console_device_count();
    if (node == SYS_FB_DEV_CHAR)
        return fb.addr && fb.width && fb.height;
    if (node == SYS_DRM_CLASS_RENDERD128 ||
        (node >= SYS_DRM_RENDERD128 &&
         node <= SYS_DRM_RENDERD128_DEVICE) ||
        node == SYS_DRM_RENDERD128_DEV_CHAR)
        return sys_drm_render_available();
    if (node == SYS_DRM_CARD0_DEVICE) {
        char name[16];
        return sys_drm_pci_device_name(name, sizeof(name)) == 0 ||
            (fb.addr && fb.width && fb.height);
    }
    if (node == SYS_DRM_VIRTUAL_DEVICE ||
        node == SYS_DRM_VIRTUAL_DEVICE_SUBSYSTEM ||
        node == SYS_DRM_VIRTUAL_DEVICE_UEVENT ||
        node == SYS_DRM_VIRTUAL_DEVICE_DRM ||
        node == SYS_DRM_VIRTUAL_DEVICE_CARD0)
        return fb.addr && fb.width && fb.height;
    if (node == SYS_DRM_VIRTUAL_DEVICE_RENDERD128)
        return sys_drm_render_available();
    if (node == SYS_DRM_CLASS_CARD0 ||
        (node >= SYS_DRM_CARD0 && node <= SYS_DRM_CARD0_MODES) ||
        node == SYS_DEVICES_VIRTUAL_DRM ||
        node == SYS_DRM_CARD0_DEV_CHAR)
        return fb.addr && fb.width && fb.height;
    if (sys_input_dev_char_node(node, &device))
        return input_device_present(device);
    if (sys_input_class_node(node, &device, &input_event)) {
        (void)input_event;
        return input_device_present(device);
    }
    if (node == SYS_NET_CLASS_ETH0)
        return sys_net_device_available(1u);
    if (sys_net_node(node, &device, 0))
        return sys_net_device_available(device);
    if (sys_input_node(node, &device, 0))
        return input_device_present(device);
    if (sys_cpu_node(node, &cpu, 0))
        return (sys_cpu_online_mask() & (1ULL << cpu)) != 0;
    return 1;
}

static void inode_set(vfs_inode_t *inode, uint32_t node, uint16_t mode) {
    memset(inode, 0, sizeof(*inode));
    inode->ino = 0xf2000000u | node;
    inode->mode = mode;
    inode->fs_private[0] = node;
}

#ifdef CONFIG_BSD_DRIVER_BRIDGE
static void
inode_set_bsd_cdev(vfs_inode_t *inode,
    const bsd_bridge_cdev_node_t *node, uint32_t kind, uint16_t mode)
{
    inode_set(inode, SYS_BSD_CDEV_DYNAMIC_NODE(kind), mode);
    inode->ino = UINT32_C(0xf3000000) ^
        (node->major << 12) ^ (node->minor << 4) ^ kind;
    inode->fs_private[1] = node->major;
    inode->fs_private[2] = node->minor;
}

static int
sys_bsd_cdev_inode(const vfs_inode_t *inode, uint32_t *kind,
    bsd_bridge_cdev_node_t *node)
{
    uint32_t value;

    if (!inode ||
        inode->fs_private[0] < SYS_BSD_CDEV_DYNAMIC_BASE ||
        inode->fs_private[0] >=
            SYS_BSD_CDEV_DYNAMIC_BASE + SYS_BSD_CDEV_DYNAMIC_COUNT)
        return 0;
    value = inode->fs_private[0] - SYS_BSD_CDEV_DYNAMIC_BASE;
    if (sys_bsd_cdev_find_identity(
        inode->fs_private[1], inode->fs_private[2], node) != 0)
        return 0;
    if (kind)
        *kind = value;
    return 1;
}
#endif

static int sys_lookup(vfs_superblock_t *sb, vfs_inode_t *directory,
                      const char *name, vfs_inode_t *out) {
    uint32_t device;
    uint32_t attribute;
    (void)sb;
    if (!directory || !name || !out) return -1;
#ifdef CONFIG_LOOP_DEVICE
    if (directory->fs_private[0] == SYS_DEV_BLOCK) {
        char loop_name[8];

        if (sys_indexed_name(name, "7:", EDGE_LOOP_DEVICE_COUNT,
                             &device) != 0)
            return -1;
        sys_loop_device_name(loop_name, sizeof(loop_name), device);
        if (edge_loop_sysfs_path_kind(loop_name, "") !=
            BLOCK_SYSFS_PATH_DIR)
            return -1;
        inode_set(out, SYS_LOOP_NODE(device, LOOP_NODE_DEV_LINK),
                  VFS_INODE_LNK | 0777);
        return 0;
    }
    if (directory->fs_private[0] == SYS_BLOCK) {
        char loop_name[8];

        for (device = 0; device < EDGE_LOOP_DEVICE_COUNT; ++device) {
            sys_loop_device_name(loop_name, sizeof(loop_name), device);
            if (!text_equal(name, loop_name) ||
                edge_loop_sysfs_path_kind(loop_name, "") !=
                    BLOCK_SYSFS_PATH_DIR)
                continue;
            inode_set(out, SYS_LOOP_NODE(device, LOOP_NODE_ROOT),
                      VFS_INODE_DIR | 0555);
            return 0;
        }
        return -1;
    }
    if (sys_loop_node(directory->fs_private[0], &device, &attribute)) {
        static const char *const names[] = {
            "loop", "backing_file", "offset", "sizelimit", "autoclear",
            "partscan", "dio"
        };

        if (attribute == LOOP_NODE_ROOT) {
            if (text_equal(name, names[0])) {
                inode_set(out, SYS_LOOP_NODE(device, LOOP_NODE_DIRECTORY),
                          VFS_INODE_DIR | 0555);
                return 0;
            }
            for (uint32_t index = 0;
                 index < sizeof(g_loop_root_attribute_names) /
                             sizeof(g_loop_root_attribute_names[0]);
                 ++index) {
                if (!text_equal(name, g_loop_root_attribute_names[index]))
                    continue;
                inode_set(out, SYS_LOOP_NODE(
                              device, LOOP_NODE_DEV + index),
                          VFS_INODE_FILE | 0444);
                return 0;
            }
            return -1;
        }
        if (attribute == LOOP_NODE_DIRECTORY) {
            for (uint32_t index = 1;
                 index < sizeof(names) / sizeof(names[0]); ++index) {
                if (!text_equal(name, names[index])) continue;
                inode_set(out, SYS_LOOP_NODE(
                              device,
                              LOOP_NODE_BACKING_FILE + index - 1u),
                          VFS_INODE_FILE | 0444);
                return 0;
            }
        }
        return -1;
    }
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    {
        bsd_bridge_cdev_node_t bsd_node;
        uint32_t bsd_kind;
        int video;

        if (directory->fs_private[0] == SYS_VIDEO4LINUX_CLASS ||
            directory->fs_private[0] == SYS_BSD_CDEV_CLASS) {
            video = directory->fs_private[0] ==
                SYS_VIDEO4LINUX_CLASS;
            if (sys_bsd_cdev_find_name(name, video, &bsd_node) != 0)
                return -1;
            inode_set_bsd_cdev(out, &bsd_node,
                SYS_BSD_CDEV_CLASS_LINK, VFS_INODE_LNK | 0777);
            return 0;
        }
        if (directory->fs_private[0] ==
                SYS_DEVICES_VIRTUAL_VIDEO4LINUX ||
            directory->fs_private[0] ==
                SYS_DEVICES_VIRTUAL_BSD_CDEV) {
            video = directory->fs_private[0] ==
                SYS_DEVICES_VIRTUAL_VIDEO4LINUX;
            if (sys_bsd_cdev_find_name(name, video, &bsd_node) != 0)
                return -1;
            inode_set_bsd_cdev(out, &bsd_node,
                SYS_BSD_CDEV_DEVICE_ROOT, VFS_INODE_DIR | 0555);
            return 0;
        }
        if (sys_bsd_cdev_inode(directory, &bsd_kind, &bsd_node) &&
            bsd_kind == SYS_BSD_CDEV_DEVICE_ROOT) {
            if (text_equal(name, "dev"))
                bsd_kind = SYS_BSD_CDEV_DEVICE_DEV;
            else if (text_equal(name, "uevent"))
                bsd_kind = SYS_BSD_CDEV_DEVICE_UEVENT;
            else if (text_equal(name, "subsystem"))
                bsd_kind = SYS_BSD_CDEV_DEVICE_SUBSYSTEM;
            else
                return -1;
            inode_set_bsd_cdev(out, &bsd_node, bsd_kind,
                bsd_kind == SYS_BSD_CDEV_DEVICE_SUBSYSTEM ?
                    VFS_INODE_LNK | 0777 :
                    VFS_INODE_FILE | 0444);
            return 0;
        }
    }
#endif
#ifdef CONFIG_PCI
    if (directory->fs_private[0] == SYS_PCI_DEVICES) {
        if (sys_pci_device_find_name(name, &device) < 0) return -1;
        inode_set(out, SYS_PCI_NODE(device, PCI_NODE_ROOT),
                  VFS_INODE_DIR | 0555);
        return 0;
    }
    if (sys_pci_node(directory->fs_private[0], &device, &attribute) &&
        attribute == PCI_NODE_ROOT) {
        for (uint32_t index = 0;
             index < sizeof(g_pci_attribute_names) /
                         sizeof(g_pci_attribute_names[0]);
             ++index) {
            if (!text_equal(name, g_pci_attribute_names[index])) continue;
            inode_set(out, SYS_PCI_NODE(device, index + 1u),
                      g_pci_attribute_modes[index]);
            return 0;
        }
        if (text_equal(name, "drm") &&
            sys_drm_pci_device_matches(device)) {
            inode_set(out, SYS_DRM_PCI_DIRECTORY,
                      VFS_INODE_DIR | 0555);
            return 0;
        }
        return -1;
    }
    if (directory->fs_private[0] == SYS_DRM_PCI_DIRECTORY) {
        if (text_equal(name, "card0"))
            inode_set(out, SYS_DRM_PCI_CARD0,
                      VFS_INODE_LNK | 0777);
        else if (text_equal(name, "renderD128"))
            inode_set(out, SYS_DRM_PCI_RENDERD128,
                      VFS_INODE_LNK | 0777);
        else
            return -1;
        return 0;
    }
#endif
    if (directory->fs_private[0] == SYS_NET_CLASS ||
        directory->fs_private[0] == SYS_DEVICES_VIRTUAL_NET) {
        int32_t ifindex;
        uint32_t network_namespace = sys_net_current_namespace();

        if (text_equal(name, "lo")) {
            inode_set(out,
                directory->fs_private[0] == SYS_NET_CLASS ?
                    SYS_NET_CLASS_LO :
                    SYS_NET_NODE(0, NET_NODE_ROOT),
                directory->fs_private[0] == SYS_NET_CLASS ?
                    VFS_INODE_LNK | 0777 : VFS_INODE_DIR | 0555);
            return 0;
        }
        if (!network_namespace && text_equal(name, "eth0")) {
            if (!lwip_stack_is_ready()) return -1;
            inode_set(out,
                directory->fs_private[0] == SYS_NET_CLASS ?
                    SYS_NET_CLASS_ETH0 :
                    SYS_NET_NODE(1, NET_NODE_ROOT),
                directory->fs_private[0] == SYS_NET_CLASS ?
                    VFS_INODE_LNK | 0777 : VFS_INODE_DIR | 0555);
            return 0;
        }
        if (edge_net_device_find(network_namespace, name, &ifindex) !=
                EDGE_NET_OK || ifindex <= 2 ||
            (uint32_t)ifindex >= SYS_NET_DYNAMIC_IFINDEX_MAX)
            return -1;
        inode_set(out, SYS_NET_DYNAMIC_NODE(
                      ifindex,
                      directory->fs_private[0] == SYS_NET_CLASS ?
                          NET_NODE_CLASS_LINK : NET_NODE_ROOT),
                  directory->fs_private[0] == SYS_NET_CLASS ?
                      VFS_INODE_LNK | 0777 : VFS_INODE_DIR | 0555);
        return 0;
    }
    if (directory->fs_private[0] == SYS_CPU_ROOT &&
        sys_cpu_parse_name(name, &device) == 0) {
        inode_set(out, SYS_CPU_NODE(device, CPU_NODE_ROOT),
                  VFS_INODE_DIR | 0555);
        return 0;
    }
    if (sys_net_node(directory->fs_private[0], &device, &attribute) &&
        attribute == NET_NODE_ROOT) {
        static const char *const names[] = {
            "ifindex", "iflink", "flags", "mtu", "type", "address",
            "broadcast", "operstate", "carrier", "tx_queue_len",
            "addr_assign_type", "addr_len", "dev_id", "dormant",
            "link_mode", "proto_down", "uevent", "subsystem", "statistics"
        };
        static const uint16_t modes[] = {
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0644, VFS_INODE_LNK | 0777,
            VFS_INODE_DIR | 0555
        };
        for (uint32_t index = 0; index < sizeof(names) / sizeof(names[0]);
             ++index) {
            if (!text_equal(name, names[index])) continue;
            inode_set(out, sys_net_device_node(
                          device, NET_NODE_IFINDEX + index),
                      modes[index]);
            return 0;
        }
        return -1;
    }
    if (sys_net_node(directory->fs_private[0], &device, &attribute) &&
        attribute == NET_NODE_STATISTICS) {
        static const char *const names[] = {
            "rx_packets", "rx_bytes", "tx_packets", "tx_bytes"
        };
        for (uint32_t index = 0; index < sizeof(names) / sizeof(names[0]);
             ++index) {
            if (!text_equal(name, names[index])) continue;
            inode_set(out, sys_net_device_node(
                          device, NET_NODE_RX_PACKETS + index),
                      VFS_INODE_FILE | 0444);
            return 0;
        }
        return -1;
    }
    if (sys_cpu_node(directory->fs_private[0], &device, &attribute) &&
        attribute == CPU_NODE_ROOT) {
        if (device != 0u && text_equal(name, "online"))
            inode_set(out, SYS_CPU_NODE(device, CPU_NODE_ONLINE),
                      VFS_INODE_FILE | 0644);
        else if (text_equal(name, "topology"))
            inode_set(out, SYS_CPU_NODE(device, CPU_NODE_TOPOLOGY),
                      VFS_INODE_DIR | 0555);
        else
            return -1;
        return 0;
    }
    if (sys_cpu_node(directory->fs_private[0], &device, &attribute) &&
        attribute == CPU_NODE_TOPOLOGY) {
        if (text_equal(name, "core_id"))
            attribute = CPU_NODE_CORE_ID;
        else if (text_equal(name, "physical_package_id"))
            attribute = CPU_NODE_PHYSICAL_PACKAGE_ID;
        else if (text_equal(name, "core_siblings_list"))
            attribute = CPU_NODE_CORE_SIBLINGS_LIST;
        else if (text_equal(name, "thread_siblings_list"))
            attribute = CPU_NODE_THREAD_SIBLINGS_LIST;
        else if (text_equal(name, "cluster_cpus_list"))
            attribute = CPU_NODE_CLUSTER_CPUS_LIST;
        else
            return -1;
        inode_set(out, SYS_CPU_NODE(device, attribute),
                  VFS_INODE_FILE | 0444);
        return 0;
    }
    if (directory->fs_private[0] == SYS_INPUT_CLASS) {
        int event = 0;

        if (sys_indexed_name(
                name, "input", EDGE_INPUT_DEVICE_MAX, &device) != 0) {
            if (sys_indexed_name(
                    name, "event", EDGE_INPUT_DEVICE_MAX, &device) != 0)
                return -1;
            event = 1;
        }
        if (!input_device_present(device)) return -1;
        inode_set(out, SYS_INPUT_CLASS_NODE(device, event),
                  VFS_INODE_LNK | 0777);
        return 0;
    }
    if (directory->fs_private[0] == SYS_DEVICES_VIRTUAL_INPUT) {
        if (sys_indexed_name(
                name, "input", EDGE_INPUT_DEVICE_MAX, &device) != 0 ||
            !input_device_present(device))
            return -1;
        inode_set(out, SYS_INPUT_NODE(device, INPUT_NODE_ROOT),
                  VFS_INODE_DIR | 0555);
        return 0;
    }
    if (sys_input_node(
            directory->fs_private[0], &device, &attribute)) {
        uint32_t child = INPUT_NODE_COUNT;
        uint16_t mode = VFS_INODE_FILE | 0444;

        if (attribute == INPUT_NODE_ROOT) {
            if (text_equal(name, "name")) child = INPUT_NODE_NAME;
            else if (text_equal(name, "phys")) child = INPUT_NODE_PHYS;
            else if (text_equal(name, "uniq")) child = INPUT_NODE_UNIQ;
            else if (text_equal(name, "properties"))
                child = INPUT_NODE_PROPERTIES;
            else if (text_equal(name, "uevent")) {
                child = INPUT_NODE_UEVENT;
                mode = VFS_INODE_FILE | 0644;
            } else if (text_equal(name, "subsystem")) {
                child = INPUT_NODE_SUBSYSTEM;
                mode = VFS_INODE_LNK | 0777;
            } else if (text_equal(name, "id")) {
                child = INPUT_NODE_ID;
                mode = VFS_INODE_DIR | 0555;
            } else if (text_equal(name, "capabilities")) {
                child = INPUT_NODE_CAPABILITIES;
                mode = VFS_INODE_DIR | 0555;
            } else {
                uint32_t event_device;

                if (sys_indexed_name(
                        name, "event", EDGE_INPUT_DEVICE_MAX,
                        &event_device) != 0 ||
                    event_device != device)
                    return -1;
                child = INPUT_NODE_EVENT;
                mode = VFS_INODE_DIR | 0555;
            }
        } else if (attribute == INPUT_NODE_ID) {
            if (text_equal(name, "bustype"))
                child = INPUT_NODE_ID_BUSTYPE;
            else if (text_equal(name, "vendor"))
                child = INPUT_NODE_ID_VENDOR;
            else if (text_equal(name, "product"))
                child = INPUT_NODE_ID_PRODUCT;
            else if (text_equal(name, "version"))
                child = INPUT_NODE_ID_VERSION;
            else
                return -1;
        } else if (attribute == INPUT_NODE_CAPABILITIES) {
            if (text_equal(name, "ev")) child = INPUT_NODE_CAP_EV;
            else if (text_equal(name, "key")) child = INPUT_NODE_CAP_KEY;
            else if (text_equal(name, "rel")) child = INPUT_NODE_CAP_REL;
            else if (text_equal(name, "abs")) child = INPUT_NODE_CAP_ABS;
            else return -1;
        } else if (attribute == INPUT_NODE_EVENT) {
            if (text_equal(name, "dev"))
                child = INPUT_NODE_EVENT_DEV;
            else if (text_equal(name, "uevent")) {
                child = INPUT_NODE_EVENT_UEVENT;
                mode = VFS_INODE_FILE | 0644;
            } else if (text_equal(name, "subsystem")) {
                child = INPUT_NODE_EVENT_SUBSYSTEM;
                mode = VFS_INODE_LNK | 0777;
            } else {
                return -1;
            }
        } else {
            return -1;
        }
        inode_set(out, SYS_INPUT_NODE(device, child), mode);
        return 0;
    }
    if (directory->fs_private[0] == SYS_TTY_CLASS) {
        if (sys_console_device_find_name(name, &device) < 0) return -1;
        inode_set(out, SYS_TTY_NODE(device, TTY_NODE_CLASS),
                  VFS_INODE_LNK | 0777);
        return 0;
    }
    if (directory->fs_private[0] == SYS_DEVICES_VIRTUAL_TTY) {
        if (sys_console_device_find_name(name, &device) < 0) return -1;
        inode_set(out, SYS_TTY_NODE(device, TTY_NODE_ROOT),
                  VFS_INODE_DIR | 0555);
        return 0;
    }
    if (directory->fs_private[0] == SYS_DEV_CHAR) {
        uint32_t node;
        if (sys_console_device_find_number(name, &device) == 0)
            node = SYS_TTY_DEV_CHAR_NODE(device);
        else if (sys_dev_char_special_lookup(name, &node) < 0) {
#ifdef CONFIG_BSD_DRIVER_BRIDGE
            bsd_bridge_cdev_node_t bsd_node;

            if (sys_bsd_cdev_find_number(name, &bsd_node) != 0)
                return -1;
            inode_set_bsd_cdev(out, &bsd_node,
                SYS_BSD_CDEV_DEV_CHAR, VFS_INODE_LNK | 0777);
            return 0;
#else
            return -1;
#endif
        }
        inode_set(out, node, VFS_INODE_LNK | 0777);
        return 0;
    }
    if (sys_tty_node(directory->fs_private[0], &device, &attribute) &&
        attribute == TTY_NODE_ROOT) {
        if (text_equal(name, "dev"))
            inode_set(out, SYS_TTY_NODE(device, TTY_NODE_DEV),
                      VFS_INODE_FILE | 0444);
        else if (text_equal(name, "uevent"))
            inode_set(out, SYS_TTY_NODE(device, TTY_NODE_UEVENT),
                      VFS_INODE_FILE | 0644);
        else if (text_equal(name, "subsystem"))
            inode_set(out, SYS_TTY_NODE(device, TTY_NODE_SUBSYSTEM),
                      VFS_INODE_LNK | 0777);
        else if (sys_console_device_has_active(device) &&
                 text_equal(name, "active"))
            inode_set(out, SYS_TTY_NODE(device, TTY_NODE_ACTIVE),
                      VFS_INODE_FILE | 0444);
        else
            return -1;
        return 0;
    }
    for (uint32_t index = 0; index < sizeof(g_entries) / sizeof(g_entries[0]); ++index) {
        const sys_entry_t *entry = &g_entries[index];
        if (entry->parent == directory->fs_private[0] &&
            sys_node_available(entry->node) && text_equal(entry->name, name)) {
            inode_set(out, entry->node, entry->mode);
            return 0;
        }
    }
    return -1;
}

static uint32_t append_text(char *buffer, uint32_t capacity, uint32_t length,
                            const char *text) {
    while (*text && length < capacity) buffer[length++] = *text++;
    return length;
}

static uint32_t append_u32(char *buffer, uint32_t capacity, uint32_t length,
                           uint32_t value) {
    char digits[10];
    uint32_t count = 0;
    if (!value) digits[count++] = '0';
    while (value && count < sizeof(digits)) {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count && length < capacity) buffer[length++] = digits[--count];
    return length;
}

static uint32_t append_u64(char *buffer, uint32_t capacity, uint32_t length,
                           uint64_t value) {
    char digits[20];
    uint32_t count = 0;
    if (!value) digits[count++] = '0';
    while (value && count < sizeof(digits)) {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count && length < capacity) buffer[length++] = digits[--count];
    return length;
}

static uint32_t append_device_number(char *buffer, uint32_t capacity,
                                     uint32_t length,
                                     const kernel_console_device_t *device) {
    length = append_u32(buffer, capacity, length, device->major);
    if (length < capacity) buffer[length++] = ':';
    return append_u32(buffer, capacity, length, device->minor);
}

static uint32_t append_hex(char *buffer, uint32_t capacity, uint32_t length,
                           uint64_t value, uint32_t minimum_digits) {
    static const char digits[] = "0123456789abcdef";
    char scratch[16];
    uint32_t count = 0;
    do {
        scratch[count++] = digits[value & 0xfu];
        value >>= 4;
    } while (value && count < sizeof(scratch));
    while (count < minimum_digits && count < sizeof(scratch))
        scratch[count++] = '0';
    while (count && length < capacity) buffer[length++] = scratch[--count];
    return length;
}

static uint32_t append_mac(char *buffer, uint32_t capacity, uint32_t length,
                           const uint8_t address[6]) {
    for (uint32_t index = 0; index < 6u; ++index) {
        if (index && length < capacity) buffer[length++] = ':';
        length = append_hex(buffer, capacity, length, address[index], 2u);
    }
    return append_text(buffer, capacity, length, "\n");
}

static uint32_t append_cpu_list(char *buffer, uint32_t capacity,
                                uint32_t length, uint64_t mask) {
    uint32_t cpu = 0;
    int first = 1;

    while (cpu < SYS_CPU_MAX) {
        uint32_t start;
        uint32_t end;

        while (cpu < SYS_CPU_MAX && !(mask & (1ULL << cpu))) ++cpu;
        if (cpu == SYS_CPU_MAX) break;
        start = cpu;
        while (cpu + 1u < SYS_CPU_MAX && (mask & (1ULL << (cpu + 1u))))
            ++cpu;
        end = cpu++;
        if (!first) length = append_text(buffer, capacity, length, ",");
        length = append_u32(buffer, capacity, length, start);
        if (end != start) {
            length = append_text(buffer, capacity, length, "-");
            length = append_u32(buffer, capacity, length, end);
        }
        first = 0;
    }
    return append_text(buffer, capacity, length, "\n");
}

static int input_bitmap_text(uint32_t device, uint32_t attribute,
                             char *out, uint32_t capacity) {
    uint8_t bits[128];
    uint32_t length = sizeof(bits);
    uint32_t event_type;
    int32_t highest_word = -1;
    uint32_t offset = 0;
    memset(bits, 0, sizeof(bits));
    if (attribute == INPUT_NODE_PROPERTIES) {
        length = input_properties(device, bits, length);
    } else {
        if (attribute == INPUT_NODE_CAP_EV) event_type = 0u;
        else if (attribute == INPUT_NODE_CAP_KEY) event_type = 1u;
        else if (attribute == INPUT_NODE_CAP_REL) event_type = 2u;
        else if (attribute == INPUT_NODE_CAP_ABS) event_type = 3u;
        else return -1;
        length = input_bits(device, event_type, bits, length);
    }
    for (uint32_t word = 0; word * 8u < length; ++word) {
        uint64_t value = 0;
        for (uint32_t byte = 0; byte < 8u && word * 8u + byte < length; ++byte)
            value |= (uint64_t)bits[word * 8u + byte] << (byte * 8u);
        if (value) highest_word = (int32_t)word;
    }
    if (highest_word < 0) highest_word = 0;
    for (int32_t word = highest_word; word >= 0; --word) {
        uint64_t value = 0;
        for (uint32_t byte = 0; byte < 8u &&
             (uint32_t)word * 8u + byte < length; ++byte)
            value |= (uint64_t)bits[(uint32_t)word * 8u + byte] << (byte * 8u);
        if (word != highest_word && offset < capacity) out[offset++] = ' ';
        offset = append_hex(out, capacity, offset, value, 1u);
    }
    if (offset < capacity) out[offset++] = '\n';
    return (int)offset;
}

static int input_attribute_text(uint32_t device, uint32_t attribute,
                                char *out, uint32_t capacity) {
    uint16_t id[4];
    uint32_t length = 0;
    const char *name;
    const char *physical_path;
    if (!input_device_present(device)) return -1;
    input_id(device, id);
    switch (attribute) {
    case INPUT_NODE_NAME:
        name = input_name(device);
        length = append_text(out, capacity, length,
                             name && name[0] ? name : "EdgeOS input device");
        length = append_text(out, capacity, length, "\n");
        break;
    case INPUT_NODE_PHYS:
        physical_path = input_physical_path(device);
        length = append_text(out, capacity, length,
                             physical_path ? physical_path : "");
        length = append_text(out, capacity, length, "\n");
        break;
    case INPUT_NODE_UNIQ:
        length = append_text(out, capacity, length, "\n");
        break;
    case INPUT_NODE_ID_BUSTYPE:
    case INPUT_NODE_ID_VENDOR:
    case INPUT_NODE_ID_PRODUCT:
    case INPUT_NODE_ID_VERSION: {
        uint32_t index = attribute - INPUT_NODE_ID_BUSTYPE;
        length = append_hex(out, capacity, length, id[index], 4u);
        length = append_text(out, capacity, length, "\n");
        break;
    }
    case INPUT_NODE_UEVENT:
        name = input_name(device);
        length = append_text(out, capacity, length, "PRODUCT=");
        length = append_hex(out, capacity, length, id[0], 1u);
        length = append_text(out, capacity, length, "/");
        length = append_hex(out, capacity, length, id[1], 1u);
        length = append_text(out, capacity, length, "/");
        length = append_hex(out, capacity, length, id[2], 1u);
        length = append_text(out, capacity, length, "/");
        length = append_hex(out, capacity, length, id[3], 1u);
        length = append_text(out, capacity, length, "\nNAME=\"");
        length = append_text(out, capacity, length,
                             name && name[0] ? name : "EdgeOS input device");
        physical_path = input_physical_path(device);
        length = append_text(out, capacity, length, "\"\nPHYS=");
        length = append_text(out, capacity, length,
                             physical_path ? physical_path : "");
        length = append_text(out, capacity, length, "\n");
        break;
    case INPUT_NODE_EVENT_DEV:
        length = append_text(out, capacity, length, "13:");
        length = append_u32(out, capacity, length, 64u + device);
        length = append_text(out, capacity, length, "\n");
        break;
    case INPUT_NODE_EVENT_UEVENT:
        length = append_text(out, capacity, length, "MAJOR=13\nMINOR=");
        length = append_u32(out, capacity, length, 64u + device);
        length = append_text(out, capacity, length, "\nDEVNAME=input/event");
        length = append_u32(out, capacity, length, device);
        length = append_text(out, capacity, length, "\n");
        break;
    case INPUT_NODE_PROPERTIES:
    case INPUT_NODE_CAP_EV:
    case INPUT_NODE_CAP_KEY:
    case INPUT_NODE_CAP_REL:
    case INPUT_NODE_CAP_ABS:
        return input_bitmap_text(device, attribute, out, capacity);
    default:
        return -1;
    }
    return (int)length;
}

static int sys_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t offset,
                    void *out, uint32_t length) {
    char value[512];
    uint32_t size = 0;
    uint32_t count;
    uint32_t input_device;
    uint32_t input_attribute;
#ifdef CONFIG_PCI
    uint32_t device;
    uint32_t attribute;
#endif
    uint32_t tty_device;
    uint32_t tty_attribute;
    uint32_t cpu;
    uint32_t cpu_attribute;
    uint32_t net_device;
    uint32_t net_attribute;
    kernel_console_device_t console_device;
    (void)sb;
    if (!inode || !out) return -1;
#ifdef CONFIG_LOOP_DEVICE
    {
        uint32_t loop_device;
        uint32_t loop_attribute;

        if (sys_loop_node(inode->fs_private[0], &loop_device,
                          &loop_attribute) &&
            loop_attribute >= LOOP_NODE_DEV &&
            loop_attribute < LOOP_NODE_DEV_LINK) {
            char loop_name[8];
            int result;

            sys_loop_device_name(loop_name, sizeof(loop_name), loop_device);
            if (loop_attribute >= LOOP_NODE_BACKING_FILE) {
                result = edge_loop_sysfs_read_file(
                    loop_name,
                    g_loop_attribute_names[
                        loop_attribute - LOOP_NODE_BACKING_FILE],
                    value, sizeof(value));
            } else {
                char path[64];
                uint32_t path_length = 0;

                path_length = append_text(
                    path, sizeof(path), path_length, "/sys/block/");
                path_length = append_text(
                    path, sizeof(path), path_length, loop_name);
                path_length = append_text(
                    path, sizeof(path), path_length, "/");
                path_length = append_text(
                    path, sizeof(path), path_length,
                    g_loop_root_attribute_names[
                        loop_attribute - LOOP_NODE_DEV]);
                path[path_length] = 0;
                result = block_sysfs_read_file(path, value, sizeof(value));
            }
            if (result < 0) return -1;
            size = (uint32_t)result;
            goto copy_value;
        }
    }
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    {
        bsd_bridge_cdev_node_t bsd_node;
        uint32_t bsd_kind;

        if (sys_bsd_cdev_inode(inode, &bsd_kind, &bsd_node)) {
            if (bsd_kind == SYS_BSD_CDEV_DEVICE_DEV) {
                size = append_u32(value, sizeof(value), size,
                    bsd_node.major);
                size = append_text(value, sizeof(value), size, ":");
                size = append_u32(value, sizeof(value), size,
                    bsd_node.minor);
                size = append_text(value, sizeof(value), size, "\n");
            } else if (bsd_kind == SYS_BSD_CDEV_DEVICE_UEVENT) {
                size = append_text(value, sizeof(value), size,
                    "MAJOR=");
                size = append_u32(value, sizeof(value), size,
                    bsd_node.major);
                size = append_text(value, sizeof(value), size,
                    "\nMINOR=");
                size = append_u32(value, sizeof(value), size,
                    bsd_node.minor);
                size = append_text(value, sizeof(value), size,
                    "\nDEVNAME=");
                size = append_text(value, sizeof(value), size,
                    bsd_node.name);
                size = append_text(value, sizeof(value), size, "\n");
            } else {
                return -1;
            }
            goto copy_value;
        }
    }
#endif
#ifdef CONFIG_PCI
    if (sys_pci_node(inode->fs_private[0], &device, &attribute) &&
        attribute != PCI_NODE_ROOT) {
        char path[96];
        int result;

        if (attribute == PCI_NODE_SUBSYSTEM ||
            sys_pci_build_path(device, attribute, path, sizeof(path)) < 0)
            return -1;
        result = pci_sysfs_read_file(path, value, sizeof(value));
        if (result < 0) return -1;
        size = (uint32_t)result;
        goto copy_value;
    }
#endif
    if (sys_net_node(inode->fs_private[0], &net_device, &net_attribute)) {
        edge_net_device_snapshot_t snapshot;
        edge_net_device_snapshot_t *dynamic_snapshot = 0;
        uint8_t address[6] = {0};
        char name[EDGE_NET_DEVICE_NAME_MAX];
        uint64_t rx_packets = 0;
        uint64_t rx_bytes = 0;
        uint64_t tx_packets = 0;
        uint64_t tx_bytes = 0;
        int link_up = net_device == 0u ? 1 : lwip_stack_get_link_state();
        if (!sys_net_device_available(net_device) ||
            sys_net_device_name(net_device, name, sizeof(name)) < 0)
            return -1;
        if (net_device == 1u) {
            (void)lwip_stack_get_mac(address);
        } else if (net_device >= 2u) {
            if (sys_net_device_snapshot(net_device, &snapshot) < 0)
                return -1;
            dynamic_snapshot = &snapshot;
            memcpy(address, snapshot.configuration.hardware_address,
                   sizeof(address));
            link_up = snapshot.configuration.carrier &&
                (snapshot.configuration.flags & EDGE_NET_DEVICE_FLAG_UP);
        }
        switch (net_attribute) {
        case NET_NODE_IFINDEX:
            size = append_u32(value, sizeof(value), size, net_device + 1u);
            size = append_text(value, sizeof(value), size, "\n");
            break;
        case NET_NODE_IFLINK:
            size = append_u32(
                value, sizeof(value), size,
                dynamic_snapshot && dynamic_snapshot->peer_ifindex > 0 ?
                    (uint32_t)dynamic_snapshot->peer_ifindex :
                    net_device + 1u);
            size = append_text(value, sizeof(value), size, "\n");
            break;
        case NET_NODE_FLAGS:
            size = append_text(value, sizeof(value), size, "0x");
            size = append_hex(
                value, sizeof(value), size,
                net_device == 0u ? 0x49u :
                dynamic_snapshot ? dynamic_snapshot->configuration.flags :
                (link_up ? 0x1043u : 0x1002u), 1u);
            size = append_text(value, sizeof(value), size, "\n");
            break;
        case NET_NODE_MTU:
            size = append_u32(
                value, sizeof(value), size,
                net_device == 0u ? 65536u :
                dynamic_snapshot ? dynamic_snapshot->configuration.mtu :
                lwip_stack_get_mtu());
            size = append_text(value, sizeof(value), size, "\n");
            break;
        case NET_NODE_TYPE:
            size = append_u32(value, sizeof(value), size,
                              net_device == 0u ? 772u : 1u);
            size = append_text(value, sizeof(value), size, "\n");
            break;
        case NET_NODE_ADDRESS:
            size = append_mac(value, sizeof(value), size, address);
            break;
        case NET_NODE_BROADCAST:
            for (uint32_t index = 0; index < 6u; ++index)
                address[index] = net_device == 0u ? 0u : 0xffu;
            size = append_mac(value, sizeof(value), size, address);
            break;
        case NET_NODE_OPERSTATE:
            size = append_text(value, sizeof(value), size,
                               net_device == 0u ? "unknown\n" :
                               link_up ? "up\n" : "down\n");
            break;
        case NET_NODE_CARRIER:
            size = append_text(value, sizeof(value), size,
                               link_up ? "1\n" : "0\n");
            break;
        case NET_NODE_TX_QUEUE_LEN:
            size = append_text(value, sizeof(value), size, "1000\n");
            break;
        case NET_NODE_ADDR_ASSIGN_TYPE:
            size = append_text(value, sizeof(value), size,
                               net_device == 0u ? "0\n" : "3\n");
            break;
        case NET_NODE_ADDR_LEN:
            size = append_text(value, sizeof(value), size, "6\n");
            break;
        case NET_NODE_DEV_ID:
            size = append_text(value, sizeof(value), size, "0x0\n");
            break;
        case NET_NODE_DORMANT:
        case NET_NODE_LINK_MODE:
        case NET_NODE_PROTO_DOWN:
            size = append_text(value, sizeof(value), size, "0\n");
            break;
        case NET_NODE_UEVENT:
            size = append_text(value, sizeof(value), size, "INTERFACE=");
            size = append_text(value, sizeof(value), size, name);
            size = append_text(value, sizeof(value), size, "\nIFINDEX=");
            size = append_u32(value, sizeof(value), size, net_device + 1u);
            size = append_text(value, sizeof(value), size, "\n");
            break;
        case NET_NODE_RX_PACKETS:
        case NET_NODE_RX_BYTES:
        case NET_NODE_TX_PACKETS:
        case NET_NODE_TX_BYTES:
            if (net_device == 1u)
                lwip_stack_get_link_stats(&rx_packets, &rx_bytes,
                                          &tx_packets, &tx_bytes);
            else if (dynamic_snapshot) {
                rx_packets = dynamic_snapshot->rx_packets;
                rx_bytes = dynamic_snapshot->rx_bytes;
                tx_packets = dynamic_snapshot->tx_packets;
                tx_bytes = dynamic_snapshot->tx_bytes;
            }
            if (net_attribute == NET_NODE_RX_PACKETS)
                size = append_u64(value, sizeof(value), size, rx_packets);
            else if (net_attribute == NET_NODE_RX_BYTES)
                size = append_u64(value, sizeof(value), size, rx_bytes);
            else if (net_attribute == NET_NODE_TX_PACKETS)
                size = append_u64(value, sizeof(value), size, tx_packets);
            else
                size = append_u64(value, sizeof(value), size, tx_bytes);
            size = append_text(value, sizeof(value), size, "\n");
            break;
        default:
            return -1;
        }
        goto copy_value;
    }
    if (sys_cpu_node(inode->fs_private[0], &cpu, &cpu_attribute)) {
        uint64_t online = sys_cpu_online_mask();
        if (!(online & (1ULL << cpu))) return -1;
        if (cpu_attribute == CPU_NODE_ONLINE) {
            size = append_text(value, sizeof(value), size, "1\n");
        } else if (cpu_attribute == CPU_NODE_CORE_ID) {
            size = append_u32(value, sizeof(value), size, cpu);
            size = append_text(value, sizeof(value), size, "\n");
        } else if (cpu_attribute == CPU_NODE_PHYSICAL_PACKAGE_ID) {
            size = append_text(value, sizeof(value), size, "0\n");
        } else if (cpu_attribute == CPU_NODE_THREAD_SIBLINGS_LIST) {
            size = append_cpu_list(value, sizeof(value), size, 1ULL << cpu);
        } else if (cpu_attribute == CPU_NODE_CORE_SIBLINGS_LIST ||
                   cpu_attribute == CPU_NODE_CLUSTER_CPUS_LIST) {
            size = append_cpu_list(value, sizeof(value), size, online);
        } else {
            return -1;
        }
        goto copy_value;
    }
    if (sys_tty_node(inode->fs_private[0], &tty_device, &tty_attribute)) {
        if (kernel_console_device_at(tty_device, &console_device) < 0)
            return -1;
        if (tty_attribute == TTY_NODE_DEV) {
            size = append_device_number(value, sizeof(value), size,
                                        &console_device);
            size = append_text(value, sizeof(value), size, "\n");
        } else if (tty_attribute == TTY_NODE_UEVENT) {
            size = append_text(value, sizeof(value), size, "MAJOR=");
            size = append_u32(value, sizeof(value), size,
                              console_device.major);
            size = append_text(value, sizeof(value), size, "\nMINOR=");
            size = append_u32(value, sizeof(value), size,
                              console_device.minor);
            size = append_text(value, sizeof(value), size, "\nDEVNAME=");
            size = append_text(value, sizeof(value), size,
                               console_device.name);
            size = append_text(value, sizeof(value), size, "\n");
        } else if (tty_attribute == TTY_NODE_ACTIVE &&
                   sys_console_device_has_active(tty_device)) {
            int result = text_equal(console_device.name, "console") ?
                kernel_console_configured_names(value, sizeof(value)) :
                kernel_console_active_names(value, sizeof(value));
            if (result < 0) return -1;
            size = (uint32_t)result;
        } else {
            return -1;
        }
        goto copy_value;
    }
    if (sys_input_node(inode->fs_private[0], &input_device,
                       &input_attribute)) {
        int input_size = input_attribute_text(input_device, input_attribute,
                                              value, sizeof(value));
        if (input_size < 0) return -1;
        size = (uint32_t)input_size;
        if (offset >= size) return 0;
        count = size - offset;
        if (count > length) count = length;
        memcpy(out, value + offset, count);
        return (int)count;
    }
    switch (inode->fs_private[0]) {
    case SYS_CPU_POSSIBLE:
    case SYS_CPU_PRESENT:
    case SYS_CPU_ONLINE:
        size = append_cpu_list(value, sizeof(value), size,
                               sys_cpu_online_mask());
        break;
    case SYS_CPU_OFFLINE:
        size = append_text(value, sizeof(value), size, "\n");
        break;
    case SYS_CPU_KERNEL_MAX:
        size = append_u32(value, sizeof(value), size, SYS_CPU_MAX - 1u);
        size = append_text(value, sizeof(value), size, "\n");
        break;
    case SYS_FB_NAME:
        size = append_text(value, sizeof(value), size, "EdgeOS UEFI GOP\n");
        break;
    case SYS_FB_SIZE:
        size = append_u32(value, sizeof(value), size, fb.width);
        size = append_text(value, sizeof(value), size, ",");
        size = append_u32(value, sizeof(value), size, fb.height);
        size = append_text(value, sizeof(value), size, "\n");
        break;
    case SYS_FB_STRIDE:
        size = append_u32(value, sizeof(value), size, fb.pitch);
        size = append_text(value, sizeof(value), size, "\n");
        break;
    case SYS_FB_BPP:
        size = append_u32(value, sizeof(value), size, fb.bpp);
        size = append_text(value, sizeof(value), size, "\n");
        break;
    case SYS_FB_DEV:
        size = append_text(value, sizeof(value), size, "29:0\n");
        break;
    case SYS_FB_UEVENT:
        size = append_text(value, sizeof(value), size,
                           "MAJOR=29\nMINOR=0\nDEVNAME=fb0\n"
                           "DRIVER=uefi-framebuffer\n"
                           "MODALIAS=platform:uefi-framebuffer\n");
        break;
    case SYS_DRM_CARD0_DEV:
        size = append_text(value, sizeof(value), size, "226:0\n");
        break;
    case SYS_DRM_CARD0_UEVENT:
        size = append_text(value, sizeof(value), size,
                           "MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\n"
                           "DEVTYPE=drm_minor\n");
        if (sys_drm_render_available())
            size = append_text(value, sizeof(value), size,
                               "DRIVER=virtio_gpu\n");
        break;
    case SYS_DRM_RENDERD128_DEV:
        size = append_text(value, sizeof(value), size, "226:128\n");
        break;
    case SYS_DRM_RENDERD128_UEVENT:
        size = append_text(value, sizeof(value), size,
                           "MAJOR=226\nMINOR=128\n"
                           "DEVNAME=dri/renderD128\n"
                           "DEVTYPE=drm_minor\n"
                           "DRIVER=virtio_gpu\n");
        break;
    case SYS_DRM_VIRTUAL_DEVICE_UEVENT:
        size = append_text(value, sizeof(value), size,
                           "DRIVER=virtio_gpu\n"
                           "MODALIAS=platform:virtio_gpu\n");
        break;
    case SYS_DRM_CARD0_STATUS:
        size = append_text(value, sizeof(value), size, "connected\n");
        break;
    case SYS_DRM_CARD0_ENABLED:
        size = append_text(value, sizeof(value), size, "enabled\n");
        break;
    case SYS_DRM_CARD0_MODES:
        size = append_u32(value, sizeof(value), size, fb.width);
        size = append_text(value, sizeof(value), size, "x");
        size = append_u32(value, sizeof(value), size, fb.height);
        size = append_text(value, sizeof(value), size, "\n");
        break;
    default:
        return -1;
    }
copy_value:
    if (offset >= size) return 0;
    count = size - offset;
    if (count > length) count = length;
    memcpy(out, value + offset, count);
    return (int)count;
}

static int sys_uevent_action(const void *input, uint32_t length,
                             char action[16]) {
    const char *bytes = (const char *)input;
    uint32_t copied = length;
    if (!input || !length || length >= 16u) return -22;
    while (copied && (bytes[copied - 1u] == '\n' ||
                      bytes[copied - 1u] == '\r'))
        --copied;
    if (!copied) return -22;
    for (uint32_t index = 0; index < copied; ++index) {
        if (!bytes[index] || bytes[index] == '\n' || bytes[index] == '\r')
            return -22;
        action[index] = bytes[index];
    }
    action[copied] = 0;
    return 0;
}

static int sys_write(vfs_superblock_t *sb, vfs_inode_t *inode,
                     uint32_t offset, const void *input, uint32_t length) {
    char action[16];
    char path[128];
    char device_name[32];
    uint32_t device;
    uint32_t attribute;
    uint32_t path_length = 0;
    uint32_t name_length = 0;
    int result;
    (void)sb;

    if (!inode) return -22;
    if (!length) return 0;
    if (offset != 0u) return -22;
    result = sys_uevent_action(input, length, action);
    if (result < 0) return result;

    if (sys_tty_node(inode->fs_private[0], &device, &attribute) &&
        attribute == TTY_NODE_UEVENT) {
        kernel_console_device_t console_device;
        if (kernel_console_device_at(device, &console_device) < 0) return -19;
        path_length = append_text(path, sizeof(path), path_length,
                                  "/devices/virtual/tty/");
        path_length = append_text(path, sizeof(path), path_length,
                                  console_device.name);
        if (path_length >= sizeof(path)) return -36;
        path[path_length] = 0;
        result = kernel_device_uevent_emit(
            action, path, "tty", console_device.major, console_device.minor,
            console_device.name, 0, 0);
    } else if (sys_input_node(inode->fs_private[0], &device, &attribute) &&
               (attribute == INPUT_NODE_UEVENT ||
                attribute == INPUT_NODE_EVENT_UEVENT)) {
        if (!input_device_present(device)) return -19;
        path_length = append_text(path, sizeof(path), path_length,
                                  "/devices/virtual/input/input");
        path_length = append_u32(path, sizeof(path), path_length, device);
        if (attribute == INPUT_NODE_EVENT_UEVENT) {
            path_length = append_text(path, sizeof(path), path_length,
                                      "/event");
            path_length = append_u32(path, sizeof(path), path_length, device);
            name_length = append_text(device_name, sizeof(device_name),
                                      name_length, "input/event");
            name_length = append_u32(device_name, sizeof(device_name),
                                     name_length, device);
        }
        if (path_length >= sizeof(path) ||
            name_length >= sizeof(device_name))
            return -36;
        path[path_length] = 0;
        device_name[name_length] = 0;
        result = kernel_device_uevent_emit(
            action, path, "input", 13u, 64u + device,
            attribute == INPUT_NODE_EVENT_UEVENT ? device_name : 0,
            input_driver(device), 0);
    } else if (sys_net_node(inode->fs_private[0], &device, &attribute) &&
               attribute == NET_NODE_UEVENT) {
        const char *driver = "virtio_net";

        if (sys_net_device_name(
                device, device_name, sizeof(device_name)) < 0)
            return -19;
        if (device >= 2u) {
            edge_net_device_snapshot_t snapshot;

            if (sys_net_device_snapshot(device, &snapshot) < 0)
                return -19;
            driver = snapshot.configuration.kind == EDGE_NET_DEVICE_BRIDGE ?
                "bridge" : "veth";
        }
        path_length = append_text(path, sizeof(path), path_length,
                                  "/devices/virtual/net/");
        path_length = append_text(
            path, sizeof(path), path_length, device_name);
        if (path_length >= sizeof(path)) return -19;
        path[path_length] = 0;
        result = kernel_device_uevent_emit(
            action, path, "net", 0u, 0u, 0,
            device == 0u ? "loopback" : driver, 0);
    } else if (inode->fs_private[0] == SYS_FB_UEVENT) {
        if (!fb.addr || !fb.width || !fb.height) return -19;
        result = kernel_device_uevent_emit(
            action, "/devices/virtual/drm/device0/graphics/fb0",
            "graphics", 29u, 0u, "fb0", "uefi-framebuffer",
            "platform:uefi-framebuffer");
    } else if (inode->fs_private[0] == SYS_DRM_CARD0_UEVENT ||
               inode->fs_private[0] == SYS_DRM_RENDERD128_UEVENT) {
        int render = inode->fs_private[0] == SYS_DRM_RENDERD128_UEVENT;
        if (!fb.addr || !fb.width || !fb.height) return -19;
        result = kernel_device_uevent_emit(
            action,
            render ? "/devices/virtual/drm/device0/drm/renderD128" :
                     "/devices/virtual/drm/device0/drm/card0",
            "drm", 226u, render ? 128u : 0u,
            render ? "dri/renderD128" : "dri/card0",
            render ? "virtio_gpu" :
                     (sys_drm_render_available() ?
                          "virtio_gpu" : "edgeos_drm"),
            0);
    } else {
        return -13;
    }
    if (result < 0) return result == -1 ? -22 : result;
    return (int)length;
}

static int sys_readlink(vfs_superblock_t *sb, vfs_inode_t *inode,
                        char *out, uint32_t maximum) {
    const char *target;
    char dynamic_target[128];
    uint32_t length;
    uint32_t device;
    uint32_t attribute;
    kernel_console_device_t console_device;
    (void)sb;
    if (!inode || !out) return -1;
#ifdef CONFIG_LOOP_DEVICE
    if (sys_loop_node(inode->fs_private[0], &device, &attribute) &&
        attribute == LOOP_NODE_DEV_LINK) {
        length = 0;
        length = append_text(dynamic_target, sizeof(dynamic_target), length,
                             "../../block/");
        length = sys_loop_device_name(
            dynamic_target + length,
            (uint32_t)sizeof(dynamic_target) - length, device) + length;
        if (maximum < length) length = maximum;
        memcpy(out, dynamic_target, length);
        return (int)length;
    }
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    {
        bsd_bridge_cdev_node_t bsd_node;
        uint32_t bsd_kind;

        if (sys_bsd_cdev_inode(inode, &bsd_kind, &bsd_node)) {
            length = 0;
            if (bsd_kind == SYS_BSD_CDEV_DEV_CHAR ||
                bsd_kind == SYS_BSD_CDEV_CLASS_LINK) {
                length = append_text(dynamic_target,
                    sizeof(dynamic_target), length,
                    "../../devices/virtual/");
                length = append_text(dynamic_target,
                    sizeof(dynamic_target), length,
                    sys_bsd_cdev_class_name(&bsd_node));
                length = append_text(dynamic_target,
                    sizeof(dynamic_target), length, "/");
                length = append_text(dynamic_target,
                    sizeof(dynamic_target), length, bsd_node.name);
            } else if (bsd_kind ==
                SYS_BSD_CDEV_DEVICE_SUBSYSTEM) {
                length = append_text(dynamic_target,
                    sizeof(dynamic_target), length,
                    "../../../../class/");
                length = append_text(dynamic_target,
                    sizeof(dynamic_target), length,
                    sys_bsd_cdev_class_name(&bsd_node));
            } else {
                return -1;
            }
            if (maximum < length)
                length = maximum;
            memcpy(out, dynamic_target, length);
            return (int)length;
        }
    }
#endif
#ifdef CONFIG_PCI
    if (sys_pci_node(inode->fs_private[0], &device, &attribute) &&
        attribute == PCI_NODE_SUBSYSTEM) {
        char path[96];
        if (sys_pci_build_path(device, attribute, path, sizeof(path)) < 0)
            return -1;
        return pci_sysfs_readlink(path, out, maximum);
    }
#endif
    if (sys_tty_node(inode->fs_private[0], &device, &attribute)) {
        if (kernel_console_device_at(device, &console_device) < 0) return -1;
        length = 0;
        if (attribute == TTY_NODE_CLASS) {
            length = append_text(dynamic_target, sizeof(dynamic_target),
                                 length, "../../devices/virtual/tty/");
            length = append_text(dynamic_target, sizeof(dynamic_target),
                                 length, console_device.name);
        } else if (attribute == TTY_NODE_SUBSYSTEM) {
            length = append_text(dynamic_target, sizeof(dynamic_target),
                                 length, "../../../../class/tty");
        } else {
            return -1;
        }
        if (maximum < length) length = maximum;
        memcpy(out, dynamic_target, length);
        return (int)length;
    }
    if (sys_tty_dev_char_node(inode->fs_private[0], &device)) {
        if (kernel_console_device_at(device, &console_device) < 0) return -1;
        length = 0;
        length = append_text(dynamic_target, sizeof(dynamic_target), length,
                             "../../devices/virtual/tty/");
        length = append_text(dynamic_target, sizeof(dynamic_target), length,
                             console_device.name);
        if (maximum < length) length = maximum;
        memcpy(out, dynamic_target, length);
        return (int)length;
    }
    {
        int input_event;

        if (sys_input_class_node(
                inode->fs_private[0], &device, &input_event)) {
            length = 0;
            length = append_text(
                dynamic_target, sizeof(dynamic_target), length,
                "../../devices/virtual/input/input");
            length = append_u32(
                dynamic_target, sizeof(dynamic_target), length, device);
            if (input_event) {
                length = append_text(
                    dynamic_target, sizeof(dynamic_target), length,
                    "/event");
                length = append_u32(
                    dynamic_target, sizeof(dynamic_target), length,
                    device);
            }
            if (maximum < length) length = maximum;
            memcpy(out, dynamic_target, length);
            return (int)length;
        }
    }
    if (sys_input_node(inode->fs_private[0], &device, &attribute) &&
        (attribute == INPUT_NODE_SUBSYSTEM ||
         attribute == INPUT_NODE_EVENT_SUBSYSTEM)) {
        target = attribute == INPUT_NODE_SUBSYSTEM ?
            "../../../../class/input" :
            "../../../../../class/input";
    } else if (sys_net_node(
                   inode->fs_private[0], &device, &attribute) &&
               attribute == NET_NODE_CLASS_LINK) {
        char net_name[EDGE_NET_DEVICE_NAME_MAX];

        if (sys_net_device_name(device, net_name, sizeof(net_name)) < 0)
            return -1;
        length = 0;
        length = append_text(
            dynamic_target, sizeof(dynamic_target), length,
            "../../devices/virtual/net/");
        length = append_text(
            dynamic_target, sizeof(dynamic_target), length, net_name);
        if (maximum < length) length = maximum;
        memcpy(out, dynamic_target, length);
        return (int)length;
    } else if (inode->fs_private[0] == SYS_NET_CLASS_LO) {
        target = "../../devices/virtual/net/lo";
    } else if (inode->fs_private[0] == SYS_NET_CLASS_ETH0) {
        target = "../../devices/virtual/net/eth0";
    } else if (inode->fs_private[0] == SYS_DRM_CLASS_CARD0) {
        target = "../../devices/virtual/drm/device0/drm/card0";
    } else if (inode->fs_private[0] == SYS_DRM_CLASS_RENDERD128) {
        target = "../../devices/virtual/drm/device0/drm/renderD128";
    } else if (sys_net_node(inode->fs_private[0], &device, &attribute) &&
               attribute == NET_NODE_SUBSYSTEM) {
        target = "../../../../class/net";
    } else if (inode->fs_private[0] == SYS_DRM_CARD0_SUBSYSTEM) {
        target = "../../../../../../class/drm";
    } else if (inode->fs_private[0] == SYS_DRM_RENDERD128_SUBSYSTEM) {
        target = "../../../../../../class/drm";
    } else if (inode->fs_private[0] == SYS_DRM_CARD0_DEVICE ||
               inode->fs_private[0] == SYS_DRM_RENDERD128_DEVICE) {
        char pci_name[16];

        if (sys_drm_pci_device_name(pci_name, sizeof(pci_name)) < 0) {
            target = "../..";
        } else {
            length = 0;
            length = append_text(dynamic_target, sizeof(dynamic_target), length,
                                 "../../../../../../bus/pci/devices/");
            length = append_text(dynamic_target, sizeof(dynamic_target), length,
                                 pci_name);
            if (maximum < length) length = maximum;
            memcpy(out, dynamic_target, length);
            return (int)length;
        }
    } else if (inode->fs_private[0] == SYS_DRM_VIRTUAL_DEVICE_SUBSYSTEM) {
        target = "../../../../bus/platform";
    } else if (inode->fs_private[0] == SYS_DRM_VIRTUAL_DEVICE_CARD0) {
        target = "../../card0";
    } else if (inode->fs_private[0] == SYS_DRM_VIRTUAL_DEVICE_RENDERD128) {
        target = "../../renderD128";
    } else if (inode->fs_private[0] == SYS_FB_DEV_CHAR) {
        target = "../../devices/virtual/drm/device0/graphics/fb0";
    } else if (inode->fs_private[0] == SYS_DRM_CARD0_DEV_CHAR) {
        target = "../../devices/virtual/drm/device0/drm/card0";
    } else if (inode->fs_private[0] == SYS_DRM_RENDERD128_DEV_CHAR) {
        target = "../../devices/virtual/drm/device0/drm/renderD128";
    } else if (inode->fs_private[0] == SYS_DRM_PCI_CARD0) {
        target = "../../../../../devices/virtual/drm/device0/drm/card0";
    } else if (inode->fs_private[0] == SYS_DRM_PCI_RENDERD128) {
        target = "../../../../../devices/virtual/drm/device0/drm/renderD128";
    } else if (sys_input_dev_char_node(inode->fs_private[0], &device)) {
        length = 0;
        length = append_text(dynamic_target, sizeof(dynamic_target), length,
                             "../../devices/virtual/input/input");
        length = append_u32(dynamic_target, sizeof(dynamic_target), length,
                            device);
        length = append_text(dynamic_target, sizeof(dynamic_target), length,
                             "/event");
        length = append_u32(dynamic_target, sizeof(dynamic_target), length,
                            device);
        if (maximum < length) length = maximum;
        memcpy(out, dynamic_target, length);
        return (int)length;
    } else if (inode->fs_private[0] == SYS_FB0) {
        target = "../../devices/virtual/drm/device0/graphics/fb0";
    } else if (inode->fs_private[0] == SYS_FB_DEVICE) {
        target = "../..";
    } else if (inode->fs_private[0] == SYS_FB_SUBSYSTEM) {
        target = "../../../../../class/graphics";
    }
    else if (inode->fs_private[0] == SYS_DEVICE_SUBSYSTEM)
        target = "../../../bus/platform";
    else if (inode->fs_private[0] == SYS_PLATFORM_DEVICE)
        target = "../../../devices/platform/uefi-framebuffer.0";
    else
        return -1;
    length = (uint32_t)strlen(target);
    if (maximum < length) length = maximum;
    memcpy(out, target, length);
    return (int)length;
}

static int sys_readdir(vfs_superblock_t *sb, vfs_inode_t *directory,
                       uint32_t position, char *name, vfs_inode_t *out) {
    uint32_t found = 0;
    uint32_t device;
    uint32_t attribute;
    kernel_console_device_t console_device;
    (void)sb;
    if (!directory || !name || !out) return -1;
#ifdef CONFIG_LOOP_DEVICE
    if (directory->fs_private[0] == SYS_DEV_BLOCK) {
        char loop_name[8];
        uint32_t ordinal = position;
        uint32_t length;

        for (device = 0; device < EDGE_LOOP_DEVICE_COUNT; ++device) {
            sys_loop_device_name(loop_name, sizeof(loop_name), device);
            if (edge_loop_sysfs_path_kind(loop_name, "") !=
                BLOCK_SYSFS_PATH_DIR)
                continue;
            if (ordinal-- != 0u) continue;
            length = append_text(name, VFS_NAME_MAX, 0u, "7:");
            length = append_u32(name, VFS_NAME_MAX, length, device);
            name[length] = 0;
            inode_set(out, SYS_LOOP_NODE(device, LOOP_NODE_DEV_LINK),
                      VFS_INODE_LNK | 0777);
            return 0;
        }
        return -1;
    }
    if (directory->fs_private[0] == SYS_BLOCK) {
        char loop_name[8];

        for (device = 0; device < EDGE_LOOP_DEVICE_COUNT; ++device) {
            sys_loop_device_name(loop_name, sizeof(loop_name), device);
            if (edge_loop_sysfs_path_kind(loop_name, "") !=
                BLOCK_SYSFS_PATH_DIR)
                continue;
            if (position-- != 0u) continue;
            strcpy(name, loop_name);
            inode_set(out, SYS_LOOP_NODE(device, LOOP_NODE_ROOT),
                      VFS_INODE_DIR | 0555);
            return 0;
        }
        return -1;
    }
    if (sys_loop_node(directory->fs_private[0], &device, &attribute)) {
        if (attribute == LOOP_NODE_ROOT) {
            if (position == 0u) {
                strcpy(name, "loop");
                inode_set(out, SYS_LOOP_NODE(device, LOOP_NODE_DIRECTORY),
                          VFS_INODE_DIR | 0555);
                return 0;
            }
            --position;
            if (position >= sizeof(g_loop_root_attribute_names) /
                                sizeof(g_loop_root_attribute_names[0]))
                return -1;
            strcpy(name, g_loop_root_attribute_names[position]);
            inode_set(out, SYS_LOOP_NODE(device, LOOP_NODE_DEV + position),
                      VFS_INODE_FILE | 0444);
            return 0;
        }
        if (attribute == LOOP_NODE_DIRECTORY) {
            if (position >= sizeof(g_loop_attribute_names) /
                                sizeof(g_loop_attribute_names[0]))
                return -1;
            strcpy(name, g_loop_attribute_names[position]);
            inode_set(out, SYS_LOOP_NODE(
                          device, LOOP_NODE_BACKING_FILE + position),
                      VFS_INODE_FILE | 0444);
            return 0;
        }
        return -1;
    }
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    {
        bsd_bridge_cdev_node_t bsd_node;
        uint32_t bsd_kind;
        int video;

        if (directory->fs_private[0] == SYS_VIDEO4LINUX_CLASS ||
            directory->fs_private[0] == SYS_BSD_CDEV_CLASS ||
            directory->fs_private[0] ==
                SYS_DEVICES_VIRTUAL_VIDEO4LINUX ||
            directory->fs_private[0] ==
                SYS_DEVICES_VIRTUAL_BSD_CDEV) {
            video = directory->fs_private[0] ==
                    SYS_VIDEO4LINUX_CLASS ||
                directory->fs_private[0] ==
                    SYS_DEVICES_VIRTUAL_VIDEO4LINUX;
            if (sys_bsd_cdev_at_class_ordinal(
                video, position, &bsd_node) != 0)
                return -1;
            strcpy(name, bsd_node.name);
            inode_set_bsd_cdev(out, &bsd_node,
                directory->fs_private[0] == SYS_VIDEO4LINUX_CLASS ||
                directory->fs_private[0] == SYS_BSD_CDEV_CLASS ?
                    SYS_BSD_CDEV_CLASS_LINK :
                    SYS_BSD_CDEV_DEVICE_ROOT,
                directory->fs_private[0] == SYS_VIDEO4LINUX_CLASS ||
                directory->fs_private[0] == SYS_BSD_CDEV_CLASS ?
                    VFS_INODE_LNK | 0777 :
                    VFS_INODE_DIR | 0555);
            return 0;
        }
        if (sys_bsd_cdev_inode(directory, &bsd_kind, &bsd_node) &&
            bsd_kind == SYS_BSD_CDEV_DEVICE_ROOT) {
            static const char *const names[] = {
                "dev", "uevent", "subsystem"
            };
            static const uint32_t kinds[] = {
                SYS_BSD_CDEV_DEVICE_DEV,
                SYS_BSD_CDEV_DEVICE_UEVENT,
                SYS_BSD_CDEV_DEVICE_SUBSYSTEM
            };
            static const uint16_t modes[] = {
                VFS_INODE_FILE | 0444,
                VFS_INODE_FILE | 0444,
                VFS_INODE_LNK | 0777
            };

            if (position >= sizeof(names) / sizeof(names[0]))
                return -1;
            strcpy(name, names[position]);
            inode_set_bsd_cdev(out, &bsd_node,
                kinds[position], modes[position]);
            return 0;
        }
    }
#endif
#ifdef CONFIG_PCI
    if (directory->fs_private[0] == SYS_PCI_DEVICES) {
        if (position >= SYS_PCI_MAX_DEVICES ||
            pci_device_name_by_index(position, name, VFS_NAME_MAX) < 0)
            return -1;
        inode_set(out, SYS_PCI_NODE(position, PCI_NODE_ROOT),
                  VFS_INODE_DIR | 0555);
        return 0;
    }
    if (sys_pci_node(directory->fs_private[0], &device, &attribute) &&
        attribute == PCI_NODE_ROOT) {
        uint32_t count = sizeof(g_pci_attribute_names) /
                         sizeof(g_pci_attribute_names[0]);
        if (position == count && sys_drm_pci_device_matches(device)) {
            strcpy(name, "drm");
            inode_set(out, SYS_DRM_PCI_DIRECTORY,
                      VFS_INODE_DIR | 0555);
            return 0;
        }
        if (position >= count)
            return -1;
        strcpy(name, g_pci_attribute_names[position]);
        inode_set(out, SYS_PCI_NODE(device, position + 1u),
                  g_pci_attribute_modes[position]);
        return 0;
    }
    if (directory->fs_private[0] == SYS_DRM_PCI_DIRECTORY) {
        if (position > 1u) return -1;
        if (position == 0u) {
            strcpy(name, "card0");
            inode_set(out, SYS_DRM_PCI_CARD0,
                      VFS_INODE_LNK | 0777);
        } else {
            strcpy(name, "renderD128");
            inode_set(out, SYS_DRM_PCI_RENDERD128,
                      VFS_INODE_LNK | 0777);
        }
        return 0;
    }
#endif
    if (directory->fs_private[0] == SYS_NET_CLASS ||
        directory->fs_private[0] == SYS_DEVICES_VIRTUAL_NET) {
        uint32_t network_namespace = sys_net_current_namespace();
        uint32_t static_count = !network_namespace &&
            lwip_stack_is_ready() ? 2u : 1u;
        edge_net_device_snapshot_t snapshot;
        uint32_t ordinal;

        if (position == 0u) {
            strcpy(name, "lo");
            inode_set(out,
                directory->fs_private[0] == SYS_NET_CLASS ?
                    SYS_NET_CLASS_LO :
                    SYS_NET_NODE(0, NET_NODE_ROOT),
                directory->fs_private[0] == SYS_NET_CLASS ?
                    VFS_INODE_LNK | 0777 : VFS_INODE_DIR | 0555);
            return 0;
        }
        if (static_count == 2u && position == 1u) {
            strcpy(name, "eth0");
            inode_set(out,
                directory->fs_private[0] == SYS_NET_CLASS ?
                    SYS_NET_CLASS_ETH0 :
                    SYS_NET_NODE(1, NET_NODE_ROOT),
                directory->fs_private[0] == SYS_NET_CLASS ?
                    VFS_INODE_LNK | 0777 : VFS_INODE_DIR | 0555);
            return 0;
        }
        position -= static_count;
        for (ordinal = 0;
             edge_net_device_snapshot_at(
                 network_namespace, ordinal, &snapshot) == EDGE_NET_OK;
             ++ordinal) {
            int32_t ifindex = snapshot.configuration.ifindex;

            if (ifindex <= 2 ||
                (uint32_t)ifindex >= SYS_NET_DYNAMIC_IFINDEX_MAX)
                continue;
            if (position-- != 0u) continue;
            strcpy(name, snapshot.configuration.name);
            inode_set(out, SYS_NET_DYNAMIC_NODE(
                          ifindex,
                          directory->fs_private[0] == SYS_NET_CLASS ?
                              NET_NODE_CLASS_LINK : NET_NODE_ROOT),
                      directory->fs_private[0] == SYS_NET_CLASS ?
                          VFS_INODE_LNK | 0777 : VFS_INODE_DIR | 0555);
            return 0;
        }
        return -1;
    }
    if (directory->fs_private[0] == SYS_CPU_ROOT) {
        uint32_t static_count = 0;
        for (uint32_t index = 0;
             index < sizeof(g_entries) / sizeof(g_entries[0]); ++index)
            if (g_entries[index].parent == SYS_CPU_ROOT) ++static_count;
        if (position >= static_count) {
            uint32_t ordinal = position - static_count;
            uint64_t online = sys_cpu_online_mask();
            for (uint32_t cpu = 0; cpu < SYS_CPU_MAX; ++cpu) {
                uint32_t length = 0;
                if (!(online & (1ULL << cpu))) continue;
                if (ordinal--) continue;
                length = append_text(name, VFS_NAME_MAX, length, "cpu");
                length = append_u32(name, VFS_NAME_MAX, length, cpu);
                name[length] = 0;
                inode_set(out, SYS_CPU_NODE(cpu, CPU_NODE_ROOT),
                          VFS_INODE_DIR | 0555);
                return 0;
            }
            return -1;
        }
    }
    if (sys_net_node(directory->fs_private[0], &device, &attribute) &&
        attribute == NET_NODE_ROOT) {
        static const char *const names[] = {
            "ifindex", "iflink", "flags", "mtu", "type", "address",
            "broadcast", "operstate", "carrier", "tx_queue_len",
            "addr_assign_type", "addr_len", "dev_id", "dormant",
            "link_mode", "proto_down", "uevent", "subsystem", "statistics"
        };
        static const uint16_t modes[] = {
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0644, VFS_INODE_LNK | 0777,
            VFS_INODE_DIR | 0555
        };
        if (position >= sizeof(names) / sizeof(names[0])) return -1;
        strcpy(name, names[position]);
        inode_set(out, sys_net_device_node(
                      device, NET_NODE_IFINDEX + position),
                  modes[position]);
        return 0;
    }
    if (sys_net_node(directory->fs_private[0], &device, &attribute) &&
        attribute == NET_NODE_STATISTICS) {
        static const char *const names[] = {
            "rx_packets", "rx_bytes", "tx_packets", "tx_bytes"
        };
        if (position >= sizeof(names) / sizeof(names[0])) return -1;
        strcpy(name, names[position]);
        inode_set(out, sys_net_device_node(
                      device, NET_NODE_RX_PACKETS + position),
                  VFS_INODE_FILE | 0444);
        return 0;
    }
    if (sys_cpu_node(directory->fs_private[0], &device, &attribute) &&
        attribute == CPU_NODE_ROOT) {
        if (device == 0u) {
            if (position != 0u) return -1;
            strcpy(name, "topology");
            inode_set(out, SYS_CPU_NODE(device, CPU_NODE_TOPOLOGY),
                      VFS_INODE_DIR | 0555);
        } else {
            if (position > 1u) return -1;
            if (position == 0u) {
                strcpy(name, "online");
                inode_set(out, SYS_CPU_NODE(device, CPU_NODE_ONLINE),
                          VFS_INODE_FILE | 0644);
            } else {
                strcpy(name, "topology");
                inode_set(out, SYS_CPU_NODE(device, CPU_NODE_TOPOLOGY),
                          VFS_INODE_DIR | 0555);
            }
        }
        return 0;
    }
    if (sys_cpu_node(directory->fs_private[0], &device, &attribute) &&
        attribute == CPU_NODE_TOPOLOGY) {
        static const char *const names[] = {
            "core_id", "physical_package_id", "core_siblings_list",
            "thread_siblings_list", "cluster_cpus_list"
        };
        static const uint32_t nodes[] = {
            CPU_NODE_CORE_ID, CPU_NODE_PHYSICAL_PACKAGE_ID,
            CPU_NODE_CORE_SIBLINGS_LIST, CPU_NODE_THREAD_SIBLINGS_LIST,
            CPU_NODE_CLUSTER_CPUS_LIST
        };
        if (position >= sizeof(names) / sizeof(names[0])) return -1;
        strcpy(name, names[position]);
        inode_set(out, SYS_CPU_NODE(device, nodes[position]),
                  VFS_INODE_FILE | 0444);
        return 0;
    }
    if (directory->fs_private[0] == SYS_INPUT_CLASS) {
        int event = (position & 1u) != 0;
        uint32_t length;

        if (sys_input_device_at_ordinal(position / 2u, &device) < 0)
            return -1;
        length = append_text(name, VFS_NAME_MAX, 0u,
                             event ? "event" : "input");
        length = append_u32(name, VFS_NAME_MAX, length, device);
        name[length] = 0;
        inode_set(out, SYS_INPUT_CLASS_NODE(device, event),
                  VFS_INODE_LNK | 0777);
        return 0;
    }
    if (directory->fs_private[0] == SYS_DEVICES_VIRTUAL_INPUT) {
        uint32_t length;

        if (sys_input_device_at_ordinal(position, &device) < 0)
            return -1;
        length = append_text(name, VFS_NAME_MAX, 0u, "input");
        length = append_u32(name, VFS_NAME_MAX, length, device);
        name[length] = 0;
        inode_set(out, SYS_INPUT_NODE(device, INPUT_NODE_ROOT),
                  VFS_INODE_DIR | 0555);
        return 0;
    }
    if (sys_input_node(
            directory->fs_private[0], &device, &attribute)) {
        static const char *const root_names[] = {
            "name", "phys", "uniq", "properties", "uevent",
            "subsystem", "id", "capabilities"
        };
        static const uint32_t root_nodes[] = {
            INPUT_NODE_NAME, INPUT_NODE_PHYS, INPUT_NODE_UNIQ,
            INPUT_NODE_PROPERTIES, INPUT_NODE_UEVENT,
            INPUT_NODE_SUBSYSTEM, INPUT_NODE_ID,
            INPUT_NODE_CAPABILITIES
        };
        static const uint16_t root_modes[] = {
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0444,
            VFS_INODE_FILE | 0644, VFS_INODE_LNK | 0777,
            VFS_INODE_DIR | 0555, VFS_INODE_DIR | 0555
        };
        static const char *const id_names[] = {
            "bustype", "vendor", "product", "version"
        };
        static const char *const capability_names[] = {
            "ev", "key", "rel", "abs"
        };
        static const char *const event_names[] = {
            "dev", "uevent", "subsystem"
        };
        static const uint16_t event_modes[] = {
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0644,
            VFS_INODE_LNK | 0777
        };

        if (attribute == INPUT_NODE_ROOT) {
            if (position < sizeof(root_names) / sizeof(root_names[0])) {
                strcpy(name, root_names[position]);
                inode_set(out, SYS_INPUT_NODE(device, root_nodes[position]),
                          root_modes[position]);
                return 0;
            }
            if (position == sizeof(root_names) / sizeof(root_names[0])) {
                uint32_t length = append_text(
                    name, VFS_NAME_MAX, 0u, "event");
                length = append_u32(
                    name, VFS_NAME_MAX, length, device);
                name[length] = 0;
                inode_set(out, SYS_INPUT_NODE(device, INPUT_NODE_EVENT),
                          VFS_INODE_DIR | 0555);
                return 0;
            }
            return -1;
        }
        if (attribute == INPUT_NODE_ID) {
            if (position >= sizeof(id_names) / sizeof(id_names[0]))
                return -1;
            strcpy(name, id_names[position]);
            inode_set(out,
                      SYS_INPUT_NODE(
                          device, INPUT_NODE_ID_BUSTYPE + position),
                      VFS_INODE_FILE | 0444);
            return 0;
        }
        if (attribute == INPUT_NODE_CAPABILITIES) {
            if (position >= sizeof(capability_names) /
                                sizeof(capability_names[0]))
                return -1;
            strcpy(name, capability_names[position]);
            inode_set(out,
                      SYS_INPUT_NODE(
                          device, INPUT_NODE_CAP_EV + position),
                      VFS_INODE_FILE | 0444);
            return 0;
        }
        if (attribute == INPUT_NODE_EVENT) {
            if (position >= sizeof(event_names) / sizeof(event_names[0]))
                return -1;
            strcpy(name, event_names[position]);
            inode_set(out,
                      SYS_INPUT_NODE(
                          device, INPUT_NODE_EVENT_DEV + position),
                      event_modes[position]);
            return 0;
        }
        return -1;
    }
    if (directory->fs_private[0] == SYS_TTY_CLASS ||
        directory->fs_private[0] == SYS_DEVICES_VIRTUAL_TTY) {
        uint32_t count = kernel_console_device_count();
        if (position >= count ||
            kernel_console_device_at(position, &console_device) < 0)
            return -1;
        if (directory->fs_private[0] == SYS_TTY_CLASS) {
            strcpy(name, console_device.name);
            inode_set(out, SYS_TTY_NODE(position, TTY_NODE_CLASS),
                      VFS_INODE_LNK | 0777);
        } else if (directory->fs_private[0] == SYS_DEVICES_VIRTUAL_TTY) {
            strcpy(name, console_device.name);
            inode_set(out, SYS_TTY_NODE(position, TTY_NODE_ROOT),
                      VFS_INODE_DIR | 0555);
        }
        return 0;
    }
    if (directory->fs_private[0] == SYS_DEV_CHAR) {
        uint32_t tty_count = kernel_console_device_count();
        uint32_t input_count = sys_input_device_count();
        uint32_t relative;
        uint32_t length;
        if (position < tty_count) {
            if (kernel_console_device_at(position, &console_device) < 0)
                return -1;
            length = append_device_number(name, 24u, 0u, &console_device);
            name[length] = 0;
            inode_set(out, SYS_TTY_DEV_CHAR_NODE(position),
                      VFS_INODE_LNK | 0777);
            return 0;
        }
        relative = position - tty_count;
        if (fb.addr && fb.width && fb.height) {
            if (relative == 0u) {
                strcpy(name, "29:0");
                inode_set(out, SYS_FB_DEV_CHAR, VFS_INODE_LNK | 0777);
                return 0;
            }
            --relative;
            if (relative == 0u) {
                strcpy(name, "226:0");
                inode_set(out, SYS_DRM_CARD0_DEV_CHAR,
                          VFS_INODE_LNK | 0777);
                return 0;
            }
            --relative;
        }
        if (sys_drm_render_available()) {
            if (relative == 0u) {
                strcpy(name, "226:128");
                inode_set(out, SYS_DRM_RENDERD128_DEV_CHAR,
                          VFS_INODE_LNK | 0777);
                return 0;
            }
            --relative;
        }
        if (relative < input_count) {
            if (sys_input_device_at_ordinal(relative, &device) < 0)
                return -1;
            length = append_text(name, VFS_NAME_MAX, 0u, "13:");
            length = append_u32(
                name, VFS_NAME_MAX, length, 64u + device);
            name[length] = 0;
            inode_set(out, SYS_INPUT_DEV_CHAR_BASE + device,
                      VFS_INODE_LNK | 0777);
            return 0;
        }
        relative -= input_count;
#ifdef CONFIG_BSD_DRIVER_BRIDGE
        {
            bsd_bridge_cdev_node_t bsd_node;

            if (sys_bsd_cdev_at_unique_ordinal(
                relative, &bsd_node) != 0)
                return -1;
            length = append_u32(name, VFS_NAME_MAX, 0,
                bsd_node.major);
            length = append_text(name, VFS_NAME_MAX, length, ":");
            length = append_u32(name, VFS_NAME_MAX, length,
                bsd_node.minor);
            name[length] = 0;
            inode_set_bsd_cdev(out, &bsd_node,
                SYS_BSD_CDEV_DEV_CHAR, VFS_INODE_LNK | 0777);
            return 0;
        }
#else
        return -1;
#endif
    }
    if (sys_tty_node(directory->fs_private[0], &device, &attribute) &&
        attribute == TTY_NODE_ROOT) {
        static const char *const attributes[] = {
            "dev", "uevent", "subsystem", "active"
        };
        uint32_t count = sys_console_device_has_active(device) ? 4u : 3u;
        static const uint32_t nodes[] = {
            TTY_NODE_DEV, TTY_NODE_UEVENT, TTY_NODE_SUBSYSTEM,
            TTY_NODE_ACTIVE
        };
        static const uint16_t modes[] = {
            VFS_INODE_FILE | 0444, VFS_INODE_FILE | 0644,
            VFS_INODE_LNK | 0777, VFS_INODE_FILE | 0444
        };
        if (position >= count) return -1;
        strcpy(name, attributes[position]);
        inode_set(out, SYS_TTY_NODE(device, nodes[position]), modes[position]);
        return 0;
    }
    for (uint32_t index = 0; index < sizeof(g_entries) / sizeof(g_entries[0]); ++index) {
        const sys_entry_t *entry = &g_entries[index];
        if (entry->parent != directory->fs_private[0]) continue;
        if (!sys_node_available(entry->node)) continue;
        if (found++ != position) continue;
        strcpy(name, entry->name);
        inode_set(out, entry->node, entry->mode);
        return 0;
    }
    return -1;
}

static int sys_statfs(vfs_superblock_t *sb, uint32_t *total, uint32_t *used) {
    (void)sb;
    if (!total || !used) return -1;
    *total = 0;
    *used = 0;
    return 0;
}

static filesystem_ops_t g_sys_ops = {
    .lookup = sys_lookup,
    .read = sys_read,
    .write = sys_write,
    .readlink = sys_readlink,
    .readdir = sys_readdir,
    .statfs = sys_statfs,
};

int sysfs_mount(const char *device, const char *target) {
    if (!target || vfs_mount_exists(target, "sysfs",
            device && device[0] ? device : "sysfs")) return target ? 0 : -1;
    memset(&g_sys_sb, 0, sizeof(g_sys_sb));
    strcpy(g_sys_sb.fs_name, "sysfs");
    strcpy(g_sys_sb.dev_name, device && device[0] ? device : "sysfs");
    strcpy(g_sys_sb.mountpoint, target);
    inode_set(&g_sys_sb.root, SYS_ROOT, VFS_INODE_DIR | 0555);
    g_sys_sb.ops = &g_sys_ops;
    return vfs_add_superblock(&g_sys_sb);
}
