/* SPDX-License-Identifier: MPL-2.0 */
/* Original architecture-independent EdgeOS procfs implementation. */

#include <stdint.h>
#include "block/block.h"
#include "block/device_mapper.h"
#include "dev/alsa.h"
#include "vfs/vfs.h"
#include "string.h"
#include "sys/boottime.h"
#include "mm/arch_vm.h"
#include "kernel/arch_cpu.h"
#include "kernel/boot_command_line.h"
#include "kernel/console_device.h"
#include "kernel/fd_runtime.h"
#include "kernel/linux_module.h"
#include "kernel/namespaces.h"
#include "kernel/namespace_runtime.h"
#include "kernel/proc_platform.h"
#include "kernel/proc_memory.h"
#include "kernel/proc_maps.h"
#include "kernel/process_runtime.h"
#include "kernel/smp.h"
#include "kernel/vfs_runtime.h"
#include "net/lwip_stack.h"
#include "net/network_core.h"
#include "fs/proc_sysctl.h"
#include "fs/cgroupfs.h"
#include "fs/swap.h"
#include "fs/tmpfs.h"
#include "serial_console.h"
#include "stdio.h"
#include "sys/bootlog.h"

#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/cdev.h"
#endif


enum {
    PROC_ROOT = 1,
    PROC_MOUNTS,
    PROC_MOUNTINFO,
    PROC_FILESYSTEMS,
    PROC_DEVICES,
    PROC_CMDLINE,
    PROC_VERSION,
    PROC_UPTIME,
    PROC_MEMINFO,
    PROC_VMSTAT,
    PROC_ZONEINFO,
    PROC_BUDDYINFO,
    PROC_PAGETYPEINFO,
    PROC_PRESSURE,
    PROC_PRESSURE_MEMORY,
    PROC_CPUINFO,
    PROC_STAT,
    PROC_SCHEDSTAT,
    PROC_SELF,
    PROC_SELF_EXE,
    PROC_SELF_FD,
    PROC_SELF_FD_ENTRY,
    PROC_SELF_FDINFO,
    PROC_SELF_FDINFO_ENTRY,
    PROC_PID_DIR,
    PROC_PID_STAT,
    PROC_PID_STATM,
    PROC_PID_STATUS,
    PROC_PID_SCHED,
    PROC_PID_SCHEDSTAT,
    PROC_PID_CMDLINE,
    PROC_PID_ENVIRON,
    PROC_PID_EXE,
    PROC_PID_CWD,
    PROC_PID_ROOT,
    PROC_PID_SYSCALL,
    PROC_PID_TASK,
    PROC_THREAD_DIR,
    PROC_SYS,
    PROC_SYS_KERNEL,
    PROC_OVERFLOWUID,
    PROC_OVERFLOWGID,
    PROC_SELF_NS,
    PROC_PID_NS,
    PROC_NS_LINK,
    PROC_NET_DIR,
    PROC_NET_DEV,
    PROC_NET_ARP,
    PROC_NET_IF_INET6,
    PROC_NET_IPV6_ROUTE,
    PROC_NET_SNMP6,
    PROC_CGROUPS,
    PROC_PID_CGROUP,
    PROC_PID_OOM_SCORE_ADJ,
    PROC_HOSTNAME,
    PROC_DOMAINNAME,
    PROC_SYS_KERNEL_RANDOM,
    PROC_BOOT_ID,
    PROC_PID_UID_MAP,
    PROC_PID_GID_MAP,
    PROC_PID_SETGROUPS,
    PROC_SYS_FS,
    PROC_FILE_MAX,
    PROC_NR_OPEN,
    PROC_PID_MAPS,
    PROC_PID_SMAPS,
    PROC_PID_SMAPS_ROLLUP,
    PROC_SYS_FS_INOTIFY,
    PROC_INOTIFY_MAX_QUEUED_EVENTS,
    PROC_INOTIFY_MAX_USER_INSTANCES,
    PROC_INOTIFY_MAX_USER_WATCHES,
    PROC_SWAPS,
    PROC_LOADAVG,
    PROC_KMSG,
    PROC_IOPORTS,
    PROC_PID_COMM,
    PROC_TTY,
    PROC_TTY_DRIVER,
    PROC_TTY_DRIVERS,
    PROC_TTY_LDISCS,
    PROC_TTY_SERIAL,
    PROC_ASOUND,
    PROC_ASOUND_CARDS,
    PROC_ASOUND_DEVICES,
    PROC_ASOUND_PCM,
    PROC_ASOUND_VERSION,
    PROC_ASOUND_TIMERS,
    PROC_ASOUND_CARD0,
    PROC_ASOUND_CARD0_ID,
    PROC_ASOUND_PCM0P,
    PROC_ASOUND_PCM0P_INFO,
    PROC_ASOUND_PCM0P_SUB0,
    PROC_ASOUND_PCM0P_SUB0_INFO,
    PROC_ASOUND_PCM0P_SUB0_STATUS,
    PROC_ASOUND_PCM0P_SUB0_HW_PARAMS,
    PROC_ASOUND_PCM0C,
    PROC_ASOUND_PCM0C_INFO,
    PROC_ASOUND_PCM0C_SUB0,
    PROC_ASOUND_PCM0C_SUB0_INFO,
    PROC_ASOUND_PCM0C_SUB0_STATUS,
    PROC_ASOUND_PCM0C_SUB0_HW_PARAMS,
    PROC_SYS_NET,
    PROC_SYS_NET_BRIDGE,
    PROC_BRIDGE_NF_CALL_IPTABLES,
    PROC_BRIDGE_NF_CALL_IP6TABLES,
    PROC_BRIDGE_NF_CALL_ARPTABLES,
    PROC_SYS_NET_IPV4,
    PROC_SYS_NET_IPV6,
    PROC_SYS_NET_IPV6_CONF,
    PROC_SYS_NET_IPV6_CONF_SCOPE,
    PROC_SYS_NET_IPV6_CONF_VALUE,
    PROC_IP_FORWARD,
    PROC_IP_LOCAL_PORT_RANGE,
    PROC_THREADS_MAX,
    PROC_OSTYPE,
    PROC_OSRELEASE,
    PROC_KERNEL_VERSION,
    PROC_SYS_KERNEL_KEYS,
    PROC_ROOT_MAXKEYS,
    PROC_MODULES,
    PROC_DISKSTATS
};

static const char *const g_namespace_names[] = {
    "cgroup", "ipc", "mnt", "net", "pid", "pid_for_children",
    "time", "time_for_children", "user", "uts"
};

static vfs_superblock_t g_proc_sb;
#define PROC_STATUS_SNAPSHOT_CAPACITY \
    ((EDGE_LINUX_NGROUPS_MAX * 11u) + 65536u)
#define PROC_SNAPSHOT_CAPACITY PROC_STATUS_SNAPSHOT_CAPACITY
typedef struct {
    char bytes[PROC_SNAPSHOT_CAPACITY];
    uint64_t guard[4];
} proc_snapshot_storage_t;
static proc_snapshot_storage_t g_proc_snapshot;
static edge_page_allocator_snapshot_t g_proc_page_allocator_snapshot;
static edge_mm_statistics_snapshot_t g_proc_mm_statistics_snapshot;
static volatile uint32_t g_proc_read_lock;
static uint32_t g_proc_guard_armed;

static uint32_t proc_net_current_namespace(void) {
    edge_namespace_set_t *namespaces = kernel_arch_current_namespace_set();

    return namespaces ? namespaces->net : 0u;
}

int procfs_guard_valid(void) {
    if (!g_proc_guard_armed) return 1;
    for (uint32_t i = 0; i < 4u; ++i)
        if (g_proc_snapshot.guard[i] != (0x4544474550524f43ULL ^ i)) return 0;
    return 1;
}

static void inode_set(vfs_inode_t *inode, uint32_t node, uint16_t mode) {
    memset(inode, 0, sizeof(*inode));
    inode->ino = 0xf1000000u | node;
    inode->mode = mode;
    inode->nlink = 1;
    inode->nlink_valid = 1;
    inode->fs_private[0] = node;
}

static void inode_set_pid(vfs_inode_t *inode, uint32_t node, int32_t pid,
                          uint16_t mode) {
    inode_set(inode, node, mode);
    inode->ino ^= (uint32_t)pid * 131u;
    inode->fs_private[1] = (uint32_t)pid;
}

static void inode_set_ipv6_conf_scope(vfs_inode_t *inode,
                                      lwip_ipv6_scope_t scope) {
    inode_set(inode, PROC_SYS_NET_IPV6_CONF_SCOPE,
              VFS_INODE_DIR | 0555);
    inode->fs_private[1] = (uint32_t)scope;
    inode->ino ^= ((uint32_t)scope + 1u) * 131u;
}

static void inode_set_ipv6_conf_value(vfs_inode_t *inode,
                                      lwip_ipv6_scope_t scope,
                                      lwip_ipv6_setting_t setting) {
    inode_set(inode, PROC_SYS_NET_IPV6_CONF_VALUE,
              VFS_INODE_FILE | 0644);
    inode->fs_private[1] = (uint32_t)scope;
    inode->fs_private[2] = (uint32_t)setting;
    inode->ino ^= (((uint32_t)scope + 1u) * 131u) ^
                  (((uint32_t)setting + 1u) * 977u);
}

static void inode_set_task_directory(vfs_inode_t *inode, int32_t tgid) {
    uint32_t threads = 0;
    int32_t tid;

    inode_set_pid(inode, PROC_PID_TASK, tgid, VFS_INODE_DIR | 0555);
    while (kernel_proc_thread_at(tgid, threads, &tid) == 0) ++threads;
    /* Linux procfs counts '.' and the parent plus one link per live thread. */
    inode->nlink = 2u + threads;
    inode->nlink_valid = 1u;
}

static void inode_set_namespace(vfs_inode_t *inode, int32_t pid, uint32_t kind) {
    uint64_t identity;
    inode_set_pid(inode, PROC_NS_LINK, pid, VFS_INODE_LNK | 0777);
    inode->fs_private[2] = kind;
    if (arch_proc_namespace_inode(pid, kind, &identity) == 0)
        inode->ino = (uint32_t)identity;
}

static int parse_pid(const char *name, int32_t *pid_out) {
    uint32_t value = 0;
    if (!name || !name[0] || !pid_out) return -1;
    for (uint32_t i = 0; name[i]; ++i) {
        if (name[i] < '0' || name[i] > '9' || value > 100000000u) return -1;
        value = value * 10u + (uint32_t)(name[i] - '0');
    }
    if (!value) return -1;
    *pid_out = (int32_t)value;
    return 0;
}

static int parse_fd(const char *name, int32_t *fd_out) {
    uint32_t value = 0;
    if (!name || !name[0] || !fd_out) return -1;
    for (uint32_t i = 0; name[i]; ++i) {
        if (name[i] < '0' || name[i] > '9' || value > 100000000u)
            return -1;
        value = value * 10u + (uint32_t)(name[i] - '0');
    }
    *fd_out = (int32_t)value;
    return 0;
}

static int32_t proc_current_tgid(void) {
    kernel_linux_identity_t identity;

    if (kernel_current_linux_identity(&identity) < 0) return -1;
    /*
     * This superblock is the procfs instance mounted by the initial PID
     * namespace.  Linux resolves its self link in that mount's PID view, so a
     * process in a descendant namespace still addresses its global task ID
     * through the inherited mount.  The shared proc task APIs also consume
     * global IDs; passing the descendant-visible TGID made /proc/self vanish
     * for sandbox children whose local PID happened not to exist globally.
     */
    return identity.global_tgid;
}

static int text_eq(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == 0 && *b == 0;
}

static int append(char *out, uint32_t cap, uint32_t *length, const char *text) {
    while (*text) {
        if (*length + 1u >= cap) return -1;
        out[(*length)++] = *text++;
    }
    out[*length] = 0;
    return 0;
}

static int append_u64(char *out, uint32_t cap, uint32_t *length, uint64_t value) {
    char digits[24];
    uint32_t count = 0;
    if (!value) digits[count++] = '0';
    while (value) {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count) {
        char byte[2] = { digits[--count], 0 };
        if (append(out, cap, length, byte) < 0) return -1;
    }
    return 0;
}

static int append_hundredths(char *out, uint32_t cap, uint32_t *length,
                             uint32_t value) {
    char fraction[3] = {
        (char)('0' + (value / 10u) % 10u),
        (char)('0' + value % 10u),
        0
    };

    return append_u64(out, cap, length, value / 100u) < 0 ||
           append(out, cap, length, ".") < 0 ||
           append(out, cap, length, fraction) < 0 ? -1 : 0;
}

static int proc_append_device(char *out, uint32_t capacity,
                              uint32_t *length, uint32_t major,
                              const char *name) {
    if (append_u64(out, capacity, length, major) < 0 ||
        append(out, capacity, length, " ") < 0 ||
        append(out, capacity, length, name) < 0 ||
        append(out, capacity, length, "\n") < 0)
        return -1;
    return 0;
}

static int proc_generate_devices(char *out, uint32_t capacity,
                                 uint32_t *length) {
    static const struct {
        uint32_t major;
        const char *name;
    } character_devices[] = {
        { 1u, "mem" },
        { 4u, "tty" },
        { 5u, "/dev/tty" },
        { 10u, "misc" },
        { 13u, "input" },
        { 14u, "sound" },
        { 29u, "fb" },
        { 81u, "video4linux" },
        { EDGE_ALSA_CARD_MAJOR, "alsa" },
        { 136u, "pts" },
#if defined(__aarch64__) || defined(_M_ARM64)
        { 204u, "ttyAMA" },
#endif
        { 226u, "drm" },
    };
    int have_ramdisk = 0;
    int have_disk = 0;

    if (append(out, capacity, length, "Character devices:\n") < 0)
        return -1;
    for (uint32_t index = 0;
         index < sizeof(character_devices) / sizeof(character_devices[0]);
         ++index) {
        if (proc_append_device(out, capacity, length,
                               character_devices[index].major,
                               character_devices[index].name) < 0)
            return -1;
    }
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    {
        uint32_t seen[128];
        uint32_t seen_count = 0;
        uint32_t count = bsd_bridge_cdev_node_count();

        if (count > sizeof(seen) / sizeof(seen[0]))
            count = sizeof(seen) / sizeof(seen[0]);
        for (uint32_t index = 0; index < count; ++index) {
            bsd_bridge_cdev_node_t node;
            int duplicate = 0;

            if (bsd_bridge_cdev_node_at(index, &node) < 0 || node.alias)
                continue;
            for (uint32_t known = 0; known < seen_count; ++known) {
                if (seen[known] == node.major) {
                    duplicate = 1;
                    break;
                }
            }
            if (duplicate) continue;
            seen[seen_count++] = node.major;
            if (proc_append_device(out, capacity, length,
                                   node.major, node.name) < 0)
                return -1;
        }
    }
#endif

    for (int index = 0; index < block_count(); ++index) {
        block_device_t *device = block_get(index);
        uint32_t major;
        uint32_t minor;

        if (!device || !device->present ||
            block_linux_major_minor(device, &major, &minor) < 0)
            continue;
        if (major == 1u) have_ramdisk = 1;
        if (major == 8u) have_disk = 1;
    }
    if (append(out, capacity, length, "\nBlock devices:\n") < 0)
        return -1;
    if (have_ramdisk &&
        proc_append_device(out, capacity, length, 1u, "ramdisk") < 0)
        return -1;
    if (have_disk &&
        proc_append_device(out, capacity, length, 8u, "sd") < 0)
        return -1;
#ifdef CONFIG_LOOP_DEVICE
    if (proc_append_device(out, capacity, length, 7u, "loop") < 0)
        return -1;
#endif
#ifdef CONFIG_DEVICE_MAPPER
    if (proc_append_device(out, capacity, length,
                           EDGE_DM_BLOCK_MAJOR, "device-mapper") < 0)
        return -1;
#endif
    return 0;
}

static int append_octal_u32(char *out, uint32_t cap, uint32_t *length,
                            uint32_t value) {
    char digits[16];
    uint32_t count = 0;
    if (!value) digits[count++] = '0';
    while (value) {
        digits[count++] = (char)('0' + (value & 7u));
        value >>= 3u;
    }
    while (count) {
        char byte[2] = { digits[--count], 0 };
        if (append(out, cap, length, byte) < 0) return -1;
    }
    return 0;
}

static int append_s64(char *out, uint32_t cap, uint32_t *length,
                      int64_t value) {
    uint64_t magnitude;

    if (value >= 0) return append_u64(out, cap, length, (uint64_t)value);
    if (append(out, cap, length, "-") < 0) return -1;
    magnitude = (uint64_t)(-(value + 1)) + 1u;
    return append_u64(out, cap, length, magnitude);
}

static int append_task_credentials(char *out, uint32_t cap,
                                   uint32_t *length,
                                   const kernel_proc_task_snapshot_t *task) {
    linux_group_list_t groups;
    int result = -1;

    if (!task) return -1;
    linux_group_list_init(&groups);
    if (kernel_process_groups_snapshot(task->pid, &groups) < 0)
        goto credentials_out;
    if (append(out, cap, length, "\nUid:\t") < 0 ||
        append_u64(out, cap, length, task->uid) < 0 ||
        append(out, cap, length, "\t") < 0 ||
        append_u64(out, cap, length, task->euid) < 0 ||
        append(out, cap, length, "\t") < 0 ||
        append_u64(out, cap, length, task->suid) < 0 ||
        append(out, cap, length, "\t") < 0 ||
        append_u64(out, cap, length, task->fsuid) < 0 ||
        append(out, cap, length, "\nGid:\t") < 0 ||
        append_u64(out, cap, length, task->gid) < 0 ||
        append(out, cap, length, "\t") < 0 ||
        append_u64(out, cap, length, task->egid) < 0 ||
        append(out, cap, length, "\t") < 0 ||
        append_u64(out, cap, length, task->sgid) < 0 ||
        append(out, cap, length, "\t") < 0 ||
        append_u64(out, cap, length, task->fsgid) < 0 ||
        append(out, cap, length, "\nGroups:\t") < 0)
        goto credentials_out;
    for (uint32_t index = 0; index < groups.count; ++index) {
        if (append_u64(out, cap, length,
                       linux_group_list_get(&groups, index)) < 0 ||
            append(out, cap, length, " ") < 0)
            goto credentials_out;
    }
    result = append(out, cap, length, "\n");

credentials_out:
    linux_group_list_release(&groups);
    return result;
}

static int append_hex_byte(char *out, uint32_t cap, uint32_t *length,
                           uint8_t value) {
    static const char digits[] = "0123456789abcdef";
    char text[3] = { digits[value >> 4], digits[value & 0x0fu], 0 };
    return append(out, cap, length, text);
}

static int append_hex_u32(char *out, uint32_t cap, uint32_t *length,
                          uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        if (append_hex_byte(out, cap, length,
                            (uint8_t)(value >> shift)) < 0)
            return -1;
    return 0;
}

static int append_ipv6_hex(char *out, uint32_t cap, uint32_t *length,
                           const uint8_t address[16]) {
    for (uint32_t index = 0; index < 16u; ++index)
        if (append_hex_byte(out, cap, length, address[index]) < 0)
            return -1;
    return 0;
}

static int append_ipv4(char *out, uint32_t cap, uint32_t *length,
                       uint32_t address_be) {
    const uint8_t *octets = (const uint8_t *)&address_be;
    for (uint32_t index = 0; index < 4u; ++index) {
        if (index && append(out, cap, length, ".") < 0) return -1;
        if (append_u64(out, cap, length, octets[index]) < 0) return -1;
    }
    return 0;
}

static int proc_lookup(vfs_superblock_t *sb, vfs_inode_t *dir,
                       const char *name, vfs_inode_t *out) {
    uint32_t node;
    (void)sb;
    if (!dir || !name || !out) return -1;
    node = dir->fs_private[0];
    if (node == PROC_ROOT) {
        int32_t pid;
        if (text_eq(name, "mounts")) inode_set(out, PROC_MOUNTS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "mountinfo")) inode_set(out, PROC_MOUNTINFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "filesystems")) inode_set(out, PROC_FILESYSTEMS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "devices")) inode_set(out, PROC_DEVICES, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "cmdline")) inode_set(out, PROC_CMDLINE, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "version")) inode_set(out, PROC_VERSION, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "cgroups")) inode_set(out, PROC_CGROUPS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "uptime")) inode_set(out, PROC_UPTIME, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "meminfo")) inode_set(out, PROC_MEMINFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "vmstat")) inode_set(out, PROC_VMSTAT, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "zoneinfo")) inode_set(out, PROC_ZONEINFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "buddyinfo")) inode_set(out, PROC_BUDDYINFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "pagetypeinfo")) inode_set(out, PROC_PAGETYPEINFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "pressure"))
            inode_set(out, PROC_PRESSURE, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "cpuinfo")) inode_set(out, PROC_CPUINFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "stat")) inode_set(out, PROC_STAT, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "schedstat")) inode_set(out, PROC_SCHEDSTAT, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "loadavg")) inode_set(out, PROC_LOADAVG, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "swaps")) inode_set(out, PROC_SWAPS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "kmsg")) inode_set(out, PROC_KMSG, VFS_INODE_FILE | 0400);
        else if (text_eq(name, "ioports")) inode_set(out, PROC_IOPORTS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "modules")) inode_set(out, PROC_MODULES, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "diskstats")) inode_set(out, PROC_DISKSTATS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "net")) inode_set(out, PROC_NET_DIR, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "tty")) inode_set(out, PROC_TTY, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "asound") && arch_proc_sound_available())
            inode_set(out, PROC_ASOUND, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "sys")) inode_set(out, PROC_SYS, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "self")) {
            inode_set(out, PROC_SELF, VFS_INODE_LNK | 0777);
            out->size = 16u;
        }
        else if (parse_pid(name, &pid) == 0) {
            kernel_proc_task_view_t view;
            if (kernel_proc_task_view_get(pid, &view) < 0) return -1;
            inode_set_pid(out, PROC_PID_DIR, pid, VFS_INODE_DIR | 0555);
        } else return -1;
        return 0;
    }
    if (node == PROC_PRESSURE) {
        if (!text_eq(name, "memory")) return -1;
        inode_set(out, PROC_PRESSURE_MEMORY, VFS_INODE_FILE | 0444);
        return 0;
    }
    if (node == PROC_NET_DIR) {
        if (text_eq(name, "dev")) inode_set(out, PROC_NET_DEV, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "arp")) inode_set(out, PROC_NET_ARP, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "if_inet6"))
            inode_set(out, PROC_NET_IF_INET6, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "ipv6_route"))
            inode_set(out, PROC_NET_IPV6_ROUTE, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "snmp6"))
            inode_set(out, PROC_NET_SNMP6, VFS_INODE_FILE | 0444);
        else return -1;
        return 0;
    }
    if (node == PROC_TTY) {
        if (text_eq(name, "driver"))
            inode_set(out, PROC_TTY_DRIVER, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "drivers"))
            inode_set(out, PROC_TTY_DRIVERS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "ldiscs"))
            inode_set(out, PROC_TTY_LDISCS, VFS_INODE_FILE | 0444);
        else return -1;
        return 0;
    }
    if (node == PROC_TTY_DRIVER) {
        if (!text_eq(name, "serial")) return -1;
        inode_set(out, PROC_TTY_SERIAL, VFS_INODE_FILE | 0444);
        return 0;
    }
    if (node == PROC_ASOUND) {
        if (!arch_proc_sound_available()) return -1;
        if (text_eq(name, "cards"))
            inode_set(out, PROC_ASOUND_CARDS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "devices"))
            inode_set(out, PROC_ASOUND_DEVICES, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "pcm"))
            inode_set(out, PROC_ASOUND_PCM, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "version"))
            inode_set(out, PROC_ASOUND_VERSION, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "timers"))
            inode_set(out, PROC_ASOUND_TIMERS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "card0"))
            inode_set(out, PROC_ASOUND_CARD0, VFS_INODE_DIR | 0555);
        else return -1;
        return 0;
    }
    if (node == PROC_ASOUND_CARD0) {
        if (!arch_proc_sound_available()) return -1;
        if (text_eq(name, "id"))
            inode_set(out, PROC_ASOUND_CARD0_ID, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "pcm0p") && alsa_playback_available())
            inode_set(out, PROC_ASOUND_PCM0P, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "pcm0c") && alsa_capture_available())
            inode_set(out, PROC_ASOUND_PCM0C, VFS_INODE_DIR | 0555);
        else return -1;
        return 0;
    }
    if (node == PROC_ASOUND_PCM0P) {
        if (!alsa_playback_available()) return -1;
        if (text_eq(name, "info"))
            inode_set(out, PROC_ASOUND_PCM0P_INFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "sub0"))
            inode_set(out, PROC_ASOUND_PCM0P_SUB0, VFS_INODE_DIR | 0555);
        else return -1;
        return 0;
    }
    if (node == PROC_ASOUND_PCM0P_SUB0) {
        if (!alsa_playback_available()) return -1;
        if (text_eq(name, "info"))
            inode_set(out, PROC_ASOUND_PCM0P_SUB0_INFO,
                      VFS_INODE_FILE | 0444);
        else if (text_eq(name, "status"))
            inode_set(out, PROC_ASOUND_PCM0P_SUB0_STATUS,
                      VFS_INODE_FILE | 0444);
        else if (text_eq(name, "hw_params"))
            inode_set(out, PROC_ASOUND_PCM0P_SUB0_HW_PARAMS,
                      VFS_INODE_FILE | 0444);
        else return -1;
        return 0;
    }
    if (node == PROC_ASOUND_PCM0C) {
        if (!alsa_capture_available()) return -1;
        if (text_eq(name, "info"))
            inode_set(out, PROC_ASOUND_PCM0C_INFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "sub0"))
            inode_set(out, PROC_ASOUND_PCM0C_SUB0, VFS_INODE_DIR | 0555);
        else return -1;
        return 0;
    }
    if (node == PROC_ASOUND_PCM0C_SUB0) {
        if (!alsa_capture_available()) return -1;
        if (text_eq(name, "info"))
            inode_set(out, PROC_ASOUND_PCM0C_SUB0_INFO,
                      VFS_INODE_FILE | 0444);
        else if (text_eq(name, "status"))
            inode_set(out, PROC_ASOUND_PCM0C_SUB0_STATUS,
                      VFS_INODE_FILE | 0444);
        else if (text_eq(name, "hw_params"))
            inode_set(out, PROC_ASOUND_PCM0C_SUB0_HW_PARAMS,
                      VFS_INODE_FILE | 0444);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS) {
        if (text_eq(name, "kernel")) inode_set(out, PROC_SYS_KERNEL, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "fs")) inode_set(out, PROC_SYS_FS, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "net")) inode_set(out, PROC_SYS_NET, VFS_INODE_DIR | 0555);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_NET) {
        if (text_eq(name, "bridge"))
            inode_set(out, PROC_SYS_NET_BRIDGE, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "ipv4"))
            inode_set(out, PROC_SYS_NET_IPV4, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "ipv6"))
            inode_set(out, PROC_SYS_NET_IPV6, VFS_INODE_DIR | 0555);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_NET_BRIDGE) {
        if (text_eq(name, "bridge-nf-call-iptables"))
            inode_set(out, PROC_BRIDGE_NF_CALL_IPTABLES,
                      VFS_INODE_FILE | 0644);
        else if (text_eq(name, "bridge-nf-call-ip6tables"))
            inode_set(out, PROC_BRIDGE_NF_CALL_IP6TABLES,
                      VFS_INODE_FILE | 0644);
        else if (text_eq(name, "bridge-nf-call-arptables"))
            inode_set(out, PROC_BRIDGE_NF_CALL_ARPTABLES,
                      VFS_INODE_FILE | 0644);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_NET_IPV4) {
        if (text_eq(name, "ip_forward"))
            inode_set(out, PROC_IP_FORWARD, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "ip_local_port_range"))
            inode_set(out, PROC_IP_LOCAL_PORT_RANGE, VFS_INODE_FILE | 0644);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_NET_IPV6) {
        if (text_eq(name, "conf"))
            inode_set(out, PROC_SYS_NET_IPV6_CONF,
                      VFS_INODE_DIR | 0555);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_NET_IPV6_CONF) {
        int32_t ifindex;

        if (text_eq(name, "all"))
            inode_set_ipv6_conf_scope(out, LWIP_IPV6_SCOPE_ALL);
        else if (text_eq(name, "default"))
            inode_set_ipv6_conf_scope(out, LWIP_IPV6_SCOPE_DEFAULT);
        else if (text_eq(name, "lo"))
            inode_set_ipv6_conf_scope(
                out, LWIP_IPV6_SCOPE_FOR_IFINDEX(1));
        else if (edge_net_device_find(
                     proc_net_current_namespace(), name, &ifindex) ==
                 EDGE_NET_OK)
            inode_set_ipv6_conf_scope(
                out, LWIP_IPV6_SCOPE_FOR_IFINDEX(ifindex));
        else if (text_eq(name, "eth0"))
            inode_set_ipv6_conf_scope(
                out, LWIP_IPV6_SCOPE_FOR_IFINDEX(2));
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_NET_IPV6_CONF_SCOPE) {
        lwip_ipv6_setting_t setting;

        if (text_eq(name, "disable_ipv6"))
            setting = LWIP_IPV6_SETTING_DISABLE;
        else if (text_eq(name, "forwarding"))
            setting = LWIP_IPV6_SETTING_FORWARDING;
        else if (text_eq(name, "accept_ra"))
            setting = LWIP_IPV6_SETTING_ACCEPT_RA;
        else if (text_eq(name, "autoconf"))
            setting = LWIP_IPV6_SETTING_AUTOCONF;
        else return -1;
        inode_set_ipv6_conf_value(
            out, (lwip_ipv6_scope_t)dir->fs_private[1], setting);
        return 0;
    }
    if (node == PROC_SYS_FS) {
        if (text_eq(name, "file-max"))
            inode_set(out, PROC_FILE_MAX, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "nr_open"))
            inode_set(out, PROC_NR_OPEN, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "inotify"))
            inode_set(out, PROC_SYS_FS_INOTIFY, VFS_INODE_DIR | 0555);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_FS_INOTIFY) {
        if (text_eq(name, "max_queued_events"))
            inode_set(out, PROC_INOTIFY_MAX_QUEUED_EVENTS,
                      VFS_INODE_FILE | 0644);
        else if (text_eq(name, "max_user_instances"))
            inode_set(out, PROC_INOTIFY_MAX_USER_INSTANCES,
                      VFS_INODE_FILE | 0644);
        else if (text_eq(name, "max_user_watches"))
            inode_set(out, PROC_INOTIFY_MAX_USER_WATCHES,
                      VFS_INODE_FILE | 0644);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_KERNEL) {
        if (text_eq(name, "overflowuid"))
            inode_set(out, PROC_OVERFLOWUID, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "overflowgid"))
            inode_set(out, PROC_OVERFLOWGID, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "hostname"))
            inode_set(out, PROC_HOSTNAME, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "domainname"))
            inode_set(out, PROC_DOMAINNAME, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "threads-max"))
            inode_set(out, PROC_THREADS_MAX, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "ostype"))
            inode_set(out, PROC_OSTYPE, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "osrelease"))
            inode_set(out, PROC_OSRELEASE, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "version"))
            inode_set(out, PROC_KERNEL_VERSION, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "keys"))
            inode_set(out, PROC_SYS_KERNEL_KEYS, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "random"))
            inode_set(out, PROC_SYS_KERNEL_RANDOM, VFS_INODE_DIR | 0555);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_KERNEL_KEYS) {
        if (text_eq(name, "root_maxkeys"))
            inode_set(out, PROC_ROOT_MAXKEYS, VFS_INODE_FILE | 0644);
        else return -1;
        return 0;
    }
    if (node == PROC_SYS_KERNEL_RANDOM) {
        if (text_eq(name, "boot_id"))
            inode_set(out, PROC_BOOT_ID, VFS_INODE_FILE | 0444);
        else return -1;
        return 0;
    }
    if (node == PROC_SELF) {
        int32_t pid = proc_current_tgid();
        if (pid <= 0) return -1;
        if (text_eq(name, "exe")) inode_set(out, PROC_SELF_EXE, VFS_INODE_LNK | 0777);
        else if (text_eq(name, "fd"))
            inode_set_pid(out, PROC_SELF_FD, pid,
                          VFS_INODE_DIR | 0555);
        else if (text_eq(name, "fdinfo"))
            inode_set_pid(out, PROC_SELF_FDINFO, pid,
                          VFS_INODE_DIR | 0555);
        else if (text_eq(name, "ns")) inode_set_pid(out, PROC_SELF_NS, pid, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "mounts")) inode_set(out, PROC_MOUNTS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "mountinfo")) inode_set(out, PROC_MOUNTINFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "stat")) inode_set_pid(out, PROC_PID_STAT, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "statm")) inode_set_pid(out, PROC_PID_STATM, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "status")) inode_set_pid(out, PROC_PID_STATUS, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "sched")) inode_set_pid(out, PROC_PID_SCHED, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "schedstat")) inode_set_pid(out, PROC_PID_SCHEDSTAT, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "maps")) inode_set_pid(out, PROC_PID_MAPS, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "smaps")) inode_set_pid(out, PROC_PID_SMAPS, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "smaps_rollup")) inode_set_pid(out, PROC_PID_SMAPS_ROLLUP, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "cmdline")) inode_set_pid(out, PROC_PID_CMDLINE, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "comm")) inode_set_pid(out, PROC_PID_COMM, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "environ")) inode_set_pid(out, PROC_PID_ENVIRON, pid, VFS_INODE_FILE | 0400);
        else if (text_eq(name, "cwd")) inode_set_pid(out, PROC_PID_CWD, pid, VFS_INODE_LNK | 0777);
        else if (text_eq(name, "root")) inode_set_pid(out, PROC_PID_ROOT, pid, VFS_INODE_LNK | 0777);
        else if (text_eq(name, "syscall")) inode_set_pid(out, PROC_PID_SYSCALL, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "task")) {
            kernel_proc_task_view_t view;
            int32_t tgid;

            if (kernel_proc_task_view_get(pid, &view) < 0) return -1;
            tgid = view.tgid > 0 ? view.tgid : view.tid;
            inode_set_task_directory(out, tgid);
        }
        else if (text_eq(name, "cgroup")) inode_set_pid(out, PROC_PID_CGROUP, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "oom_score_adj")) inode_set_pid(out, PROC_PID_OOM_SCORE_ADJ, pid, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "uid_map")) inode_set_pid(out, PROC_PID_UID_MAP, pid, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "gid_map")) inode_set_pid(out, PROC_PID_GID_MAP, pid, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "setgroups")) inode_set_pid(out, PROC_PID_SETGROUPS, pid, VFS_INODE_FILE | 0644);
        else return -1;
        return 0;
    }
    if (node == PROC_SELF_FDINFO) {
        kernel_fd_proc_snapshot_t snapshot;
        int32_t pid = (int32_t)dir->fs_private[1];
        int32_t descriptor;
        if (parse_fd(name, &descriptor) < 0 ||
            arch_proc_fd_snapshot(pid, descriptor, &snapshot) < 0)
            return -1;
        inode_set_pid(out, PROC_SELF_FDINFO_ENTRY, pid,
                      VFS_INODE_FILE | 0444);
        out->ino ^= (uint32_t)descriptor * 131u;
        out->fs_private[2] = (uint32_t)descriptor;
        return 0;
    }
    if (node == PROC_SELF_FD) {
        kernel_fd_proc_snapshot_t snapshot;
        int32_t pid = (int32_t)dir->fs_private[1];
        int32_t descriptor;
        if (parse_fd(name, &descriptor) < 0 ||
            arch_proc_fd_snapshot(pid, descriptor, &snapshot) < 0)
            return -1;
        inode_set_pid(out, PROC_SELF_FD_ENTRY, pid,
                      VFS_INODE_LNK | 0777);
        out->ino ^= (uint32_t)descriptor * 131u;
        out->fs_private[2] = (uint32_t)descriptor;
        out->size = 64u;
        return 0;
    }
    if (node == PROC_PID_DIR) {
        int32_t pid = (int32_t)dir->fs_private[1];
        if (text_eq(name, "mounts")) inode_set(out, PROC_MOUNTS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "mountinfo")) inode_set(out, PROC_MOUNTINFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "stat")) inode_set_pid(out, PROC_PID_STAT, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "statm")) inode_set_pid(out, PROC_PID_STATM, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "status")) inode_set_pid(out, PROC_PID_STATUS, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "sched")) inode_set_pid(out, PROC_PID_SCHED, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "schedstat")) inode_set_pid(out, PROC_PID_SCHEDSTAT, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "maps")) inode_set_pid(out, PROC_PID_MAPS, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "smaps")) inode_set_pid(out, PROC_PID_SMAPS, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "smaps_rollup")) inode_set_pid(out, PROC_PID_SMAPS_ROLLUP, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "cmdline")) inode_set_pid(out, PROC_PID_CMDLINE, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "comm")) inode_set_pid(out, PROC_PID_COMM, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "environ")) inode_set_pid(out, PROC_PID_ENVIRON, pid, VFS_INODE_FILE | 0400);
        else if (text_eq(name, "exe")) inode_set_pid(out, PROC_PID_EXE, pid, VFS_INODE_LNK | 0777);
        else if (text_eq(name, "cwd")) inode_set_pid(out, PROC_PID_CWD, pid, VFS_INODE_LNK | 0777);
        else if (text_eq(name, "root")) inode_set_pid(out, PROC_PID_ROOT, pid, VFS_INODE_LNK | 0777);
        else if (text_eq(name, "fd"))
            inode_set_pid(out, PROC_SELF_FD, pid, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "fdinfo"))
            inode_set_pid(out, PROC_SELF_FDINFO, pid,
                          VFS_INODE_DIR | 0555);
        else if (text_eq(name, "ns")) inode_set_pid(out, PROC_PID_NS, pid, VFS_INODE_DIR | 0555);
        else if (text_eq(name, "syscall")) inode_set_pid(out, PROC_PID_SYSCALL, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "task")) inode_set_task_directory(out, pid);
        else if (text_eq(name, "cgroup")) inode_set_pid(out, PROC_PID_CGROUP, pid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "oom_score_adj")) inode_set_pid(out, PROC_PID_OOM_SCORE_ADJ, pid, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "uid_map")) inode_set_pid(out, PROC_PID_UID_MAP, pid, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "gid_map")) inode_set_pid(out, PROC_PID_GID_MAP, pid, VFS_INODE_FILE | 0644);
        else if (text_eq(name, "setgroups")) inode_set_pid(out, PROC_PID_SETGROUPS, pid, VFS_INODE_FILE | 0644);
        else return -1;
        return 0;
    }
    if (node == PROC_PID_TASK) {
        int32_t tgid = (int32_t)dir->fs_private[1];
        int32_t tid;
        kernel_proc_task_view_t view;
        if (parse_pid(name, &tid) < 0 ||
            kernel_proc_task_view_get(tid, &view) < 0 ||
            (view.tgid > 0 ? view.tgid : view.tid) != tgid)
            return -1;
        inode_set_pid(out, PROC_THREAD_DIR, tid, VFS_INODE_DIR | 0555);
        return 0;
    }
    if (node == PROC_THREAD_DIR) {
        int32_t tid = (int32_t)dir->fs_private[1];
        if (text_eq(name, "mounts")) inode_set(out, PROC_MOUNTS, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "mountinfo")) inode_set(out, PROC_MOUNTINFO, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "stat")) inode_set_pid(out, PROC_PID_STAT, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "statm")) inode_set_pid(out, PROC_PID_STATM, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "status")) inode_set_pid(out, PROC_PID_STATUS, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "sched")) inode_set_pid(out, PROC_PID_SCHED, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "schedstat")) inode_set_pid(out, PROC_PID_SCHEDSTAT, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "maps")) inode_set_pid(out, PROC_PID_MAPS, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "smaps")) inode_set_pid(out, PROC_PID_SMAPS, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "smaps_rollup")) inode_set_pid(out, PROC_PID_SMAPS_ROLLUP, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "cmdline")) inode_set_pid(out, PROC_PID_CMDLINE, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "comm")) inode_set_pid(out, PROC_PID_COMM, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "environ")) inode_set_pid(out, PROC_PID_ENVIRON, tid, VFS_INODE_FILE | 0400);
        else if (text_eq(name, "exe")) inode_set_pid(out, PROC_PID_EXE, tid, VFS_INODE_LNK | 0777);
        else if (text_eq(name, "cwd")) inode_set_pid(out, PROC_PID_CWD, tid, VFS_INODE_LNK | 0777);
        else if (text_eq(name, "root")) inode_set_pid(out, PROC_PID_ROOT, tid, VFS_INODE_LNK | 0777);
        else if (text_eq(name, "syscall")) inode_set_pid(out, PROC_PID_SYSCALL, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "cgroup")) inode_set_pid(out, PROC_PID_CGROUP, tid, VFS_INODE_FILE | 0444);
        else if (text_eq(name, "oom_score_adj")) inode_set_pid(out, PROC_PID_OOM_SCORE_ADJ, tid, VFS_INODE_FILE | 0644);
        else return -1;
        return 0;
    }
    if (node == PROC_SELF_NS || node == PROC_PID_NS) {
        uint32_t kind;
        for (kind = 0; kind < sizeof(g_namespace_names) / sizeof(g_namespace_names[0]); ++kind)
            if (text_eq(name, g_namespace_names[kind])) break;
        if (kind == sizeof(g_namespace_names) / sizeof(g_namespace_names[0])) return -1;
        inode_set_namespace(out, (int32_t)dir->fs_private[1], kind);
        return 0;
    }
    return -1;
}

static const char *proc_sound_snapshot_name(uint32_t node) {
    switch (node) {
        case PROC_ASOUND_CARDS:
            return "cards";
        case PROC_ASOUND_DEVICES:
            return "devices";
        case PROC_ASOUND_PCM:
            return "pcm";
        case PROC_ASOUND_VERSION:
            return "version";
        case PROC_ASOUND_TIMERS:
            return "timers";
        case PROC_ASOUND_CARD0_ID:
            return "card0_id";
        case PROC_ASOUND_PCM0P_INFO:
            return "pcm0p_info";
        case PROC_ASOUND_PCM0P_SUB0_INFO:
            return "pcm0p_sub0_info";
        case PROC_ASOUND_PCM0P_SUB0_STATUS:
            return "pcm0p_sub0_status";
        case PROC_ASOUND_PCM0P_SUB0_HW_PARAMS:
            return "pcm0p_sub0_hw_params";
        case PROC_ASOUND_PCM0C_INFO:
            return "pcm0c_info";
        case PROC_ASOUND_PCM0C_SUB0_INFO:
            return "pcm0c_sub0_info";
        case PROC_ASOUND_PCM0C_SUB0_STATUS:
            return "pcm0c_sub0_status";
        case PROC_ASOUND_PCM0C_SUB0_HW_PARAMS:
            return "pcm0c_sub0_hw_params";
        default:
            return 0;
    }
}

static void proc_ipv6_prefix(uint8_t destination[16],
                             const uint8_t address[16], uint8_t prefix) {
    memcpy(destination, address, 16u);
    for (uint32_t bit = prefix; bit < 128u; ++bit)
        destination[bit / 8u] &= (uint8_t)~(1u << (7u - bit % 8u));
}

static int proc_append_ipv6_route(char *buffer, uint32_t capacity,
                                  uint32_t *length,
                                  const uint8_t destination[16],
                                  uint8_t prefix,
                                  const uint8_t next_hop[16],
                                  uint32_t metric, const char *interface) {
    static const uint8_t zero[16];

    if (append_ipv6_hex(buffer, capacity, length, destination) < 0 ||
        append(buffer, capacity, length, " ") < 0 ||
        append_hex_byte(buffer, capacity, length, prefix) < 0 ||
        append(buffer, capacity, length, " ") < 0 ||
        append_ipv6_hex(buffer, capacity, length, zero) < 0 ||
        append(buffer, capacity, length, " 00 ") < 0 ||
        append_ipv6_hex(buffer, capacity, length, next_hop) < 0 ||
        append(buffer, capacity, length, " ") < 0 ||
        append_hex_u32(buffer, capacity, length, metric) < 0 ||
        append(buffer, capacity, length,
               " 00000000 00000000 00000001 ") < 0 ||
        append(buffer, capacity, length, interface) < 0 ||
        append(buffer, capacity, length, "\n") < 0)
        return -1;
    return 0;
}

static int proc_append_stat(char *buffer, uint32_t capacity,
                            uint32_t *length, const char *name,
                            uint64_t value) {
    return append(buffer, capacity, length, name) < 0 ||
           append(buffer, capacity, length, "\t") < 0 ||
           append_u64(buffer, capacity, length, value) < 0 ||
           append(buffer, capacity, length, "\n") < 0 ? -1 : 0;
}

static uint64_t proc_u64_saturating_add(uint64_t left, uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static int proc_generate(uint32_t node, int32_t pid, uint32_t auxiliary,
                         char *buffer, uint32_t capacity) {
    uint32_t length = 0;
    uint64_t centiseconds;
    const char *sound_snapshot = proc_sound_snapshot_name(node);
    if (sound_snapshot)
        return arch_proc_sound_read(sound_snapshot, buffer, capacity);
    if (node == PROC_PID_MAPS)
        return kernel_proc_maps_render(pid, buffer, capacity);
    if (node == PROC_MODULES)
        return kernel_linux_modules_render(buffer, capacity);
    if (node == PROC_PID_SCHED)
        return kernel_scheduler_proc_task_render(pid, buffer, capacity);
    if (node == PROC_PID_SCHEDSTAT)
        return kernel_scheduler_proc_task_schedstat(pid, buffer, capacity);
    if (node == PROC_SCHEDSTAT)
        return kernel_scheduler_proc_system_schedstat(buffer, capacity);
    if (node == PROC_PID_UID_MAP || node == PROC_PID_GID_MAP ||
        node == PROC_PID_SETGROUPS) {
        kernel_proc_task_view_t task;
        edge_namespace_set_t namespaces;
        if (kernel_proc_task_view_get(pid, &task) < 0) return -1;
        memset(&namespaces, 0, sizeof(namespaces));
        namespaces.user = task.user_namespace_id;
        if (node == PROC_PID_SETGROUPS)
            return edge_userns_read_setgroups(&namespaces, buffer, capacity);
        return edge_userns_read_map(&namespaces,
                                    node == PROC_PID_GID_MAP,
                                    buffer, capacity);
    }
    if (node == PROC_SELF_FDINFO_ENTRY) {
        kernel_fd_proc_snapshot_t snapshot;
        int32_t descriptor = (int32_t)auxiliary;
        if (arch_proc_fd_snapshot(pid, descriptor, &snapshot) < 0 ||
            append(buffer, capacity, &length, "pos:\t") < 0 ||
            append_u64(buffer, capacity, &length, snapshot.offset) < 0 ||
            append(buffer, capacity, &length, "\nflags:\t0") < 0 ||
            append_octal_u32(buffer, capacity, &length, snapshot.flags) < 0 ||
            append(buffer, capacity, &length, "\nmnt_id:\t1\nino:\t") < 0 ||
            append_u64(buffer, capacity, &length, snapshot.inode) < 0)
            return -1;
        if (snapshot.is_pidfd) {
            if (append(buffer, capacity, &length, "\nPid:\t") < 0 ||
                append_s64(buffer, capacity, &length,
                           snapshot.pidfd_target) < 0 ||
                append(buffer, capacity, &length, "\nNSpid:\t") < 0 ||
                append_s64(buffer, capacity, &length,
                           snapshot.pidfd_target) < 0)
                return -1;
        }
        if (append(buffer, capacity, &length, "\n") < 0) return -1;
        return (int)length;
    }
    if (node == PROC_PID_OOM_SCORE_ADJ) {
        int32_t value;
        if (kernel_process_oom_score_adj_get(pid, &value) < 0 ||
            append_s64(buffer, capacity, &length, value) < 0 ||
            append(buffer, capacity, &length, "\n") < 0)
            return -1;
        return (int)length;
    }
    if (node == PROC_PID_CGROUP)
        return cgroupfs_proc_pid_snapshot(pid, buffer, capacity);
    if (node == PROC_CGROUPS)
        return cgroupfs_proc_cgroups_snapshot(buffer, capacity);
    if (node == PROC_PID_STAT || node == PROC_PID_STATM ||
        node == PROC_PID_STATUS ||
        node == PROC_PID_CMDLINE || node == PROC_PID_COMM ||
        node == PROC_PID_ENVIRON ||
        node == PROC_PID_SYSCALL) {
        kernel_proc_task_snapshot_t task;
        if (kernel_proc_task_snapshot(pid, &task) < 0) return -1;
        if (node == PROC_PID_CMDLINE) {
            int result = arch_proc_task_cmdline(pid, buffer, capacity);
            if (result != 0 || !task.exec_path[0]) return result;
            length = (uint32_t)strlen(task.exec_path) + 1u;
            if (length > capacity) return -1;
            memcpy(buffer, task.exec_path, length);
            return (int)length;
        }
        if (node == PROC_PID_ENVIRON)
            return arch_proc_task_environ(pid, buffer, capacity);
        if (node == PROC_PID_COMM) {
            if (append(buffer, capacity, &length, task.comm) < 0 ||
                append(buffer, capacity, &length, "\n") < 0)
                return -1;
            return (int)length;
        }
        if (node == PROC_PID_SYSCALL) {
            append_u64(buffer, capacity, &length, task.syscall_nr);
            for (uint32_t i = 0; i < 6u; ++i) {
                append(buffer, capacity, &length, " ");
                append_u64(buffer, capacity, &length, task.syscall_args[i]);
            }
            append(buffer, capacity, &length, " 0 0\n");
            return (int)length;
        }
        if (node == PROC_PID_STATM) {
            uint64_t size_pages =
                (task.virtual_size_bytes + 4095u) / 4096u;
            uint64_t resident_pages = task.resident_size_bytes / 4096u;
            uint64_t text_pages =
                (task.text_size_bytes + 4095u) / 4096u;
            uint64_t data_pages =
                (task.data_size_bytes + task.stack_size_bytes + 4095u) /
                4096u;

            if (append_u64(buffer, capacity, &length, size_pages) < 0 ||
                append(buffer, capacity, &length, " ") < 0 ||
                append_u64(buffer, capacity, &length, resident_pages) < 0 ||
                append(buffer, capacity, &length, " 0 ") < 0 ||
                append_u64(buffer, capacity, &length, text_pages) < 0 ||
                append(buffer, capacity, &length, " 0 ") < 0 ||
                append_u64(buffer, capacity, &length, data_pages) < 0 ||
                append(buffer, capacity, &length, " 0\n") < 0)
                return -1;
            return (int)length;
        }
        if (node == PROC_PID_STATUS) {
            append(buffer, capacity, &length, "Name:\t"); append(buffer, capacity, &length, task.comm);
            append(buffer, capacity, &length, "\nState:\t");
            { char state[2] = { task.state, 0 }; append(buffer, capacity, &length, state); }
            append(buffer, capacity, &length, "\nTgid:\t"); append_u64(buffer, capacity, &length, task.tgid);
            append(buffer, capacity, &length, "\nPid:\t"); append_u64(buffer, capacity, &length, task.pid);
            append(buffer, capacity, &length, "\nPPid:\t"); append_u64(buffer, capacity, &length, task.ppid);
            append(buffer, capacity, &length, "\nThreads:\t"); append_u64(buffer, capacity, &length, task.threads);
            append(buffer, capacity, &length, "\nVmPeak:\t"); append_u64(buffer, capacity, &length, task.virtual_size_bytes / 1024u); append(buffer, capacity, &length, " kB");
            append(buffer, capacity, &length, "\nVmSize:\t"); append_u64(buffer, capacity, &length, task.virtual_size_bytes / 1024u); append(buffer, capacity, &length, " kB");
            append(buffer, capacity, &length, "\nVmLck:\t"); append_u64(buffer, capacity, &length, task.locked_size_bytes / 1024u); append(buffer, capacity, &length, " kB");
            append(buffer, capacity, &length, "\nVmPin:\t0 kB");
            append(buffer, capacity, &length, "\nVmHWM:\t"); append_u64(buffer, capacity, &length, task.peak_resident_size_bytes / 1024u); append(buffer, capacity, &length, " kB");
            append(buffer, capacity, &length, "\nVmRSS:\t"); append_u64(buffer, capacity, &length, task.resident_size_bytes / 1024u); append(buffer, capacity, &length, " kB");
            append(buffer, capacity, &length, "\nRssAnon:\t"); append_u64(buffer, capacity, &length, task.resident_size_bytes / 1024u); append(buffer, capacity, &length, " kB");
            append(buffer, capacity, &length, "\nRssFile:\t0 kB");
            append(buffer, capacity, &length, "\nRssShmem:\t0 kB");
            append(buffer, capacity, &length, "\nVmData:\t"); append_u64(buffer, capacity, &length, task.data_size_bytes / 1024u); append(buffer, capacity, &length, " kB");
            append(buffer, capacity, &length, "\nVmStk:\t"); append_u64(buffer, capacity, &length, task.stack_size_bytes / 1024u); append(buffer, capacity, &length, " kB");
            append(buffer, capacity, &length, "\nVmExe:\t"); append_u64(buffer, capacity, &length, task.text_size_bytes / 1024u); append(buffer, capacity, &length, " kB");
            if (append_task_credentials(buffer, capacity, &length, &task) < 0)
                return -1;
            return (int)length;
        }
        append_u64(buffer, capacity, &length, task.pid); append(buffer, capacity, &length, " (");
        append(buffer, capacity, &length, task.comm); append(buffer, capacity, &length, ") ");
        { char state[2] = { task.state, 0 }; append(buffer, capacity, &length, state); }
        append(buffer, capacity, &length, " "); append_u64(buffer, capacity, &length, task.ppid);
        append(buffer, capacity, &length, " "); append_u64(buffer, capacity, &length, task.pgid);
        append(buffer, capacity, &length, " "); append_u64(buffer, capacity, &length, task.sid);
        append(buffer, capacity, &length, " 0 "); append_u64(buffer, capacity, &length, task.tty_pgrp);
        /* fields 9..17: flags and the fault/CPU-time counters */
        append(buffer, capacity, &length, " 0 ");
        append_u64(buffer, capacity, &length, task.minor_faults); append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.children_minor_faults); append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.major_faults); append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.children_major_faults); append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.user_time_ticks); append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.system_time_ticks); append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.children_user_time_ticks); append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.children_system_time_ticks); append(buffer, capacity, &length, " ");
        append_s64(buffer, capacity, &length, 20 + (int64_t)task.nice_value);
        append(buffer, capacity, &length, " ");
        append_s64(buffer, capacity, &length, (int64_t)task.nice_value);
        append(buffer, capacity, &length, " "); append_u64(buffer, capacity, &length, task.threads);
        append(buffer, capacity, &length, " 0 ");
        append_u64(buffer, capacity, &length, task.start_time_ticks);
        /* fields 23..38 */
        append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.virtual_size_bytes);
        append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length,
                   task.resident_size_bytes / 4096u);
        append(buffer, capacity, &length,
               " 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 ");
        /* fields 39..41: last CPU, real-time priority, policy */
        append_u64(buffer, capacity, &length, task.processor);
        append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.scheduler_priority);
        append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length, task.scheduler_policy);
        /* fields 42..52 */
        append(buffer, capacity, &length,
               " 0 0 0 0 0 0 0 0 0 0 0\n");
        return (int)length;
    }
    if (node == PROC_OVERFLOWUID || node == PROC_OVERFLOWGID) {
        append_u64(buffer, capacity, &length,
                   proc_sysctl_read(node == PROC_OVERFLOWUID ?
                                    PROC_SYSCTL_OVERFLOWUID :
                                    PROC_SYSCTL_OVERFLOWGID));
        append(buffer, capacity, &length, "\n");
    } else if (node == PROC_HOSTNAME || node == PROC_DOMAINNAME ||
               node == PROC_BOOT_ID || node == PROC_FILE_MAX ||
               node == PROC_NR_OPEN ||
               node == PROC_INOTIFY_MAX_QUEUED_EVENTS ||
               node == PROC_INOTIFY_MAX_USER_INSTANCES ||
               node == PROC_INOTIFY_MAX_USER_WATCHES ||
               node == PROC_IP_FORWARD ||
               node == PROC_BRIDGE_NF_CALL_IPTABLES ||
               node == PROC_BRIDGE_NF_CALL_IP6TABLES ||
               node == PROC_BRIDGE_NF_CALL_ARPTABLES ||
               node == PROC_IP_LOCAL_PORT_RANGE ||
               node == PROC_THREADS_MAX ||
               node == PROC_OSTYPE ||
               node == PROC_OSRELEASE ||
               node == PROC_KERNEL_VERSION ||
               node == PROC_ROOT_MAXKEYS) {
        int result = proc_sysctl_render_in_network_namespace(
            node == PROC_HOSTNAME ? PROC_SYSCTL_HOSTNAME :
            node == PROC_DOMAINNAME ? PROC_SYSCTL_DOMAINNAME :
            node == PROC_BOOT_ID ? PROC_SYSCTL_BOOT_ID :
            node == PROC_FILE_MAX ? PROC_SYSCTL_FILE_MAX :
            node == PROC_NR_OPEN ? PROC_SYSCTL_NR_OPEN :
            node == PROC_INOTIFY_MAX_QUEUED_EVENTS ?
                PROC_SYSCTL_INOTIFY_MAX_QUEUED_EVENTS :
            node == PROC_INOTIFY_MAX_USER_INSTANCES ?
                PROC_SYSCTL_INOTIFY_MAX_USER_INSTANCES :
            node == PROC_INOTIFY_MAX_USER_WATCHES ?
                PROC_SYSCTL_INOTIFY_MAX_USER_WATCHES :
            node == PROC_IP_FORWARD ? PROC_SYSCTL_IP_FORWARD :
            node == PROC_BRIDGE_NF_CALL_IPTABLES ?
                PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES :
            node == PROC_BRIDGE_NF_CALL_IP6TABLES ?
                PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES :
            node == PROC_BRIDGE_NF_CALL_ARPTABLES ?
                PROC_SYSCTL_BRIDGE_NF_CALL_ARPTABLES :
            node == PROC_IP_LOCAL_PORT_RANGE ?
                PROC_SYSCTL_IP_LOCAL_PORT_RANGE :
            node == PROC_THREADS_MAX ? PROC_SYSCTL_THREADS_MAX :
            node == PROC_OSTYPE ? PROC_SYSCTL_OSTYPE :
            node == PROC_OSRELEASE ? PROC_SYSCTL_OSRELEASE :
            node == PROC_KERNEL_VERSION ? PROC_SYSCTL_VERSION :
                PROC_SYSCTL_ROOT_MAXKEYS,
            proc_net_current_namespace(),
            buffer, capacity);
        if (result < 0) return -1;
        length = (uint32_t)result;
    } else if (node == PROC_MOUNTS) return vfs_mounts_snapshot(buffer, capacity);
    else if (node == PROC_MOUNTINFO) return vfs_mountinfo_snapshot(buffer, capacity);
    else if (node == PROC_CMDLINE) {
        if (append(buffer, capacity, &length,
                   kernel_boot_command_line_get()) < 0 ||
            append(buffer, capacity, &length, "\n") < 0)
            return -1;
    }
    else if (node == PROC_VERSION) {
        int version_length = bootlog_format_linux_version(buffer, capacity);
        if (version_length < 0) return -1;
        length = (uint32_t)version_length;
        if (append(buffer, capacity, &length, "\n") < 0) return -1;
    }
    else if (node == PROC_FILESYSTEMS) {
        if (append(buffer, capacity, &length,
                   "nodev\tproc\nnodev\tsysfs\nnodev\tdevtmpfs\n"
                   "nodev\tdevpts\nnodev\ttmpfs\nnodev\tmqueue\n"
                   "nodev\tcgroup2\n") < 0)
            return -1;
#ifdef CONFIG_FUSE_FS
        if (append(buffer, capacity, &length,
                   "nodev\tfuse\nnodev\tfuseblk\n") < 0)
            return -1;
#endif
        if (arch_proc_filesystem_available(KERNEL_PROC_FS_EXT2) &&
            append(buffer, capacity, &length, "\text2\n") < 0)
            return -1;
        if (arch_proc_filesystem_available(KERNEL_PROC_FS_EXT4) &&
            append(buffer, capacity, &length, "\text4\n") < 0)
            return -1;
        if (arch_proc_filesystem_available(KERNEL_PROC_FS_FAT32) &&
            append(buffer, capacity, &length, "\tfat32\n") < 0)
            return -1;
        if (arch_proc_filesystem_available(KERNEL_PROC_FS_EXFAT) &&
            append(buffer, capacity, &length, "\texfat\n") < 0)
            return -1;
        if (arch_proc_filesystem_available(KERNEL_PROC_FS_NTFS) &&
            append(buffer, capacity, &length, "\tntfs\n") < 0)
            return -1;
        if (arch_proc_filesystem_available(KERNEL_PROC_FS_ISO9660) &&
            append(buffer, capacity, &length, "\tiso9660\n") < 0)
            return -1;
        if (arch_proc_filesystem_available(KERNEL_PROC_FS_UDF) &&
            append(buffer, capacity, &length, "\tudf\n") < 0)
            return -1;
    } else if (node == PROC_DEVICES) {
        if (proc_generate_devices(buffer, capacity, &length) < 0)
            return -1;
    } else if (node == PROC_SWAPS) {
        return swap_proc_snapshot(buffer, capacity);
    } else if (node == PROC_LOADAVG) {
        uint32_t running;
        uint32_t total;
        uint32_t load[3];
        if (kernel_proc_task_load_snapshot(&running, &total) < 0)
            return -1;
        kernel_scheduler_load_snapshot(&load[0], &load[1], &load[2]);
        if (append_hundredths(buffer, capacity, &length, load[0]) < 0 ||
            append(buffer, capacity, &length, " ") < 0 ||
            append_hundredths(buffer, capacity, &length, load[1]) < 0 ||
            append(buffer, capacity, &length, " ") < 0 ||
            append_hundredths(buffer, capacity, &length, load[2]) < 0 ||
            append(buffer, capacity, &length, " ") < 0 ||
            append_u64(buffer, capacity, &length,
                       running ? running : 1u) < 0 ||
            append(buffer, capacity, &length, "/") < 0 ||
            append_u64(buffer, capacity, &length, total ? total : 1u) < 0 ||
            append(buffer, capacity, &length, " 1\n") < 0)
            return -1;
    } else if (node == PROC_IOPORTS) {
        return arch_cpu_proc_ioports(buffer, capacity);
    } else if (node == PROC_DISKSTATS) {
        int devices = block_count();
        for (int index = 0; index < devices; ++index) {
            block_device_t *device = block_get(index);
            block_io_statistics_t statistics;
            uint32_t major;
            uint32_t minor;
            if (!device ||
                block_linux_major_minor(device, &major, &minor) < 0 ||
                block_io_statistics_snapshot(device, &statistics) < 0)
                continue;
            if (append_u64(buffer, capacity, &length, major) < 0 ||
                append(buffer, capacity, &length, " ") < 0 ||
                append_u64(buffer, capacity, &length, minor) < 0 ||
                append(buffer, capacity, &length, " ") < 0 ||
                append(buffer, capacity, &length, device->name) < 0 ||
                append(buffer, capacity, &length, " ") < 0 ||
                append_u64(buffer, capacity, &length,
                           statistics.read_ios) < 0 ||
                append(buffer, capacity, &length, " 0 ") < 0 ||
                append_u64(buffer, capacity, &length,
                           statistics.read_sectors) < 0 ||
                append(buffer, capacity, &length, " 0 ") < 0 ||
                append_u64(buffer, capacity, &length,
                           statistics.write_ios) < 0 ||
                append(buffer, capacity, &length, " 0 ") < 0 ||
                append_u64(buffer, capacity, &length,
                           statistics.write_sectors) < 0 ||
                append(buffer, capacity, &length, " 0 ") < 0 ||
                append_u64(buffer, capacity, &length,
                           statistics.in_flight) < 0 ||
                append(buffer, capacity, &length,
                       " 0 0 0 0 0 0 ") < 0 ||
                append_u64(buffer, capacity, &length,
                           statistics.flush_ios) < 0 ||
                append(buffer, capacity, &length, " 0\n") < 0)
                return -1;
        }
    } else if (node == PROC_TTY_DRIVERS) {
        kernel_console_device_t serial;

        if (kernel_arch_serial_console_device(&serial) == 0 &&
            append(buffer, capacity, &length,
                   serial.major == 204u ?
                       "serial               /dev/ttyAMA   204 64-64 serial\n" :
                       "serial               /dev/ttyS       4 64-64 serial\n") < 0)
            return -1;
        if (append(buffer, capacity, &length,
                   "console              /dev/console    5 1 system:console\n"
                   "tty                  /dev/tty        5 0 system:/dev/tty\n"
                   "vtmaster             /dev/tty0       4 0 system:vtmaster\n"
                   "vcs                  /dev/tty        4 1-63 console\n") < 0)
            return -1;
    } else if (node == PROC_TTY_LDISCS) {
        if (append(buffer, capacity, &length, "n_tty       0\n") < 0)
            return -1;
    } else if (node == PROC_TTY_SERIAL) {
        return serial_console_proc_snapshot(buffer, capacity);
    } else if (node == PROC_UPTIME) {
        centiseconds = boottime_monotonic_us() / 10000u;
        append_u64(buffer, capacity, &length, centiseconds / 100u);
        append(buffer, capacity, &length, ".");
        if (centiseconds % 100u < 10u) append(buffer, capacity, &length, "0");
        append_u64(buffer, capacity, &length, centiseconds % 100u);
        append(buffer, capacity, &length, " 0.00\n");
    } else if (node == PROC_MEMINFO) {
        kernel_proc_memory_snapshot_t memory;
        int result;
        memory.total_bytes = arch_vm_memory_total_bytes();
        memory.free_bytes = arch_vm_memory_free_bytes();
        memory.available_bytes = memory.free_bytes;
        memory.buffer_bytes = 0;
        memory.cache_bytes = tmpfs_resident_bytes();
        memory.shared_bytes = memory.cache_bytes +
                              kernel_runtime_sysv_shmem_bytes();
        memory.slab_reclaimable_bytes = 0;
        memory.slab_unreclaimable_bytes = 0;
        memory.swap_total_bytes = swap_total_bytes();
        memory.swap_free_bytes = swap_free_bytes();
        result = kernel_proc_memory_render(buffer, capacity, &memory);
        if (result < 0) {
            printf("procfs: meminfo render failed capacity=%u total=%llu free=%llu cache=%llu shared=%llu\n",
                   capacity,
                   (unsigned long long)memory.total_bytes,
                   (unsigned long long)memory.free_bytes,
                   (unsigned long long)memory.cache_bytes,
                   (unsigned long long)memory.shared_bytes);
        }
        return result;
    } else if (node == PROC_VMSTAT || node == PROC_ZONEINFO ||
               node == PROC_BUDDYINFO || node == PROC_PAGETYPEINFO) {
        if (arch_vm_page_allocator_snapshot(
                &g_proc_page_allocator_snapshot) < 0)
            return -1;
        if (node == PROC_VMSTAT) {
            edge_mm_statistics_snapshot(&g_proc_mm_statistics_snapshot);
            return kernel_proc_vmstat_render(
                buffer, capacity, &g_proc_page_allocator_snapshot,
                &g_proc_mm_statistics_snapshot,
                tmpfs_resident_bytes() / EDGE_PAGE_SIZE,
                (tmpfs_resident_bytes() +
                 kernel_runtime_sysv_shmem_bytes()) / EDGE_PAGE_SIZE);
        }
        if (node == PROC_ZONEINFO)
            return kernel_proc_zoneinfo_render(
                buffer, capacity, &g_proc_page_allocator_snapshot);
        if (node == PROC_BUDDYINFO)
            return kernel_proc_buddyinfo_render(
                buffer, capacity, &g_proc_page_allocator_snapshot);
        return kernel_proc_pagetypeinfo_render(
            buffer, capacity, &g_proc_page_allocator_snapshot);
    } else if (node == PROC_PRESSURE_MEMORY) {
        edge_mm_pressure_snapshot_t pressure = {0};

        edge_mm_statistics_pressure_snapshot(
            boottime_monotonic_us(), &pressure);
        return kernel_proc_memory_pressure_render(
            buffer, capacity, &pressure);
    } else if (node == PROC_CPUINFO) {
        return arch_cpu_proc_info(buffer, capacity);
    } else if (node == PROC_STAT) {
        uint64_t monotonic = boottime_monotonic_us();
        uint64_t realtime = boottime_realtime_us();
        uint64_t boot_seconds =
            realtime >= monotonic ? (realtime - monotonic) / 1000000u : 0;
        kernel_scheduler_cpu_stats_t aggregate;
        uint64_t online = kernel_arch_scheduler_online_cpu_mask();
        uint32_t running;
        uint32_t total;
        uint32_t emitted_cpus = 0;
        memset(&aggregate, 0, sizeof(aggregate));
        if (kernel_proc_task_load_snapshot(&running, &total) < 0)
            return -1;

        if (!online) online = 1u;
        for (uint32_t cpu = 0; cpu < 64u; ++cpu) {
            kernel_scheduler_cpu_stats_t stats;

            if (!(online & (1ull << cpu)) ||
                kernel_arch_scheduler_cpu_stats(cpu, &stats) < 0)
                continue;
            aggregate.user_time_us = proc_u64_saturating_add(
                aggregate.user_time_us, stats.user_time_us);
            aggregate.system_time_us = proc_u64_saturating_add(
                aggregate.system_time_us, stats.system_time_us);
            aggregate.idle_time_us = proc_u64_saturating_add(
                aggregate.idle_time_us, stats.idle_time_us);
            aggregate.context_switches = proc_u64_saturating_add(
                aggregate.context_switches, stats.context_switches);
            ++emitted_cpus;
        }
        if (!emitted_cpus) {
            aggregate.idle_time_us = monotonic;
            emitted_cpus = 1u;
        }
        append(buffer, capacity, &length, "cpu  ");
        append_u64(buffer, capacity, &length,
                   aggregate.user_time_us / 10000u);
        append(buffer, capacity, &length, " 0 ");
        append_u64(buffer, capacity, &length,
                   aggregate.system_time_us / 10000u);
        append(buffer, capacity, &length, " ");
        append_u64(buffer, capacity, &length,
                   aggregate.idle_time_us / 10000u);
        append(buffer, capacity, &length, " 0 0 0 0 0 0\n");
        emitted_cpus = 0u;
        for (uint32_t cpu = 0; cpu < 64u; ++cpu) {
            kernel_scheduler_cpu_stats_t stats;

            if (!(online & (1ull << cpu)) ||
                kernel_arch_scheduler_cpu_stats(cpu, &stats) < 0)
                continue;
            append(buffer, capacity, &length, "cpu");
            append_u64(buffer, capacity, &length, cpu);
            append(buffer, capacity, &length, " ");
            append_u64(buffer, capacity, &length,
                       stats.user_time_us / 10000u);
            append(buffer, capacity, &length, " 0 ");
            append_u64(buffer, capacity, &length,
                       stats.system_time_us / 10000u);
            append(buffer, capacity, &length, " ");
            append_u64(buffer, capacity, &length,
                       stats.idle_time_us / 10000u);
            append(buffer, capacity, &length, " 0 0 0 0 0 0\n");
            ++emitted_cpus;
        }
        if (!emitted_cpus) {
            append(buffer, capacity, &length, "cpu0 0 0 0 ");
            append_u64(buffer, capacity, &length, monotonic / 10000u);
            append(buffer, capacity, &length, " 0 0 0 0 0 0\n");
        }
        append(buffer, capacity, &length, "intr 0\nctxt ");
        append_u64(buffer, capacity, &length,
                   aggregate.context_switches);
        append(buffer, capacity, &length, "\nbtime ");
        append_u64(buffer, capacity, &length, boot_seconds);
        append(buffer, capacity, &length, "\nprocesses ");
        append_u64(buffer, capacity, &length, total);
        append(buffer, capacity, &length, "\nprocs_running ");
        append_u64(buffer, capacity, &length, running ? running : 1u);
        append(buffer, capacity, &length, "\nprocs_blocked 0\n");
    } else if (node == PROC_NET_DEV) {
        edge_namespace_set_t *namespaces =
            kernel_arch_current_namespace_set();
        uint32_t network_namespace = namespaces ? namespaces->net : 0u;

        append(buffer, capacity, &length,
               "Inter-|   Receive                                                |  Transmit\n"
               " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
               "    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
        for (uint32_t ordinal = 0; ordinal < EDGE_NET_DEVICE_MAX;
             ++ordinal) {
            edge_net_device_snapshot_t snapshot;

            if (edge_net_device_snapshot_at(
                    network_namespace, ordinal, &snapshot) != EDGE_NET_OK)
                break;
            append(buffer, capacity, &length, "  ");
            append(buffer, capacity, &length,
                   snapshot.configuration.name);
            append(buffer, capacity, &length, ": ");
            append_u64(buffer, capacity, &length, snapshot.rx_bytes);
            append(buffer, capacity, &length, " ");
            append_u64(buffer, capacity, &length, snapshot.rx_packets);
            append(buffer, capacity, &length, " 0 ");
            append_u64(buffer, capacity, &length, snapshot.rx_drops);
            append(buffer, capacity, &length, " 0 0 0 0 ");
            append_u64(buffer, capacity, &length, snapshot.tx_bytes);
            append(buffer, capacity, &length, " ");
            append_u64(buffer, capacity, &length, snapshot.tx_packets);
            append(buffer, capacity, &length, " 0 ");
            append_u64(buffer, capacity, &length, snapshot.tx_drops);
            append(buffer, capacity, &length, " 0 0 0 0\n");
        }
    } else if (node == PROC_NET_ARP) {
        append(buffer, capacity, &length,
               "IP address       HW type     Flags       HW address            Mask     Device\n");
        for (int ordinal = 0; ordinal < 256; ++ordinal) {
            uint32_t address_be;
            uint8_t mac[6];
            int ifindex;
            if (lwip_stack_get_ipv4_neighbor(ordinal, &address_be, mac,
                                              &ifindex) < 0)
                break;
            append_ipv4(buffer, capacity, &length, address_be);
            append(buffer, capacity, &length, " 0x1 0x2 ");
            for (uint32_t index = 0; index < 6u; ++index) {
                if (index) append(buffer, capacity, &length, ":");
                append_hex_byte(buffer, capacity, &length, mac[index]);
            }
            append(buffer, capacity, &length,
                   ifindex == 2 ? " * eth0\n" : " * unknown\n");
        }
    } else if (node == PROC_NET_IF_INET6) {
        uint8_t address[16], prefix = 0, scope = 0, flags = 0;
        append(buffer, capacity, &length,
               "00000000000000000000000000000001 01 80 10 80       lo\n");
        for (int ordinal = 0; ordinal < 16; ++ordinal) {
            if (lwip_stack_get_ipv6_addr_at(ordinal, address, &prefix, &scope,
                                             &flags) < 0)
                break;
            for (uint32_t index = 0; index < 16u; ++index)
                append_hex_byte(buffer, capacity, &length, address[index]);
            append(buffer, capacity, &length, " 02 ");
            append_hex_byte(buffer, capacity, &length, prefix);
            append(buffer, capacity, &length, " ");
            append_hex_byte(buffer, capacity, &length, scope);
            append(buffer, capacity, &length, " ");
            append_hex_byte(buffer, capacity, &length, flags);
            append(buffer, capacity, &length, "       eth0\n");
        }
    } else if (node == PROC_NET_IPV6_ROUTE) {
        static const uint8_t zero[16];
        static const uint8_t loopback[16] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        };
        uint8_t address[16], destination[16], prefix = 0;
        uint8_t scope = 0, flags = 0;

        if (proc_append_ipv6_route(buffer, capacity, &length, loopback,
                                   128u, zero, 0u, "lo") < 0)
            return -1;
        for (int ordinal = 0; ordinal < 64; ++ordinal) {
            if (lwip_stack_get_ipv6_addr_at(ordinal, address, &prefix,
                                             &scope, &flags) < 0)
                break;
            if (prefix > 128u) continue;
            proc_ipv6_prefix(destination, address, prefix);
            if (proc_append_ipv6_route(buffer, capacity, &length,
                                       destination, prefix, zero, 256u,
                                       "eth0") < 0)
                return -1;
        }
        for (int ordinal = 0; ordinal < 64; ++ordinal) {
            uint32_t lifetime;
            uint8_t preference;

            if (lwip_stack_get_ipv6_router(ordinal, address, &lifetime,
                                            &preference) < 0)
                break;
            (void)lifetime;
            if (proc_append_ipv6_route(buffer, capacity, &length, zero, 0,
                                       address,
                                       1024u - (uint32_t)preference,
                                       "eth0") < 0)
                return -1;
        }
    } else if (node == PROC_NET_SNMP6) {
        lwip_stack_ipv6_stats_t stats;

        if (lwip_stack_get_ipv6_stats(&stats) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6InReceives", stats.in_receives) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6InHdrErrors", stats.in_header_errors) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6InNoRoutes", stats.in_no_routes) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6InUnknownProtos",
                             stats.in_unknown_protocols) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6InDiscards", stats.in_discards) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6InDelivers", stats.in_delivers) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6OutForwDatagrams", stats.out_forwards) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6OutRequests", stats.out_requests) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6OutNoRoutes", stats.out_no_routes) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6ReasmReqds",
                             stats.reassembly_requests) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6ReasmFails",
                             stats.reassembly_failures) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Ip6FragCreates",
                             stats.fragments_created) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Icmp6InMsgs", stats.icmp_in_messages) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Icmp6InErrors", stats.icmp_in_errors) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Icmp6OutMsgs", stats.icmp_out_messages) < 0 ||
            proc_append_stat(buffer, capacity, &length,
                             "Icmp6OutErrors", stats.icmp_out_errors) < 0)
            return -1;
    } else if (node == PROC_SYS_NET_IPV6_CONF_VALUE) {
        int value = lwip_stack_ipv6_setting_get_in_namespace(
            proc_net_current_namespace(),
            (lwip_ipv6_scope_t)pid,
            (lwip_ipv6_setting_t)auxiliary);

        if (value < 0 || append_u64(buffer, capacity, &length,
                                    (uint32_t)value) < 0 ||
            append(buffer, capacity, &length, "\n") < 0)
            return -1;
    } else return -1;
    return (int)length;
}

static int proc_node_is_writable(uint32_t node) {
    return node == PROC_PID_OOM_SCORE_ADJ ||
        node == PROC_PID_UID_MAP ||
        node == PROC_PID_GID_MAP ||
        node == PROC_PID_SETGROUPS ||
        node == PROC_OVERFLOWUID ||
        node == PROC_OVERFLOWGID ||
        node == PROC_HOSTNAME ||
        node == PROC_DOMAINNAME ||
        node == PROC_FILE_MAX ||
        node == PROC_NR_OPEN ||
        node == PROC_INOTIFY_MAX_QUEUED_EVENTS ||
        node == PROC_INOTIFY_MAX_USER_INSTANCES ||
        node == PROC_INOTIFY_MAX_USER_WATCHES ||
        node == PROC_IP_FORWARD ||
        node == PROC_BRIDGE_NF_CALL_IPTABLES ||
        node == PROC_BRIDGE_NF_CALL_IP6TABLES ||
        node == PROC_BRIDGE_NF_CALL_ARPTABLES ||
        node == PROC_IP_LOCAL_PORT_RANGE ||
        node == PROC_SYS_NET_IPV6_CONF_VALUE ||
        node == PROC_THREADS_MAX ||
        node == PROC_ROOT_MAXKEYS;
}

static int proc_write(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off,
                      const void *buffer, uint32_t len) {
    (void)sb;
    if (!inode || !buffer || off != 0) return -1;
    if (inode->fs_private[0] == PROC_PID_OOM_SCORE_ADJ) {
        int32_t value;
        if (proc_parse_s32(buffer, len, -1000, 1000, &value) < 0 ||
            kernel_process_oom_score_adj_set(
                (int32_t)inode->fs_private[1], value) < 0)
            return -1;
        return (int)len;
    }
    if (inode->fs_private[0] == PROC_PID_UID_MAP ||
        inode->fs_private[0] == PROC_PID_GID_MAP ||
        inode->fs_private[0] == PROC_PID_SETGROUPS) {
        kernel_proc_task_view_t target;
        kernel_linux_identity_t writer;
        edge_namespace_set_t namespaces;
        if (kernel_proc_task_view_get((int32_t)inode->fs_private[1],
                                      &target) < 0 ||
            kernel_current_linux_identity(&writer) < 0)
            return -1;
        memset(&namespaces, 0, sizeof(namespaces));
        namespaces.user = target.user_namespace_id;
        if (inode->fs_private[0] == PROC_PID_SETGROUPS)
            return edge_userns_write_setgroups(&namespaces, buffer, len,
                                               writer.euid);
        return edge_userns_write_map(
            &namespaces, inode->fs_private[0] == PROC_PID_GID_MAP,
            buffer, len, writer.euid, writer.egid);
    }
    if (inode->fs_private[0] == PROC_SYS_NET_IPV6_CONF_VALUE) {
        int32_t value;
        int32_t maximum = inode->fs_private[2] ==
            LWIP_IPV6_SETTING_ACCEPT_RA ? 2 : 1;

        if (proc_parse_s32(buffer, len, 0, maximum, &value) < 0 ||
            lwip_stack_ipv6_setting_set_in_namespace(
                proc_net_current_namespace(),
                (lwip_ipv6_scope_t)inode->fs_private[1],
                (lwip_ipv6_setting_t)inode->fs_private[2], value) < 0)
            return -1;
        return (int)len;
    }
    if (!proc_node_is_writable(inode->fs_private[0])) return -1;
    return proc_sysctl_write_in_network_namespace(
                             inode->fs_private[0] == PROC_OVERFLOWUID ?
                             PROC_SYSCTL_OVERFLOWUID :
                             inode->fs_private[0] == PROC_OVERFLOWGID ?
                             PROC_SYSCTL_OVERFLOWGID :
                             inode->fs_private[0] == PROC_HOSTNAME ?
                             PROC_SYSCTL_HOSTNAME :
                             inode->fs_private[0] == PROC_DOMAINNAME ?
                             PROC_SYSCTL_DOMAINNAME :
                             inode->fs_private[0] == PROC_FILE_MAX ?
                             PROC_SYSCTL_FILE_MAX :
                             inode->fs_private[0] == PROC_NR_OPEN ?
                             PROC_SYSCTL_NR_OPEN :
                             inode->fs_private[0] ==
                                 PROC_INOTIFY_MAX_QUEUED_EVENTS ?
                             PROC_SYSCTL_INOTIFY_MAX_QUEUED_EVENTS :
                             inode->fs_private[0] ==
                                 PROC_INOTIFY_MAX_USER_INSTANCES ?
                             PROC_SYSCTL_INOTIFY_MAX_USER_INSTANCES :
                             inode->fs_private[0] ==
                                 PROC_INOTIFY_MAX_USER_WATCHES ?
                             PROC_SYSCTL_INOTIFY_MAX_USER_WATCHES :
                             inode->fs_private[0] == PROC_IP_FORWARD ?
                             PROC_SYSCTL_IP_FORWARD :
                             inode->fs_private[0] ==
                                 PROC_BRIDGE_NF_CALL_IPTABLES ?
                             PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES :
                             inode->fs_private[0] ==
                                 PROC_BRIDGE_NF_CALL_IP6TABLES ?
                             PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES :
                             inode->fs_private[0] ==
                                 PROC_BRIDGE_NF_CALL_ARPTABLES ?
                             PROC_SYSCTL_BRIDGE_NF_CALL_ARPTABLES :
                             inode->fs_private[0] ==
                                 PROC_IP_LOCAL_PORT_RANGE ?
                             PROC_SYSCTL_IP_LOCAL_PORT_RANGE :
                             inode->fs_private[0] == PROC_THREADS_MAX ?
                             PROC_SYSCTL_THREADS_MAX :
                             PROC_SYSCTL_ROOT_MAXKEYS,
                             proc_net_current_namespace(),
                             buffer, len);
}

static int proc_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off,
                     void *out, uint32_t len) {
    int size;
    uint32_t count;
    (void)sb;
    if (!inode || !out) return -1;
    if (inode->fs_private[0] == PROC_KMSG)
        return (int)bootlog_read(off, out, len);
    if (inode->fs_private[0] == PROC_PID_MAPS)
        return kernel_proc_maps_read((int32_t)inode->fs_private[1],
                                     off, out, len);
    if (inode->fs_private[0] == PROC_PID_SMAPS)
        return kernel_proc_smaps_read((int32_t)inode->fs_private[1],
                                      off, out, len);
    if (inode->fs_private[0] == PROC_PID_SMAPS_ROLLUP)
        return kernel_proc_smaps_rollup_read(
            (int32_t)inode->fs_private[1], off, out, len);
    if (inode->fs_private[0] == PROC_MOUNTS ||
        inode->fs_private[0] == PROC_MOUNTINFO)
        return vfs_mount_snapshot_read(
            inode->fs_private[0] == PROC_MOUNTINFO, off, out, len);
    while (__sync_lock_test_and_set(&g_proc_read_lock, 1u))
        arch_cpu_relax();
    for (uint32_t i = 0; i < 4u; ++i)
        g_proc_snapshot.guard[i] = 0x4544474550524f43ULL ^ i;
    g_proc_guard_armed = 1;
    size = proc_generate(
        inode->fs_private[0], (int32_t)inode->fs_private[1],
        inode->fs_private[2], g_proc_snapshot.bytes,
        sizeof(g_proc_snapshot.bytes));
    for (uint32_t i = 0; i < 4u; ++i) {
        if (g_proc_snapshot.guard[i] != (0x4544474550524f43ULL ^ i)) {
            printf("procfs: snapshot overflow during generation node=%u size=%d guard=%x\n",
                   inode->fs_private[0], size, (uint32_t)g_proc_snapshot.guard[i]);
            __sync_lock_release(&g_proc_read_lock);
            return -1;
        }
    }
    if (size < 0 || off >= (uint32_t)size) {
        __sync_lock_release(&g_proc_read_lock);
        return size < 0 ? -1 : 0;
    }
    count = (uint32_t)size - off;
    if (count > len) count = len;
    memcpy(out, g_proc_snapshot.bytes + off, count);
    if (!procfs_guard_valid()) {
        printf("procfs: snapshot overflow during copy node=%u off=%u count=%u\n",
               inode->fs_private[0], off, count);
        __sync_lock_release(&g_proc_read_lock);
        return -1;
    }
    __sync_lock_release(&g_proc_read_lock);
    return (int)count;
}

static int proc_readlink(vfs_superblock_t *sb, vfs_inode_t *inode, char *out, uint32_t max) {
    uint32_t length;
    (void)sb;
    if (inode && inode->fs_private[0] == PROC_SELF) {
        char target[16];
        int32_t pid = proc_current_tgid();
        uint32_t target_length = 0;
        if (pid <= 0 ||
            append_u64(target, sizeof(target), &target_length,
                       (uint32_t)pid) < 0 ||
            max < target_length)
            return -1;
        memcpy(out, target, target_length);
        return (int)target_length;
    }
    if (inode && inode->fs_private[0] == PROC_NS_LINK) {
        char target[48];
        uint32_t target_length = 0;
        uint32_t kind = inode->fs_private[2];
        uint64_t identity;
        if (kind >= sizeof(g_namespace_names) / sizeof(g_namespace_names[0])) return -1;
        if (arch_proc_namespace_inode((int32_t)inode->fs_private[1], kind,
                                      &identity) < 0)
            return -1;
        append(target, sizeof(target), &target_length, g_namespace_names[kind]);
        append(target, sizeof(target), &target_length, ":[");
        append_u64(target, sizeof(target), &target_length, identity);
        append(target, sizeof(target), &target_length, "]");
        if (max < target_length) return -1;
        memcpy(out, target, target_length);
        return (int)target_length;
    }
    if (inode && (inode->fs_private[0] == PROC_PID_CWD ||
                  inode->fs_private[0] == PROC_PID_ROOT)) {
        int32_t pid = (int32_t)inode->fs_private[1];
        if (kernel_proc_task_fs_snapshot(
                pid,
                inode->fs_private[0] == PROC_PID_CWD ? out : 0,
                inode->fs_private[0] == PROC_PID_CWD ? max : 0,
                inode->fs_private[0] == PROC_PID_ROOT ? out : 0,
                inode->fs_private[0] == PROC_PID_ROOT ? max : 0) < 0)
            return -1;
        length = (uint32_t)strlen(out);
        if (!length || max < length) return -1;
        return (int)length;
    }
    if (inode && (inode->fs_private[0] == PROC_PID_EXE ||
                  inode->fs_private[0] == PROC_SELF_EXE)) {
        kernel_proc_task_snapshot_t task;
        int32_t pid = inode->fs_private[0] == PROC_SELF_EXE ?
            proc_current_tgid() : (int32_t)inode->fs_private[1];
        if (pid <= 0) return -1;
        if (kernel_proc_task_snapshot(pid, &task) < 0)
            return -1;
        length = (uint32_t)strlen(task.exec_path);
        if (!length || max < length) return -1;
        memcpy(out, task.exec_path, length);
        return (int)length;
    }
    if (inode && inode->fs_private[0] == PROC_SELF_FD_ENTRY) {
        return kernel_procfd_readlink_target(
            (int32_t)inode->fs_private[1],
            (int32_t)inode->fs_private[2], out, max);
    }
    return -1;
}

static int proc_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t index,
                        char *name, vfs_inode_t *out) {
    static const char *const root_names[] = {
        "mounts", "mountinfo", "filesystems", "devices", "cmdline", "version",
        "cgroups", "uptime", "meminfo", "vmstat", "zoneinfo", "buddyinfo",
        "pagetypeinfo", "pressure", "cpuinfo", "stat", "schedstat", "loadavg", "swaps", "kmsg",
        "ioports", "modules", "diskstats", "net", "tty", "sys", "self"
    };
    (void)sb;
    if (!dir || !name || !out) return -1;
    if (dir->fs_private[0] == PROC_SELF_FD) {
        int32_t pid = (int32_t)dir->fs_private[1];
        uint32_t fd;
        uint32_t descriptor;
        char reversed[16];
        uint32_t digits = 0;
        uint32_t position = 0;
        if (arch_procfd_at(pid, index, &fd) < 0) return -1;
        descriptor = fd;
        do {
            reversed[digits++] = (char)('0' + fd % 10u);
            fd /= 10u;
        } while (fd && digits < sizeof(reversed));
        while (digits) name[position++] = reversed[--digits];
        name[position] = 0;
        inode_set_pid(out, PROC_SELF_FD_ENTRY, pid,
                      VFS_INODE_LNK | 0777);
        out->ino ^= descriptor * 131u;
        out->fs_private[2] = descriptor;
        out->size = 64u;
        return 0;
    }
    if (dir->fs_private[0] == PROC_SELF) {
        static const char *const self_names[] = {
            "exe", "cwd", "root", "fd", "fdinfo", "ns", "mounts", "mountinfo", "stat", "statm", "status",
            "sched", "schedstat", "maps", "smaps", "smaps_rollup", "cmdline", "comm", "environ", "syscall", "task", "cgroup", "oom_score_adj",
            "uid_map", "gid_map", "setgroups"
        };
        if (index >= sizeof(self_names) / sizeof(self_names[0])) return -1;
        strcpy(name, self_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SELF_FDINFO) {
        int32_t pid = (int32_t)dir->fs_private[1];
        uint32_t descriptor;
        char reversed[16];
        uint32_t digits = 0;
        uint32_t position = 0;
        if (arch_procfd_at(pid, index, &descriptor) < 0) return -1;
        do {
            reversed[digits++] = (char)('0' + descriptor % 10u);
            descriptor /= 10u;
        } while (descriptor && digits < sizeof(reversed));
        while (digits) name[position++] = reversed[--digits];
        name[position] = 0;
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_PID_DIR) {
        static const char *const pid_names[] = {
            "mounts", "mountinfo", "stat", "statm", "status", "sched", "schedstat", "maps", "smaps", "smaps_rollup", "cmdline",
            "comm", "environ", "exe", "cwd", "root", "fd", "fdinfo", "ns",
            "syscall", "task", "cgroup", "oom_score_adj", "uid_map",
            "gid_map", "setgroups"
        };
        uint32_t count = sizeof(pid_names) / sizeof(pid_names[0]);
        if (index >= count) return -1;
        strcpy(name, pid_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_PID_TASK) {
        int32_t tid;
        char reversed[16];
        uint32_t digits = 0, position = 0;
        if (kernel_proc_thread_at((int32_t)dir->fs_private[1], index, &tid) < 0)
            return -1;
        do { reversed[digits++] = (char)('0' + (uint32_t)tid % 10u); tid /= 10; }
        while (tid && digits < sizeof(reversed));
        while (digits) name[position++] = reversed[--digits];
        name[position] = 0;
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_THREAD_DIR) {
        static const char *const thread_names[] = {
            "mounts", "mountinfo", "stat", "statm", "status", "sched", "schedstat", "maps", "smaps", "smaps_rollup", "cmdline",
            "comm", "exe", "cwd", "root", "syscall", "cgroup",
            "oom_score_adj"
        };
        if (index >= sizeof(thread_names) / sizeof(thread_names[0])) return -1;
        strcpy(name, thread_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SELF_NS || dir->fs_private[0] == PROC_PID_NS) {
        if (index >= sizeof(g_namespace_names) / sizeof(g_namespace_names[0])) return -1;
        strcpy(name, g_namespace_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS) {
        static const char *const sys_names[] = {"kernel", "fs", "net"};
        if (index >= sizeof(sys_names) / sizeof(sys_names[0])) return -1;
        strcpy(name, sys_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_PRESSURE) {
        if (index) return -1;
        strcpy(name, "memory");
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_NET) {
        static const char *const net_names[] = {"bridge", "ipv4", "ipv6"};
        if (index >= sizeof(net_names) / sizeof(net_names[0])) return -1;
        strcpy(name, net_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_NET_BRIDGE) {
        static const char *const bridge_names[] = {
            "bridge-nf-call-iptables", "bridge-nf-call-ip6tables",
            "bridge-nf-call-arptables"
        };
        if (index >= sizeof(bridge_names) / sizeof(bridge_names[0]))
            return -1;
        strcpy(name, bridge_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_NET_IPV4) {
        static const char *const ipv4_names[] = {
            "ip_forward", "ip_local_port_range"
        };
        if (index >= sizeof(ipv4_names) / sizeof(ipv4_names[0])) return -1;
        strcpy(name, ipv4_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_NET_IPV6) {
        if (index) return -1;
        strcpy(name, "conf");
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_NET_IPV6_CONF) {
        edge_net_device_snapshot_t snapshot;

        if (index == 0u) {
            strcpy(name, "all");
        } else if (index == 1u) {
            strcpy(name, "default");
        } else if (index == 2u) {
            strcpy(name, "lo");
        } else if (edge_net_device_snapshot_at(
                       proc_net_current_namespace(), index - 3u,
                       &snapshot) == EDGE_NET_OK) {
            strcpy(name, snapshot.configuration.name);
        } else {
            return -1;
        }
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_NET_IPV6_CONF_SCOPE) {
        static const char *const setting_names[] = {
            "disable_ipv6", "forwarding", "accept_ra", "autoconf"
        };
        if (index >= sizeof(setting_names) / sizeof(setting_names[0]))
            return -1;
        strcpy(name, setting_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_FS) {
        static const char *const fs_names[] = {
            "file-max", "nr_open", "inotify"
        };
        if (index >= sizeof(fs_names) / sizeof(fs_names[0])) return -1;
        strcpy(name, fs_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_FS_INOTIFY) {
        static const char *const inotify_names[] = {
            "max_queued_events", "max_user_instances", "max_user_watches"
        };
        if (index >= sizeof(inotify_names) / sizeof(inotify_names[0]))
            return -1;
        strcpy(name, inotify_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_KERNEL) {
        static const char *const kernel_names[] = {
            "overflowuid", "overflowgid", "hostname", "domainname",
            "threads-max", "ostype", "osrelease", "version", "keys",
            "random"
        };
        if (index >= sizeof(kernel_names) / sizeof(kernel_names[0])) return -1;
        strcpy(name, kernel_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_KERNEL_KEYS) {
        if (index) return -1;
        strcpy(name, "root_maxkeys");
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_SYS_KERNEL_RANDOM) {
        if (index) return -1;
        strcpy(name, "boot_id");
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_NET_DIR) {
        static const char *const net_names[] = {
            "dev", "arp", "if_inet6", "ipv6_route", "snmp6"
        };
        if (index >= sizeof(net_names) / sizeof(net_names[0])) return -1;
        strcpy(name, net_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_TTY) {
        static const char *const tty_names[] = {
            "driver", "drivers", "ldiscs"
        };
        if (index >= sizeof(tty_names) / sizeof(tty_names[0])) return -1;
        strcpy(name, tty_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_TTY_DRIVER) {
        if (index) return -1;
        strcpy(name, "serial");
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_ASOUND) {
        static const char *const sound_names[] = {
            "cards", "devices", "pcm", "version", "timers", "card0"
        };
        if (!arch_proc_sound_available() ||
            index >= sizeof(sound_names) / sizeof(sound_names[0]))
            return -1;
        strcpy(name, sound_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_ASOUND_CARD0) {
        if (!arch_proc_sound_available()) return -1;
        if (!index) {
            strcpy(name, "id");
        } else {
            --index;
            if (alsa_playback_available()) {
                if (!index) {
                    strcpy(name, "pcm0p");
                    return proc_lookup(&g_proc_sb, dir, name, out);
                }
                --index;
            }
            if (alsa_capture_available() && !index) {
                strcpy(name, "pcm0c");
            } else {
                return -1;
            }
        }
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_ASOUND_PCM0P) {
        static const char *const pcm_names[] = { "info", "sub0" };
        if (!alsa_playback_available() ||
            index >= sizeof(pcm_names) / sizeof(pcm_names[0]))
            return -1;
        strcpy(name, pcm_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_ASOUND_PCM0P_SUB0) {
        static const char *const substream_names[] = {
            "info", "status", "hw_params"
        };
        if (!alsa_playback_available() ||
            index >= sizeof(substream_names) / sizeof(substream_names[0]))
            return -1;
        strcpy(name, substream_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_ASOUND_PCM0C) {
        static const char *const pcm_names[] = { "info", "sub0" };
        if (!alsa_capture_available() ||
            index >= sizeof(pcm_names) / sizeof(pcm_names[0]))
            return -1;
        strcpy(name, pcm_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] == PROC_ASOUND_PCM0C_SUB0) {
        static const char *const substream_names[] = {
            "info", "status", "hw_params"
        };
        if (!alsa_capture_available() ||
            index >= sizeof(substream_names) / sizeof(substream_names[0]))
            return -1;
        strcpy(name, substream_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    if (dir->fs_private[0] != PROC_ROOT) return -1;
    if (index < sizeof(root_names) / sizeof(root_names[0])) {
        strcpy(name, root_names[index]);
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
    index -= (uint32_t)(sizeof(root_names) / sizeof(root_names[0]));
    if (arch_proc_sound_available()) {
        if (!index) {
            strcpy(name, "asound");
            return proc_lookup(&g_proc_sb, dir, name, out);
        }
        --index;
    }
    {
        int32_t pid;
        char reversed[16];
        uint32_t digits = 0, position = 0;
        if (kernel_proc_task_at(index, &pid) < 0)
            return -1;
        do { reversed[digits++] = (char)('0' + (uint32_t)pid % 10u); pid /= 10; }
        while (pid && digits < sizeof(reversed));
        while (digits) name[position++] = reversed[--digits];
        name[position] = 0;
        return proc_lookup(&g_proc_sb, dir, name, out);
    }
}

static int proc_statfs(vfs_superblock_t *sb, uint32_t *total, uint32_t *used) {
    (void)sb;
    if (!total || !used) return -1;
    *total = 0;
    *used = 0;
    return 0;
}

static int proc_truncate(vfs_superblock_t *sb, vfs_inode_t *inode,
                         uint32_t length) {
    (void)sb;
    /* Linux permits O_TRUNC on writable proc control files. */
    if (!inode || length != 0) return -1;
    return proc_node_is_writable(inode->fs_private[0]) ? 0 : -1;
}

static filesystem_ops_t g_proc_ops = {
    .lookup = proc_lookup,
    .read = proc_read,
    .write = proc_write,
    .readlink = proc_readlink,
    .truncate = proc_truncate,
    .readdir = proc_readdir,
    .statfs = proc_statfs,
};

int procfs_mount(const char *dev, const char *target) {
    if (!target || vfs_mount_exists(target, "proc", dev && dev[0] ? dev : "proc")) return target ? 0 : -1;
    memset(&g_proc_sb, 0, sizeof(g_proc_sb));
    strcpy(g_proc_sb.fs_name, "proc");
    strcpy(g_proc_sb.dev_name, dev && dev[0] ? dev : "proc");
    strcpy(g_proc_sb.mountpoint, target);
    inode_set(&g_proc_sb.root, PROC_ROOT, VFS_INODE_DIR | 0555);
    g_proc_sb.ops = &g_proc_ops;
    for (uint32_t i = 0; i < 4u; ++i)
        g_proc_snapshot.guard[i] = 0x4544474550524f43ULL ^ i;
    g_proc_guard_armed = 1;
    return vfs_add_superblock(&g_proc_sb);
}
