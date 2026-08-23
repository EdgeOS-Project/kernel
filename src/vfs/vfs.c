#include "vfs/vfs.h"
#include "vfs/filesystem_registry.h"
#include "fs/squashfs.h"
#include "fs/erofs.h"
#include "fs/xfs.h"
#include "fs/btrfs.h"
#include "vfs/mount_namespace.h"
#include "vfs/path_cache.h"
#include "fs/tmpfs.h"
#include "fs/sysfs.h"
#include "fs/cgroupfs.h"
#include "kernel/linux_errno.h"
#include "kernel/fs_context.h"
#include "kernel/drm_runtime.h"
#include "kernel/console_device.h"
#include "kernel/input_device.h"
#include "kernel/process_runtime.h"
#include "string.h"
#include "stdio.h"
#include "console.h"
#include "keyboard.h"
#include "serial_console.h"
#include "fb.h"
#include "fb_console.h"
#include "dev/fbdev.h"
#include "dev/devtmpfs.h"
#include "dev/memdev.h"
#include "dev/alsa.h"
#include "dev/uvc.h"
#include "kernel/random.h"
#include "sys/bootlog.h"
#include "sys/process.h"
#include "sys/syscall.h"
#include "drivers/rtc.h"
#ifdef CONFIG_VIRTIO_CONSOLE
#include "drivers/virtio_console.h"
#endif
#ifdef CONFIG_HPET
#include "drivers/hpet.h"
#endif
#ifdef CONFIG_WATCHDOG
#include "drivers/watchdog.h"
#endif
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO)
#include "drivers/audio.h"
#endif
#ifdef CONFIG_PCI
#include "drivers/pci.h"
#endif
#include "drivers/acpi.h"

typedef struct { char name[VFS_NAME_MAX]; uint16_t mode; uint16_t kind; void *ptr; } devnode_t;
#define ENOSYS 38
#define EINVAL 22
#define EACCES 13
#define ENOSPC 28

#ifndef EDGE_SECURITY_DEBUG
#define EDGE_SECURITY_DEBUG 0
#endif

enum {
    DEV_KIND_NONE = 0,
    DEV_KIND_BLOCK,
    DEV_KIND_TTY0,
    DEV_KIND_SERIAL0,
    DEV_KIND_NULL,
    DEV_KIND_ZERO,
    DEV_KIND_FULL,
    DEV_KIND_FB0,
    DEV_KIND_RANDOM,
    DEV_KIND_URANDOM,
    DEV_KIND_PTMX,
    DEV_KIND_UINPUT,
    DEV_KIND_DRI,
    DEV_KIND_HVC0,
    DEV_KIND_RTC,
    DEV_KIND_WATCHDOG,
    DEV_KIND_DSP,
    DEV_KIND_MIXER,
    DEV_KIND_VIDEO0
};

#define g_mount_table (*vfs_mount_namespace_active_table())
#define g_mount_at(index) \
    (*vfs_mount_table_at(&g_mount_table, (uint32_t)(index)))
#define g_mount_count (g_mount_table.mount_count)
#define g_next_mount_peer_group (g_mount_table.next_peer_group)
#define g_next_mount_id (g_mount_table.next_mount_id)
static char g_cwd[VFS_PATH_MAX] = "/";
static devnode_t g_devnodes[BLOCK_MAX_DEVICES + EDGE_FB_VT_COUNT + 48];
static int g_devnode_count;

// Turn on FS debug for more verbose output during path resolution and operations.
//#define VFS_DEBUG(fmt, ...) printf("[vfs] " fmt "\n", ##__VA_ARGS__)
#define VFS_DEBUG(fmt, ...) ((void)0)

static int path_split_last(const char *path, char *parent, char *leaf);
static int sys_tty_node_dev(const char *name, uint32_t *major,
                            uint32_t *minor);
static int vfs_resolve_inner(const char *path, vfs_inode_t *out_inode, vfs_superblock_t **out_sb,
                             vfs_inode_t *out_parent, char *leaf, int symlink_depth,
                             int follow_final_symlink, char *resolved,
                             uint32_t resolved_capacity,
                             const char *resolution_root);
static void normalize_path(const char *in, char *out);
static int path_append_limited(char *dst, uint32_t max, const char *src);
static vfs_superblock_t *vfs_find_mount(const char *path);
static int mount_path_is_at_or_below(const char *mountpoint,
                                     const char *target);
static int mount_path_copy_join(char out[VFS_PATH_MAX], const char *prefix,
                                const char *suffix);

static int vfs_superblock_index(const vfs_superblock_t *sb) {
    if (!sb) return -1;
    for (int i = 0; i < g_mount_count; ++i) {
        if (&g_mount_at(i) == sb) return i;
    }
    return -1;
}

static int vfs_path_cache_allowed(const char *path) {
    vfs_superblock_t *sb = path ? vfs_find_mount(path) : 0;
    return !sb || !(sb->runtime_flags & VFS_SUPERBLOCK_DYNAMIC_LOOKUP);
}

static int vfs_path_cache_lookup(const char *abs, vfs_inode_t *inode,
                                 uint32_t *sb_index, int *miss) {
    vfs_path_cache_result_t result;
    if (!vfs_path_cache_allowed(abs)) return 0;
    if (!vfs_path_cache_runtime_lookup(
            abs, vfs_mount_namespace_current(), &result))
        return 0;
    if (miss) *miss = result.miss != 0;
    if (inode) *inode = result.inode;
    if (sb_index) *sb_index = result.superblock_index;
    return 1;
}

static void vfs_path_cache_store(const char *abs, int miss, const vfs_inode_t *inode, const vfs_superblock_t *sb) {
    int sb_index = 0;
    if (!vfs_path_cache_allowed(abs)) return;
    if (!miss) {
        if (!inode || !sb) return;
        sb_index = vfs_superblock_index(sb);
        if (sb_index < 0) return;
    }
    vfs_path_cache_runtime_store(
        abs, vfs_mount_namespace_current(), miss, inode,
        (uint32_t)sb_index);
}

void vfs_path_cache_seed(const char *path, const vfs_inode_t *inode, const vfs_superblock_t *sb) {
    char abs[VFS_PATH_MAX];
    if (!path || !inode || !sb ||
        (sb->runtime_flags & VFS_SUPERBLOCK_DYNAMIC_LOOKUP)) return;
    if ((inode->mode & 0xF000u) == VFS_INODE_LNK) return;
    normalize_path(path, abs);
    /*
     * A readdir inode belongs to the directory's filesystem, but the child
     * path may cross a mount boundary or normalize through "..".  Linux path
     * lookup follows the mounted filesystem at that path.  Never let a
     * readdir optimization seed an underlying or parent filesystem object for
     * the visible path; doing so can make concurrent scans of /proc and /
     * exchange superblocks.
     */
    if (vfs_find_mount(abs) != sb) return;
    vfs_path_cache_store(abs, 0, inode, sb);
}

#ifdef CONFIG_FS_EXT2
extern int ext2_mount(const char *dev, const char *target);
extern int ext2_mount_block(block_device_t *bdev, const char *target);
extern int ext2_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                        uint16_t mode, uint32_t uid, uint32_t gid,
                        uint32_t mask);
#endif
#ifdef CONFIG_FS_EXT4
extern int ext4_mount(const char *dev, const char *target);
extern int ext4_mount_block(block_device_t *bdev, const char *target);
extern int ext4_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                        uint16_t mode, uint32_t uid, uint32_t gid,
                        uint32_t mask);
extern int ext4_settimes(vfs_superblock_t *sb, const vfs_inode_t *inode, uint32_t atime, uint32_t mtime, int set_atime, int set_mtime);
#endif
#ifdef CONFIG_FS_FAT32
extern int fat32_mount(const char *dev, const char *target);
extern int fat32_mount_block(block_device_t *bdev, const char *target);
#endif
#ifdef CONFIG_FS_EXFAT
extern int exfat_mount(const char *dev, const char *target);
extern int exfat_mount_block(block_device_t *bdev, const char *target);
#endif
#ifdef CONFIG_FS_NTFS
extern int ntfs_mount(const char *dev, const char *target);
extern int ntfs_mount_block(block_device_t *bdev, const char *target);
#endif
#ifdef CONFIG_FS_ISO9660
extern int iso9660_mount(const char *dev, const char *target);
extern int iso9660_mount_block(block_device_t *bdev, const char *target);
#endif
#ifdef CONFIG_FS_UDF
extern int udf_mount(const char *dev, const char *target);
extern int udf_mount_block(block_device_t *bdev, const char *target);
#endif
extern int procfs_mount(const char *dev, const char *target);
#ifdef CONFIG_OVERLAY_FS
extern int overlayfs_mount(const char *dev, const char *target);
#endif

static int vfs_add_devnode(const char *name, uint16_t mode, uint16_t kind, void *ptr) {
    if (g_devnode_count >= (int)(sizeof(g_devnodes) / sizeof(g_devnodes[0]))) return -1;
    strcpy(g_devnodes[g_devnode_count].name, name);
    g_devnodes[g_devnode_count].mode = mode;
    g_devnodes[g_devnode_count].kind = kind;
    g_devnodes[g_devnode_count].ptr = ptr;
    g_devnode_count++;
    return 0;
}

static void vfs_inode_set_ptr(vfs_inode_t *ino, void *p) {
    uintptr_t v = (uintptr_t)p;
    ino->fs_private[0] = (uint32_t)(v & 0xFFFFFFFFu);
    ino->fs_private[1] = (uint32_t)((v >> 32) & 0xFFFFFFFFu);
}

static void *vfs_inode_get_ptr(const vfs_inode_t *ino) {
    uintptr_t v = (uintptr_t)ino->fs_private[0] | ((uintptr_t)ino->fs_private[1] << 32);
    return (void *)v;
}

static void vfs_build_devnodes(void) {
    kernel_console_device_t serial;
    char tty_name[8];

    g_devnode_count = 0;
    for (int i = 0; i < block_count(); ++i) {
        block_device_t *b = block_get(i);
        if (!b || !b->present) continue;
        if (vfs_add_devnode(b->name, VFS_INODE_BLK | 0660, DEV_KIND_BLOCK, b) < 0) break;
    }
    vfs_add_devnode("console", VFS_INODE_CHR | 0666, DEV_KIND_TTY0, 0);
    vfs_add_devnode("tty0", VFS_INODE_CHR | 0666, DEV_KIND_TTY0, 0);
    for (uint32_t vt = 1u; vt <= EDGE_FB_VT_COUNT; ++vt) {
        uint32_t offset = 3u;

        memcpy(tty_name, "tty", 3u);
        if (vt >= 10u) tty_name[offset++] = (char)('0' + vt / 10u);
        tty_name[offset++] = (char)('0' + vt % 10u);
        tty_name[offset] = 0;
        vfs_add_devnode(tty_name, VFS_INODE_CHR | 0666, DEV_KIND_TTY0, 0);
    }
    vfs_add_devnode("tty", VFS_INODE_CHR | 0666, DEV_KIND_TTY0, 0);
    if (kernel_arch_serial_console_device(&serial) == 0)
        vfs_add_devnode(serial.name, VFS_INODE_CHR | 0666,
                        DEV_KIND_SERIAL0, 0);
#ifdef CONFIG_VIRTIO_CONSOLE
    vfs_add_devnode("hvc0", VFS_INODE_CHR | 0666, DEV_KIND_HVC0, 0);
#endif
#ifdef CONFIG_RTC
    vfs_add_devnode("rtc", VFS_INODE_CHR | 0666, DEV_KIND_RTC, 0);
    vfs_add_devnode("rtc0", VFS_INODE_CHR | 0666, DEV_KIND_RTC, 0);
#endif
#ifdef CONFIG_WATCHDOG
    if (watchdog_available()) {
        vfs_add_devnode("watchdog", VFS_INODE_CHR | 0600, DEV_KIND_WATCHDOG, 0);
        vfs_add_devnode("watchdog0", VFS_INODE_CHR | 0600, DEV_KIND_WATCHDOG, 0);
    }
#endif
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO)
    if (audio_available()) {
        vfs_add_devnode("dsp", VFS_INODE_CHR | 0660, DEV_KIND_DSP, 0);
        vfs_add_devnode("audio", VFS_INODE_CHR | 0660, DEV_KIND_DSP, 0);
        vfs_add_devnode("mixer", VFS_INODE_CHR | 0660, DEV_KIND_MIXER, 0);
    }
#endif
    vfs_add_devnode("null", VFS_INODE_CHR | 0666, DEV_KIND_NULL, 0);
    vfs_add_devnode("zero", VFS_INODE_CHR | 0666, DEV_KIND_ZERO, 0);
    vfs_add_devnode("full", VFS_INODE_CHR | 0666, DEV_KIND_FULL, 0);
    vfs_add_devnode("fb0", VFS_INODE_CHR | 0660, DEV_KIND_FB0, 0);
    vfs_add_devnode("random", VFS_INODE_CHR | 0666, DEV_KIND_RANDOM, 0);
    vfs_add_devnode("urandom", VFS_INODE_CHR | 0666, DEV_KIND_URANDOM, 0);
    vfs_add_devnode("ptmx", VFS_INODE_CHR | 0666, DEV_KIND_PTMX, 0);
    vfs_add_devnode("uinput", VFS_INODE_CHR | 0660, DEV_KIND_UINPUT, 0);
#ifdef CONFIG_USB_UVC
    if (uvc_available()) vfs_add_devnode("video0", VFS_INODE_CHR | 0660, DEV_KIND_VIDEO0, 0);
#endif
}

static int vfs_devnode_find(const char *name) {
    for (int i = 0; i < g_devnode_count; ++i) {
        if (strcmp(g_devnodes[i].name, (char *)name) == 0) return i;
    }
    return -1;
}

static uint32_t vfs_linux_device_major(uint64_t device) {
    return (uint32_t)((device >> 8) & 0xfffu) |
           (uint32_t)((device >> 32) & ~0xfffull);
}

static uint32_t vfs_linux_device_minor(uint64_t device) {
    return (uint32_t)(device & 0xffu) |
           (uint32_t)((device >> 12) & ~0xffull);
}

static int vfs_devnode_find_kind(uint16_t kind) {
    for (int i = 0; i < g_devnode_count; ++i) {
        if (g_devnodes[i].kind == kind) return i;
    }
    return -1;
}

static int vfs_devnode_from_inode(const vfs_inode_t *ino) {
    uint32_t major;
    uint32_t minor;
    if (!ino) return -1;
    if (ino->ino >= 0xD0000000u) {
        uint32_t idx = ino->ino - 0xD0000000u;
        if (idx < (uint32_t)g_devnode_count) return (int)idx;
    }

    /*
     * Once devtmpfs is mounted, device inodes are ordinary filesystem
     * objects and no longer carry EdgeOS' early synthetic inode numbers.
     * Linux dispatches character devices by st_rdev, so recognize the same
     * stable major/minor identities here.  Falling back to an inode-number
     * test makes a driver disappear as soon as userspace mounts devtmpfs.
     */
    if ((ino->mode & 0xf000u) != VFS_INODE_CHR || ino->rdev == 0) return -1;
    major = vfs_linux_device_major(ino->rdev);
    minor = vfs_linux_device_minor(ino->rdev);
    if (major == 1u) {
        switch (minor) {
            case 3u: return vfs_devnode_find_kind(DEV_KIND_NULL);
            case 5u: return vfs_devnode_find_kind(DEV_KIND_ZERO);
            case 7u: return vfs_devnode_find_kind(DEV_KIND_FULL);
            case 8u: return vfs_devnode_find_kind(DEV_KIND_RANDOM);
            case 9u: return vfs_devnode_find_kind(DEV_KIND_URANDOM);
            default: return -1;
        }
    }
    if (major == 4u && minor <= EDGE_FB_VT_COUNT)
        return vfs_devnode_find_kind(DEV_KIND_TTY0);
    if (major == 4u && minor == 64u)
        return vfs_devnode_find_kind(DEV_KIND_SERIAL0);
    if (major == 204u && minor == 64u)
        return vfs_devnode_find_kind(DEV_KIND_SERIAL0);
    if (major == 5u) {
        if (minor <= 1u) return vfs_devnode_find_kind(DEV_KIND_TTY0);
        if (minor == 2u) return vfs_devnode_find_kind(DEV_KIND_PTMX);
    }
    if (major == 10u && minor == 223u)
        return vfs_devnode_find_kind(DEV_KIND_UINPUT);
    if (major == 29u && minor == 0u)
        return vfs_devnode_find_kind(DEV_KIND_FB0);
    if (major == 81u && minor == 0u)
        return vfs_devnode_find_kind(DEV_KIND_VIDEO0);
    if (major == 229u && minor == 0u)
        return vfs_devnode_find_kind(DEV_KIND_HVC0);
    if (major == 254u && minor == 0u)
        return vfs_devnode_find_kind(DEV_KIND_RTC);
    return -1;
}

static uint64_t vfs_memory_device_rdev(uint16_t kind, const char *name) {
    uint32_t minor;

    if (kind == DEV_KIND_TTY0 && name) {
        uint32_t major;

        if (sys_tty_node_dev(name, &major, &minor))
            return ((uint64_t)major << 8) | minor;
    }
    switch (kind) {
        case DEV_KIND_NULL: minor = 3u; break;
        case DEV_KIND_ZERO: minor = 5u; break;
        case DEV_KIND_FULL: minor = 7u; break;
        case DEV_KIND_RANDOM: minor = 8u; break;
        case DEV_KIND_URANDOM: minor = 9u; break;
        default: return 0;
    }
    return (1ull << 8) | minor;
}

static int vfs_read_tty(char *out, uint32_t max) {
    if (max == 0) return 0;
    uint32_t i = 0;
    for (; i < max; ++i) {
        int ch = keyboard_getchar();
        if (ch < 0) break;
        out[i] = (char)ch;
        if ((char)ch == '\n') {
            ++i;
            break;
        }
    }
    return (int)i;
}

static int vfs_dev_read_chr(const devnode_t *dn, char *out, uint32_t max) {
    if (!dn) return -1;
    switch (dn->kind) {
        case DEV_KIND_TTY0:
            return vfs_read_tty(out, max);
        case DEV_KIND_SERIAL0: {
            uint32_t count = 0;
            while (count < max) {
                int ch = serial_console_pollchar();
                if (ch < 0) break;
                out[count++] = (char)ch;
            }
            return (int)count;
        }
#ifdef CONFIG_VIRTIO_CONSOLE
        case DEV_KIND_HVC0:
            return virtio_console_read(out, max);
#endif
#ifdef CONFIG_RTC
        case DEV_KIND_RTC: {
            struct edge_rtc_time tm;
            uint32_t v = 0;
            if (max == 0) return 0;
            /*
             * Linux /dev/rtc reads normally return interrupt event counters.
             * EdgeOS does not enable periodic RTC IRQ delivery yet, so provide
             * a deterministic readable counter based on a fresh CMOS sample and
             * keep the richer Linux ABI on ioctl(RTC_RD_TIME).  Do not block
             * forever here; simple diagnostics sometimes read the node to test
             * whether it is alive.
             */
            if (rtc_read_time(&tm) == 0) {
                v = (uint32_t)(tm.tm_sec | (tm.tm_min << 8) | (tm.tm_hour << 16));
            }
            if (max > sizeof(v)) max = sizeof(v);
            memcpy(out, &v, max);
            return (int)max;
        }
#endif
#ifdef CONFIG_WATCHDOG
        case DEV_KIND_WATCHDOG:
            /*
             * Linux watchdog devices are controlled by writes and WDIOC_*
             * ioctls.  There is no event stream for this i6300ESB-backed
             * implementation, so reads fail with ENOSYS instead of blocking
             * forever or returning invented data.
             */
            return -ENOSYS;
#endif
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO)
        case DEV_KIND_DSP:
        case DEV_KIND_MIXER:
            return -ENOSYS;
#endif
        case DEV_KIND_NULL:
            return 0;
        case DEV_KIND_ZERO:
        case DEV_KIND_FULL:
            if (max) memset(out, 0, max);
            return (int)max;
        case DEV_KIND_FB0: {
            uint32_t fb_bytes;
            uint32_t n;
            const uint8_t *src;
            if (!fb.addr || fb.pitch == 0 || fb.height == 0) return -1;
            fb_bytes = fb.pitch * fb.height;
            n = (max < fb_bytes) ? max : fb_bytes;
            /*
             * /dev/fb0 is readable on Linux.  A short read from offset zero is
             * used by diagnostics and simple framebuffer tools to inspect the
             * current visible memory.  Offset-aware pread/read iteration is
             * handled by the syscall/VFS layer; this character-device helper
             * supplies the bytes for reads starting at the device position.
             * Red flag: keep this tied to framebuffer memory, not the console
             * backbuffer, once userspace mmap owns fbdev.
             */
            src = fb_user_mmap_active() ? fb.addr : fb_get_draw_buffer();
            if (!src) src = fb.addr;
            if (n) memcpy(out, src, n);
            return (int)n;
        }
        case DEV_KIND_RANDOM:
            edge_random_fill(out, max);
            return (int)max;
        case DEV_KIND_URANDOM:
            edge_random_fill(out, max);
            return (int)max;
        case DEV_KIND_PTMX:
        case DEV_KIND_UINPUT:
        case DEV_KIND_DRI:
            return -ENOSYS;
        case DEV_KIND_VIDEO0:
            return uvc_read(EDGE_UVC_PATH_VIDEO0, out, max);
        default:
            return -1;
    }
}

static int vfs_dev_write_chr(const devnode_t *dn, const char *buf, uint32_t len) {
    if (!dn) return -1;
    switch (dn->kind) {
        case DEV_KIND_TTY0:
            for (uint32_t i = 0; i < len; ++i) {
                serial_console_write_raw(buf[i]);
                console_putchar(buf[i]);
            }
            return (int)len;
        case DEV_KIND_SERIAL0:
            for (uint32_t i = 0; i < len; ++i) serial_console_write_raw(buf[i]);
            return (int)len;
#ifdef CONFIG_VIRTIO_CONSOLE
        case DEV_KIND_HVC0:
            return virtio_console_write(buf, len);
#endif
#ifdef CONFIG_RTC
        case DEV_KIND_RTC:
            return -ENOSYS;
#endif
#ifdef CONFIG_WATCHDOG
        case DEV_KIND_WATCHDOG:
            return watchdog_write(buf, len);
#endif
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO)
        case DEV_KIND_DSP:
            return audio_write_pcm(buf, len);
        case DEV_KIND_MIXER:
            return audio_mixer_write(buf, len);
#endif
        case DEV_KIND_NULL:
        case DEV_KIND_ZERO:
            return (int)len;
        case DEV_KIND_FULL:
            return -ENOSPC;
        case DEV_KIND_FB0: {
            uint32_t fb_bytes;
            uint32_t n;
            uint8_t *dst;
            if (!fb.addr || fb.pitch == 0 || fb.height == 0) return -1;
            fb_bytes = fb.pitch * fb.height;
            n = (len < fb_bytes) ? len : fb_bytes;
            dst = fb_get_draw_buffer();
            if (!dst) dst = fb.addr;
            if (n) memcpy(dst, buf, n);
            if (dst != fb.addr) fb_present();
            return (int)n;
        }
        case DEV_KIND_RANDOM:
        case DEV_KIND_URANDOM:
            edge_random_mix(buf, len);
            return (int)len;
        case DEV_KIND_PTMX:
        case DEV_KIND_UINPUT:
        case DEV_KIND_DRI:
        case DEV_KIND_VIDEO0:
            return -ENOSYS;
        default:
            return -1;
    }
}

static int parse_decimal_str(const char *s, int *out) {
    int v = 0;
    if (!s || !s[0] || !out) return -1;
    for (const char *p = s; *p; ++p) {
        if (*p < '0' || *p > '9') return -1;
        v = v * 10 + (*p - '0');
        if (v < 0 || v > 1000000) return -1;
    }
    *out = v;
    return 0;
}

static int dev_input_is_mouse_stream(const char *name) {
    if (!name) return 0;
    return strcmp(name, "input/mice") == 0 || strcmp(name, "input/mouse0") == 0;
}

static int dev_input_is_event_stream(const char *name) {
    int n = 0;
    if (!name) return 0;
    if (strncmp(name, "input/event", 11) != 0) return 0;
    name += 11;
    if (!*name) return 0;
    while (*name >= '0' && *name <= '9') {
        n = n * 10 + (*name - '0');
        ++name;
    }
    return *name == 0 && n >= 0 &&
           n < (int)EDGE_INPUT_DEVICE_MAX &&
           input_device_present((uint32_t)n);
}

static int dev_dri_is_node(const char *name) {
    if (!name) return 0;
    if (strcmp(name, "dri/card0") == 0) return 1;
    return edge_drm_path_is_render("/dev/dri/renderD128") &&
        strcmp(name, "dri/renderD128") == 0;
}

static uint32_t synthetic_sys_ino(const char *abs) {
    uint32_t h = 2166136261u;
    if (!abs) return 0x5F500000u;
    while (*abs) {
        h ^= (uint8_t)*abs++;
        h *= 16777619u;
    }
    return 0x5F500000u | (h & 0x000FFFFFu);
}

static int sys_input_node_name(const char *name) {
    if (!name) return 0;
    if (strcmp(name, "mice") == 0 || strcmp(name, "mouse0") == 0) return 1;
    if (strncmp(name, "event", 5) == 0) {
        int n = 0;
        const char *p = name + 5;
        if (!*p) return 0;
        while (*p >= '0' && *p <= '9') {
            n = n * 10 + (*p - '0');
            ++p;
        }
        return *p == 0 && n >= 0 &&
               n < (int)EDGE_INPUT_DEVICE_MAX &&
               input_device_present((uint32_t)n);
    }
    return 0;
}

static int sys_tty_node_dev(const char *name, uint32_t *major, uint32_t *minor) {
    kernel_console_device_t serial;

    if (!name || !major || !minor) return 0;
    /*
     * These are Linux ABI-visible character device numbers, not EdgeOS
     * internals.  Keep them aligned with stat(2) for the corresponding /dev
     * nodes: 5:0 is the controlling terminal alias, 5:1 is /dev/console,
     * 4:0 is the VT multiplexer, 4:1..4:63 are the virtual terminals, and
     * 4:64 is the first 16550-compatible serial console.
     */
    if (strcmp(name, "tty") == 0) {
        *major = 5;
        *minor = 0;
        return 1;
    }
    if (strcmp(name, "console") == 0) {
        *major = 5;
        *minor = 1;
        return 1;
    }
    if (strcmp(name, "tty0") == 0) {
        *major = 4;
        *minor = 0;
        return 1;
    }
    if (kernel_arch_serial_console_device(&serial) == 0 &&
        strcmp(name, serial.name) == 0) {
        *major = serial.major;
        *minor = serial.minor;
        return 1;
    }
    if (strncmp(name, "tty", 3) == 0) {
        const char *cursor = name + 3;
        uint32_t number = 0;

        if (*cursor < '0' || *cursor > '9') return 0;
        while (*cursor >= '0' && *cursor <= '9') {
            number = number * 10u + (uint32_t)(*cursor - '0');
            if (number > EDGE_FB_VT_COUNT) return 0;
            ++cursor;
        }
        if (!*cursor && number <= EDGE_FB_VT_COUNT) {
            *major = 4u;
            *minor = number;
            return 1;
        }
    }
    return 0;
}

static int sys_tty_node_name(const char *name) {
    uint32_t major = 0;
    uint32_t minor = 0;
    return sys_tty_node_dev(name, &major, &minor);
}

static int sys_sound_node_dev(const char *name, uint32_t *major, uint32_t *minor) {
    if (!name || !major || !minor || !alsa_available()) return 0;
    *major = EDGE_ALSA_CARD_MAJOR;
    if (strcmp(name, "controlC0") == 0) {
        *minor = alsa_dev_minor_from_kind(EDGE_ALSA_NODE_CONTROL);
        return 1;
    }
    if (strcmp(name, "pcmC0D0p") == 0) {
        *minor = alsa_dev_minor_from_kind(EDGE_ALSA_NODE_PCM_PLAYBACK);
        return 1;
    }
    if (strcmp(name, "pcmC0D0c") == 0 && alsa_capture_available()) {
        *minor = alsa_dev_minor_from_kind(EDGE_ALSA_NODE_PCM_CAPTURE);
        return 1;
    }
    if (strcmp(name, "timer") == 0) {
        *minor = alsa_dev_minor_from_kind(EDGE_ALSA_NODE_TIMER);
        return 1;
    }
    return 0;
}

static int sys_sound_node_name(const char *name) {
    uint32_t major = 0;
    uint32_t minor = 0;
    if (strcmp(name ? name : "", "card0") == 0) return alsa_available();
    return sys_sound_node_dev(name, &major, &minor);
}

static int sys_power_supply_node_name(const char *name) {
#ifdef CONFIG_ACPI
#ifdef CONFIG_ACPI_AC_ADAPTER
    if (strcmp(name ? name : "", "AC") == 0) return acpi_available() && acpi_has_ac_adapter();
#endif
#ifdef CONFIG_ACPI_BATTERY
    if (strcmp(name ? name : "", "BAT0") == 0) return acpi_available() && acpi_has_battery();
#endif
#endif
    (void)name;
    return 0;
}

static int sys_power_supply_file_name(const char *node, const char *file) {
#if defined(CONFIG_ACPI)
    struct edge_acpi_battery_info information;
    uint32_t attributes;

    if (!node || !file || !sys_power_supply_node_name(node))
        return 0;
    if (strcmp(file, "type") == 0 || strcmp(file, "scope") == 0 ||
        strcmp(file, "model_name") == 0 ||
        strcmp(file, "manufacturer") == 0 ||
        strcmp(file, "uevent") == 0)
        return 1;
    if (strcmp(node, "AC") == 0)
        return strcmp(file, "online") == 0;
    if (strcmp(node, "BAT0") != 0 ||
        acpi_get_battery_info(0, &information) != 0)
        return 0;
    if (strcmp(file, "status") == 0 || strcmp(file, "present") == 0)
        return 1;
    attributes = acpi_battery_attribute_mask(&information);
    if (strcmp(file, "capacity") == 0)
        return (attributes & EDGE_ACPI_BATTERY_ATTR_CAPACITY) != 0;
    if (strcmp(file, "technology") == 0)
        return (attributes & EDGE_ACPI_BATTERY_ATTR_TECHNOLOGY) != 0;
    if (strcmp(file, "serial_number") == 0)
        return (attributes & EDGE_ACPI_BATTERY_ATTR_SERIAL) != 0;
    if (strcmp(file, "cycle_count") == 0)
        return (attributes & EDGE_ACPI_BATTERY_ATTR_CYCLE_COUNT) != 0;
    if (strcmp(file, "voltage_now") == 0)
        return (attributes & EDGE_ACPI_BATTERY_ATTR_VOLTAGE_NOW) != 0;
    if (strcmp(file, "voltage_min_design") == 0)
        return (attributes & EDGE_ACPI_BATTERY_ATTR_VOLTAGE_DESIGN) != 0;
    if (strcmp(file, "time_to_empty_now") == 0)
        return (attributes & EDGE_ACPI_BATTERY_ATTR_TIME_TO_EMPTY) != 0;
    if ((attributes & EDGE_ACPI_BATTERY_ATTR_STORAGE) != 0) {
        if (information.units == 0)
            return strcmp(file, "energy_now") == 0 ||
                   strcmp(file, "energy_full") == 0 ||
                   strcmp(file, "energy_full_design") == 0;
        if (information.units == 1)
            return strcmp(file, "charge_now") == 0 ||
                   strcmp(file, "charge_full") == 0 ||
                   strcmp(file, "charge_full_design") == 0;
    }
    if ((attributes & EDGE_ACPI_BATTERY_ATTR_RATE) != 0) {
        if (information.units == 0)
            return strcmp(file, "power_now") == 0;
        if (information.units == 1)
            return strcmp(file, "current_now") == 0;
    }
#else
    (void)node;
    (void)file;
#endif
    return 0;
}

static int sysfs_leaf_has_slash(const char *name) {
    if (!name) return 0;
    while (*name) {
        if (*name == '/') return 1;
        ++name;
    }
    return 0;
}

static int sys_class_path_mode(const char *abs, uint16_t *mode_out) {
    const char *p;
    if (!abs || !mode_out) return 0;
#ifdef CONFIG_PCI
    {
        int pci_kind = pci_sysfs_path_kind(abs);
        if (pci_kind == PCI_SYSFS_PATH_DIR) {
            *mode_out = VFS_INODE_DIR | 0755;
            return 1;
        }
        if (pci_kind == PCI_SYSFS_PATH_FILE) {
            *mode_out = VFS_INODE_FILE | 0444;
            return 1;
        }
        if (pci_kind == PCI_SYSFS_PATH_LINK) {
            *mode_out = VFS_INODE_LNK | 0777;
            return 1;
        }
    }
#endif
    {
        int block_kind = block_sysfs_path_kind(abs);
        if (block_kind == BLOCK_SYSFS_PATH_DIR) {
            *mode_out = VFS_INODE_DIR | 0755;
            return 1;
        }
        if (block_kind == BLOCK_SYSFS_PATH_FILE) {
            *mode_out = VFS_INODE_FILE | 0444;
            return 1;
        }
        if (block_kind == BLOCK_SYSFS_PATH_LINK) {
            *mode_out = VFS_INODE_LNK | 0777;
            return 1;
        }
    }
    if (strcmp(abs, "/sys") == 0 || strcmp(abs, "/sys/fs") == 0 ||
        strcmp(abs, "/sys/fs/cgroup") == 0 ||
        strcmp(abs, "/sys/class") == 0 ||
        strcmp(abs, "/sys/firmware") == 0 ||
        strcmp(abs, "/sys/devices") == 0 ||
        strcmp(abs, "/sys/devices/system") == 0 ||
        strcmp(abs, "/sys/devices/system/clocksource") == 0 ||
        strcmp(abs, "/sys/devices/system/clocksource/clocksource0") == 0 ||
        strcmp(abs, "/sys/class/drm") == 0 ||
        strcmp(abs, "/sys/class/graphics") == 0 ||
        strcmp(abs, "/sys/class/input") == 0 ||
        strcmp(abs, "/sys/class/power_supply") == 0 ||
        strcmp(abs, "/sys/class/rtc") == 0 ||
        strcmp(abs, "/sys/class/rtc/rtc0") == 0 ||
        strcmp(abs, "/sys/class/tty") == 0 ||
        strcmp(abs, "/sys/class/drm/card0") == 0 ||
        strcmp(abs, "/sys/class/graphics/fb0") == 0 ||
        strcmp(abs, "/sys/class/graphics/fb0/device") == 0) {
        *mode_out = VFS_INODE_DIR | 0755;
        return 1;
    }
    if (alsa_available() &&
        (strcmp(abs, "/sys/class/sound") == 0 ||
         strcmp(abs, "/sys/class/sound/card0") == 0)) {
        *mode_out = VFS_INODE_DIR | 0755;
        return 1;
    }
#ifdef CONFIG_ACPI
    if (acpi_available() &&
        (strcmp(abs, "/sys/firmware/acpi") == 0 ||
         strcmp(abs, "/sys/firmware/acpi/tables") == 0 ||
         strcmp(abs, "/sys/firmware/acpi/tables/dynamic") == 0)) {
        *mode_out = VFS_INODE_DIR | 0755;
        return 1;
    }
    if (acpi_available() && strcmp(abs, "/sys/firmware/acpi/pm_profile") == 0) {
        *mode_out = VFS_INODE_FILE | 0444;
        return 1;
    }
    if (acpi_available() && strncmp(abs, "/sys/firmware/acpi/tables/", 26) == 0) {
        const char *name = abs + 26;
        uint32_t sz = 0;
        if (!sysfs_leaf_has_slash(name) && acpi_sysfs_table_size(name, &sz) == 0) {
            (void)sz;
            *mode_out = VFS_INODE_FILE | 0400;
            return 1;
        }
    }
#endif
    if (strncmp(abs, "/sys/devices/system/clocksource/clocksource0/", 45) == 0) {
        const char *file = abs + 45;
        if (strcmp(file, "available_clocksource") == 0 ||
            strcmp(file, "current_clocksource") == 0) {
            *mode_out = VFS_INODE_FILE | 0444;
            return 1;
        }
    }
    p = "/sys/class/input/";
    if (strncmp(abs, p, strlen(p)) == 0) {
        const char *rest = abs + strlen(p);
        char node[VFS_NAME_MAX];
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_input_node_name(node) && rest[i] == 0) {
            *mode_out = VFS_INODE_DIR | 0755;
            return 1;
        }
        if (sys_input_node_name(node) && rest[i] == '/') {
            const char *file = rest + i + 1;
            if (strcmp(file, "dev") == 0 || strcmp(file, "name") == 0 ||
                strcmp(file, "uevent") == 0) {
                *mode_out = VFS_INODE_FILE | 0444;
                return 1;
            }
        }
    }
    p = "/sys/class/tty/";
    if (strncmp(abs, p, strlen(p)) == 0) {
        const char *rest = abs + strlen(p);
        char node[VFS_NAME_MAX];
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_tty_node_name(node) && rest[i] == 0) {
            *mode_out = VFS_INODE_DIR | 0755;
            return 1;
        }
        if (sys_tty_node_name(node) && rest[i] == '/') {
            const char *file = rest + i + 1;
            if (strcmp(file, "dev") == 0 || strcmp(file, "uevent") == 0 ||
                strcmp(file, "subsystem") == 0 ||
                ((strcmp(node, "tty0") == 0 || strcmp(node, "console") == 0) &&
                 strcmp(file, "active") == 0)) {
                *mode_out = (strcmp(file, "subsystem") == 0) ?
                    (VFS_INODE_LNK | 0777) : (VFS_INODE_FILE | 0444);
                return 1;
            }
        }
    }
    if (strncmp(abs, "/sys/class/rtc/rtc0/", 20) == 0) {
        const char *file = abs + 20;
        if (strcmp(file, "dev") == 0 || strcmp(file, "name") == 0 ||
            strcmp(file, "date") == 0 || strcmp(file, "time") == 0 ||
            strcmp(file, "since_epoch") == 0 || strcmp(file, "hctosys") == 0 ||
            strcmp(file, "max_user_freq") == 0 || strcmp(file, "uevent") == 0) {
            *mode_out = VFS_INODE_FILE | 0444;
            return 1;
        }
    }
    p = "/sys/class/power_supply/";
    if (strncmp(abs, p, strlen(p)) == 0) {
        const char *rest = abs + strlen(p);
        char node[VFS_NAME_MAX];
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_power_supply_node_name(node) && rest[i] == 0) {
            *mode_out = VFS_INODE_DIR | 0755;
            return 1;
        }
        if (sys_power_supply_node_name(node) && rest[i] == '/') {
            const char *file = rest + i + 1;
            if (sys_power_supply_file_name(node, file)) {
                *mode_out = VFS_INODE_FILE | 0444;
                return 1;
            }
        }
    }
    p = "/sys/class/sound/";
    if (strncmp(abs, p, strlen(p)) == 0) {
        const char *rest = abs + strlen(p);
        char node[VFS_NAME_MAX];
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_sound_node_name(node) && rest[i] == 0) {
            *mode_out = VFS_INODE_DIR | 0755;
            return 1;
        }
        if (sys_sound_node_name(node) && rest[i] == '/') {
            const char *file = rest + i + 1;
            if (strcmp(node, "card0") == 0) {
                if (strcmp(file, "id") == 0 || strcmp(file, "number") == 0 ||
                    strcmp(file, "uevent") == 0 || strcmp(file, "subsystem") == 0) {
                    *mode_out = (strcmp(file, "subsystem") == 0) ?
                        (VFS_INODE_LNK | 0777) : (VFS_INODE_FILE | 0444);
                    return 1;
                }
            } else if (strcmp(file, "dev") == 0 || strcmp(file, "uevent") == 0 ||
                       strcmp(file, "name") == 0 || strcmp(file, "subsystem") == 0) {
                *mode_out = (strcmp(file, "subsystem") == 0) ?
                    (VFS_INODE_LNK | 0777) : (VFS_INODE_FILE | 0444);
                return 1;
            }
        }
    }
    if (strncmp(abs, "/sys/class/drm/card0/", 21) == 0) {
        const char *file = abs + 21;
        if (strcmp(file, "dev") == 0 || strcmp(file, "uevent") == 0 ||
            strcmp(file, "status") == 0 || strcmp(file, "enabled") == 0 ||
            strcmp(file, "modes") == 0) {
            *mode_out = VFS_INODE_FILE | 0444;
            return 1;
        }
    }
    if (strncmp(abs, "/sys/class/graphics/fb0/", 24) == 0) {
        const char *file = abs + 24;
        if (strcmp(file, "dev") == 0 || strcmp(file, "name") == 0 ||
            strcmp(file, "virtual_size") == 0 || strcmp(file, "bits_per_pixel") == 0 ||
            strcmp(file, "modes") == 0) {
            *mode_out = VFS_INODE_FILE | 0444;
            return 1;
        }
        if (strcmp(file, "device") == 0 || strcmp(file, "device/subsystem") == 0 ||
            strcmp(file, "subsystem") == 0) {
            *mode_out = VFS_INODE_FILE | 0777;
            return 1;
        }
    }
    return 0;
}

static int vfs_try_resolve_syspath(const char *abs, vfs_inode_t *out_inode, vfs_superblock_t **out_sb, vfs_inode_t *out_parent) {
    uint16_t mode;
    uint16_t parent_mode;
    char parent[VFS_PATH_MAX];
    char leaf[VFS_NAME_MAX];
    if (!sys_class_path_mode(abs, &mode)) return -1;
    if (out_parent) {
        memset(out_parent, 0, sizeof(*out_parent));
        if (path_split_last(abs, parent, leaf) == 0 &&
            sys_class_path_mode(parent, &parent_mode)) {
            out_parent->ino = synthetic_sys_ino(parent);
            out_parent->mode = parent_mode;
            out_parent->uid = 0;
            out_parent->gid = 0;
            out_parent->size = 0;
        }
    }
    if (out_sb) *out_sb = 0;
    if (out_inode) {
        uint32_t size = 0;
        memset(out_inode, 0, sizeof(*out_inode));
        out_inode->ino = synthetic_sys_ino(abs);
        out_inode->mode = mode;
        out_inode->uid = 0;
        out_inode->gid = 0;
#ifdef CONFIG_ACPI
        if (strncmp(abs, "/sys/firmware/acpi/tables/", 26) == 0) {
            const char *name = abs + 26;
            if (sysfs_leaf_has_slash(name) ||
                acpi_sysfs_table_size(name, &size) < 0) {
                size = 0;
            }
        }
#endif
        out_inode->size = size;
        vfs_inode_set_ptr(out_inode, 0);
    }
    return 0;
}

static int sysfs_append_char(char *buf, uint32_t max, uint32_t *off, char c) {
    if (!buf || !off || *off + 1u >= max) return -1;
    buf[(*off)++] = c;
    buf[*off] = 0;
    return 0;
}

static int sysfs_append_lit(char *buf, uint32_t max, uint32_t *off, const char *s) {
    if (!s) return -1;
    while (*s) {
        if (sysfs_append_char(buf, max, off, *s++) < 0) return -1;
    }
    return 0;
}

static int sysfs_append_u32(char *buf, uint32_t max, uint32_t *off, uint32_t v) {
    char tmp[11];
    int n = 0;
    if (v == 0) return sysfs_append_char(buf, max, off, '0');
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (n > 0) {
        if (sysfs_append_char(buf, max, off, tmp[--n]) < 0) return -1;
    }
    return 0;
}

static int sysfs_append_u64(char *buf, uint32_t max, uint32_t *off, uint64_t v) {
    char tmp[21];
    int n = 0;
    if (v == 0) return sysfs_append_char(buf, max, off, '0');
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10ull));
        v /= 10ull;
    }
    while (n > 0) {
        if (sysfs_append_char(buf, max, off, tmp[--n]) < 0) return -1;
    }
    return 0;
}

static int sysfs_append_line_u64(char *buf, uint32_t max, uint64_t value) {
    uint32_t off = 0;

    if (!buf || max == 0)
        return -1;
    buf[0] = 0;
    if (sysfs_append_u64(buf, max, &off, value) < 0 ||
        sysfs_append_char(buf, max, &off, '\n') < 0)
        return -1;
    return 0;
}

static int sysfs_append_uevent_u64(char *buf, uint32_t max, uint32_t *off,
                                   const char *key, uint64_t value) {
    return sysfs_append_lit(buf, max, off, key) < 0 ||
           sysfs_append_char(buf, max, off, '=') < 0 ||
           sysfs_append_u64(buf, max, off, value) < 0 ||
           sysfs_append_char(buf, max, off, '\n') < 0 ? -1 : 0;
}

static int sysfs_append_uevent_text(char *buf, uint32_t max, uint32_t *off,
                                    const char *key, const char *value) {
    return sysfs_append_lit(buf, max, off, key) < 0 ||
           sysfs_append_char(buf, max, off, '=') < 0 ||
           sysfs_append_lit(buf, max, off, value) < 0 ||
           sysfs_append_char(buf, max, off, '\n') < 0 ? -1 : 0;
}

static const char *sysfs_battery_status(
    const struct edge_acpi_battery_info *information) {
    if (!information || !information->present)
        return "Unknown";
    if ((information->state & EDGE_ACPI_BATTERY_STATE_CHARGING) != 0)
        return "Charging";
    if ((information->state & EDGE_ACPI_BATTERY_STATE_DISCHARGING) != 0)
        return "Discharging";
    if (information->capacity_percent >= 100)
        return "Full";
    return "Not charging";
}

static int sysfs_append_two_dec(char *buf, uint32_t max, uint32_t *off, uint32_t v) {
    if (v > 99u) return -1;
    if (sysfs_append_char(buf, max, off, (char)('0' + (v / 10u))) < 0) return -1;
    return sysfs_append_char(buf, max, off, (char)('0' + (v % 10u)));
}

static int sysfs_format_mode(char *buf, uint32_t max, const char *prefix,
                             const char *sep, const char *suffix) {
    uint32_t off = 0;
    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (prefix && sysfs_append_lit(buf, max, &off, prefix) < 0) return -1;
    if (sysfs_append_u32(buf, max, &off, fb.width) < 0) return -1;
    if (sep && sysfs_append_lit(buf, max, &off, sep) < 0) return -1;
    if (sysfs_append_u32(buf, max, &off, fb.height) < 0) return -1;
    if (suffix && sysfs_append_lit(buf, max, &off, suffix) < 0) return -1;
    return 0;
}

static int sysfs_format_rtc_date(char *buf, uint32_t max) {
    struct edge_rtc_time tm;
    uint32_t off = 0;
    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (rtc_read_time(&tm) < 0) return -1;
    if (sysfs_append_u32(buf, max, &off, (uint32_t)(tm.tm_year + 1900)) < 0) return -1;
    if (sysfs_append_char(buf, max, &off, '-') < 0) return -1;
    if (sysfs_append_two_dec(buf, max, &off, (uint32_t)(tm.tm_mon + 1)) < 0) return -1;
    if (sysfs_append_char(buf, max, &off, '-') < 0) return -1;
    if (sysfs_append_two_dec(buf, max, &off, (uint32_t)tm.tm_mday) < 0) return -1;
    return sysfs_append_char(buf, max, &off, '\n');
}

static int sysfs_format_rtc_time(char *buf, uint32_t max) {
    struct edge_rtc_time tm;
    uint32_t off = 0;
    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (rtc_read_time(&tm) < 0) return -1;
    if (sysfs_append_two_dec(buf, max, &off, (uint32_t)tm.tm_hour) < 0) return -1;
    if (sysfs_append_char(buf, max, &off, ':') < 0) return -1;
    if (sysfs_append_two_dec(buf, max, &off, (uint32_t)tm.tm_min) < 0) return -1;
    if (sysfs_append_char(buf, max, &off, ':') < 0) return -1;
    if (sysfs_append_two_dec(buf, max, &off, (uint32_t)tm.tm_sec) < 0) return -1;
    return sysfs_append_char(buf, max, &off, '\n');
}

static int sysfs_format_rtc_since_epoch(char *buf, uint32_t max) {
    uint64_t seconds = 0;
    uint32_t off = 0;
    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (rtc_unix_seconds(&seconds) < 0) return -1;
    if (sysfs_append_u64(buf, max, &off, seconds) < 0) return -1;
    return sysfs_append_char(buf, max, &off, '\n');
}

static int vfs_sys_class_read_file(const char *path, char *out, uint32_t max) {
    const char *s = 0;
    char buf[1024];
    if (!path || !out) return -1;
#ifdef CONFIG_PCI
    if (pci_sysfs_path_kind(path) == PCI_SYSFS_PATH_FILE) {
        return pci_sysfs_read_file(path, out, max);
    }
#endif
    if (block_sysfs_path_kind(path) == BLOCK_SYSFS_PATH_FILE) {
        return block_sysfs_read_file(path, out, max);
    }
#ifdef CONFIG_ACPI
    if (acpi_available() && strncmp(path, "/sys/firmware/acpi/tables/", 26) == 0) {
        const char *name = path + 26;
        if (!sysfs_leaf_has_slash(name))
            return acpi_sysfs_table_read(name, 0, out, max);
    }
    if (acpi_available() && strcmp(path, "/sys/firmware/acpi/pm_profile") == 0) {
        uint32_t off = 0;
        buf[0] = 0;
        if (sysfs_append_u32(buf, sizeof(buf), &off, acpi_pm_profile()) < 0 ||
            sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0) {
            return -1;
        }
        s = buf;
    }
#endif
    if (!s && strcmp(path, "/sys/devices/system/clocksource/clocksource0/current_clocksource") == 0) s = "pit\n";
    else if (strcmp(path, "/sys/devices/system/clocksource/clocksource0/available_clocksource") == 0) {
#ifdef CONFIG_HPET
        s = hpet_is_available() ? "pit hpet\n" : "pit\n";
#else
        s = "pit\n";
#endif
    }
    else if (strcmp(path, "/sys/class/drm/card0/dev") == 0) s = "226:0\n";
    else if (strcmp(path, "/sys/class/drm/card0/status") == 0) s = "connected\n";
    else if (strcmp(path, "/sys/class/drm/card0/enabled") == 0) s = "enabled\n";
    else if (strcmp(path, "/sys/class/drm/card0/modes") == 0) {
        /*
         * Keep Linux-visible graphics sysfs tied to the active framebuffer.
         * Hardcoding 1024x768 while virtio-gpu exposes a 640x480 scanout makes
         * desktop helpers reason about a mode that the fbdev ioctl path rejects
         * and the host cannot display.  Red flag: this is generic fbdev/DRM
         * reporting, not an Xorg/XFCE/rootfs policy workaround.
         */
        if (sysfs_format_mode(buf, sizeof(buf), "", "x", "\n") < 0) return -1;
        s = buf;
    }
    else if (strcmp(path, "/sys/class/drm/card0/uevent") == 0) s = "MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\n";
    else if (strcmp(path, "/sys/class/graphics/fb0/dev") == 0) s = "29:0\n";
    else if (strcmp(path, "/sys/class/graphics/fb0/name") == 0) s = "EdgeOS framebuffer\n";
    else if (strcmp(path, "/sys/class/graphics/fb0/virtual_size") == 0) {
        if (sysfs_format_mode(buf, sizeof(buf), "", ",", "\n") < 0) return -1;
        s = buf;
    }
    else if (strcmp(path, "/sys/class/graphics/fb0/bits_per_pixel") == 0) {
        uint32_t off = 0;
        buf[0] = 0;
        if (sysfs_append_u32(buf, sizeof(buf), &off, fb.bpp) < 0 ||
            sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0) {
            return -1;
        }
        s = buf;
    }
    else if (strcmp(path, "/sys/class/graphics/fb0/modes") == 0) {
        if (sysfs_format_mode(buf, sizeof(buf), "U:", "x", "p-0\n") < 0) return -1;
        s = buf;
    }
    else if (strcmp(path, "/sys/class/rtc/rtc0/dev") == 0) s = "254:0\n";
    else if (strcmp(path, "/sys/class/rtc/rtc0/name") == 0) s = "rtc_cmos\n";
    else if (strcmp(path, "/sys/class/rtc/rtc0/date") == 0) {
        if (sysfs_format_rtc_date(buf, sizeof(buf)) < 0) return -1;
        s = buf;
    }
    else if (strcmp(path, "/sys/class/rtc/rtc0/time") == 0) {
        if (sysfs_format_rtc_time(buf, sizeof(buf)) < 0) return -1;
        s = buf;
    }
    else if (strcmp(path, "/sys/class/rtc/rtc0/since_epoch") == 0) {
        if (sysfs_format_rtc_since_epoch(buf, sizeof(buf)) < 0) return -1;
        s = buf;
    }
    else if (strcmp(path, "/sys/class/rtc/rtc0/hctosys") == 0) s = "1\n";
    else if (strcmp(path, "/sys/class/rtc/rtc0/max_user_freq") == 0) s = "1\n";
    else if (strcmp(path, "/sys/class/rtc/rtc0/uevent") == 0) s = "MAJOR=254\nMINOR=0\nDEVNAME=rtc0\n";
    else if (strncmp(path, "/sys/class/power_supply/", 24) == 0) {
        const char *rest = path + 24;
        char node[VFS_NAME_MAX];
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_power_supply_node_name(node) && rest[i] == '/') {
            const char *file = rest + i + 1;
            uint32_t off = 0;
            int is_ac = strcmp(node, "AC") == 0;
            int is_bat = strcmp(node, "BAT0") == 0;
            struct edge_acpi_battery_info information;
            uint32_t attributes = 0;
            int online = 0;

            if (!sys_power_supply_file_name(node, file))
                return -1;
            memset(&information, 0, sizeof(information));
            if (is_ac && acpi_get_ac_adapter_online(&online) != 0)
                return -1;
            if (is_bat) {
                if (acpi_get_battery_info(0, &information) != 0)
                    return -1;
                attributes = acpi_battery_attribute_mask(&information);
            }
            if (strcmp(file, "type") == 0) {
                s = is_ac ? "Mains\n" : "Battery\n";
            } else if (strcmp(file, "scope") == 0) {
                s = "System\n";
            } else if (strcmp(file, "online") == 0 && is_ac) {
                s = online ? "1\n" : "0\n";
            } else if (strcmp(file, "status") == 0 && is_bat) {
                if (sysfs_append_lit(buf, sizeof(buf), &off,
                                     sysfs_battery_status(&information)) < 0 ||
                    sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0)
                    return -1;
                s = buf;
            } else if (strcmp(file, "present") == 0 && is_bat) {
                s = information.present ? "1\n" : "0\n";
            } else if (strcmp(file, "capacity") == 0 && is_bat &&
                       (attributes & EDGE_ACPI_BATTERY_ATTR_CAPACITY) != 0) {
                if (sysfs_append_line_u64(
                        buf, sizeof(buf),
                        (uint64_t)information.capacity_percent) < 0)
                    return -1;
                s = buf;
            } else if (strcmp(file, "technology") == 0 && is_bat) {
                if (sysfs_append_lit(buf, sizeof(buf), &off,
                                     information.technology) < 0 ||
                    sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0)
                    return -1;
                s = buf;
            } else if (strcmp(file, "serial_number") == 0 && is_bat) {
                if (sysfs_append_lit(buf, sizeof(buf), &off,
                                     information.serial) < 0 ||
                    sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0)
                    return -1;
                s = buf;
            } else if (strcmp(file, "cycle_count") == 0 && is_bat) {
                if (sysfs_append_line_u64(
                        buf, sizeof(buf), information.cycle_count) < 0)
                    return -1;
                s = buf;
            } else if (strcmp(file, "voltage_now") == 0 && is_bat) {
                if (sysfs_append_line_u64(
                        buf, sizeof(buf),
                        (uint64_t)information.voltage * 1000ull) < 0)
                    return -1;
                s = buf;
            } else if (strcmp(file, "voltage_min_design") == 0 && is_bat) {
                if (sysfs_append_line_u64(
                        buf, sizeof(buf),
                        (uint64_t)information.design_voltage * 1000ull) < 0)
                    return -1;
                s = buf;
            } else if ((strcmp(file, "energy_now") == 0 ||
                        strcmp(file, "charge_now") == 0) && is_bat) {
                if (sysfs_append_line_u64(
                        buf, sizeof(buf),
                        (uint64_t)information.remaining_capacity * 1000ull) < 0)
                    return -1;
                s = buf;
            } else if ((strcmp(file, "energy_full") == 0 ||
                        strcmp(file, "charge_full") == 0) && is_bat) {
                if (sysfs_append_line_u64(
                        buf, sizeof(buf),
                        (uint64_t)information.full_capacity * 1000ull) < 0)
                    return -1;
                s = buf;
            } else if ((strcmp(file, "energy_full_design") == 0 ||
                        strcmp(file, "charge_full_design") == 0) && is_bat) {
                if (sysfs_append_line_u64(
                        buf, sizeof(buf),
                        (uint64_t)information.design_capacity * 1000ull) < 0)
                    return -1;
                s = buf;
            } else if ((strcmp(file, "power_now") == 0 ||
                        strcmp(file, "current_now") == 0) && is_bat) {
                if (sysfs_append_line_u64(
                        buf, sizeof(buf),
                        (uint64_t)information.rate * 1000ull) < 0)
                    return -1;
                s = buf;
            } else if (strcmp(file, "time_to_empty_now") == 0 && is_bat) {
                if (sysfs_append_line_u64(
                        buf, sizeof(buf),
                        (uint64_t)information.remaining_minutes * 60ull) < 0)
                    return -1;
                s = buf;
            } else if (strcmp(file, "model_name") == 0) {
                if (is_ac)
                    s = "ACPI AC Adapter\n";
                else if (!information.model[0])
                    s = "ACPI Battery\n";
                else {
                    if (sysfs_append_lit(buf, sizeof(buf), &off,
                                         information.model) < 0 ||
                        sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0)
                        return -1;
                    s = buf;
                }
            } else if (strcmp(file, "manufacturer") == 0) {
                if (is_ac || !information.manufacturer[0])
                    s = "ACPI\n";
                else {
                    if (sysfs_append_lit(buf, sizeof(buf), &off,
                                         information.manufacturer) < 0 ||
                        sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0)
                        return -1;
                    s = buf;
                }
            } else if (strcmp(file, "uevent") == 0) {
                if (sysfs_append_lit(buf, sizeof(buf), &off, "POWER_SUPPLY_NAME=") < 0 ||
                    sysfs_append_lit(buf, sizeof(buf), &off, node) < 0 ||
                    sysfs_append_lit(buf, sizeof(buf), &off, "\nPOWER_SUPPLY_TYPE=") < 0 ||
                    sysfs_append_lit(buf, sizeof(buf), &off, is_ac ? "Mains" : "Battery") < 0 ||
                    sysfs_append_lit(buf, sizeof(buf), &off, "\nPOWER_SUPPLY_SCOPE=System\n") < 0) {
                    return -1;
                }
                if (is_ac) {
                    if (sysfs_append_lit(buf, sizeof(buf), &off,
                                         "POWER_SUPPLY_ONLINE=") < 0 ||
                        sysfs_append_u32(buf, sizeof(buf), &off,
                                         online ? 1u : 0u) < 0 ||
                        sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0)
                        return -1;
                } else if (is_bat) {
                    if (sysfs_append_lit(buf, sizeof(buf), &off,
                                         "POWER_SUPPLY_STATUS=") < 0 ||
                        sysfs_append_lit(
                            buf, sizeof(buf), &off,
                            sysfs_battery_status(&information)) < 0 ||
                        sysfs_append_lit(buf, sizeof(buf), &off,
                                         "\nPOWER_SUPPLY_PRESENT=") < 0 ||
                        sysfs_append_u32(buf, sizeof(buf), &off,
                                         information.present ? 1u : 0u) < 0 ||
                        sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0) {
                        return -1;
                    }
                    if ((attributes & EDGE_ACPI_BATTERY_ATTR_CAPACITY) &&
                        sysfs_append_uevent_u64(
                            buf, sizeof(buf), &off,
                            "POWER_SUPPLY_CAPACITY",
                            (uint64_t)information.capacity_percent) < 0)
                        return -1;
                    if ((attributes & EDGE_ACPI_BATTERY_ATTR_VOLTAGE_NOW) &&
                        sysfs_append_uevent_u64(
                            buf, sizeof(buf), &off,
                            "POWER_SUPPLY_VOLTAGE_NOW",
                            (uint64_t)information.voltage * 1000ull) < 0)
                        return -1;
                    if ((attributes &
                         EDGE_ACPI_BATTERY_ATTR_VOLTAGE_DESIGN) &&
                        sysfs_append_uevent_u64(
                            buf, sizeof(buf), &off,
                            "POWER_SUPPLY_VOLTAGE_MIN_DESIGN",
                            (uint64_t)information.design_voltage * 1000ull) < 0)
                        return -1;
                    if (attributes & EDGE_ACPI_BATTERY_ATTR_STORAGE) {
                        const char *prefix = information.units == 0 ?
                            "POWER_SUPPLY_ENERGY_" :
                            "POWER_SUPPLY_CHARGE_";

                        if (sysfs_append_lit(
                                buf, sizeof(buf), &off, prefix) < 0 ||
                            sysfs_append_lit(
                                buf, sizeof(buf), &off, "NOW=") < 0 ||
                            sysfs_append_u64(
                                buf, sizeof(buf), &off,
                                (uint64_t)information.remaining_capacity *
                                    1000ull) < 0 ||
                            sysfs_append_char(
                                buf, sizeof(buf), &off, '\n') < 0 ||
                            sysfs_append_lit(
                                buf, sizeof(buf), &off, prefix) < 0 ||
                            sysfs_append_lit(
                                buf, sizeof(buf), &off, "FULL=") < 0 ||
                            sysfs_append_u64(
                                buf, sizeof(buf), &off,
                                (uint64_t)information.full_capacity *
                                    1000ull) < 0 ||
                            sysfs_append_char(
                                buf, sizeof(buf), &off, '\n') < 0 ||
                            sysfs_append_lit(
                                buf, sizeof(buf), &off, prefix) < 0 ||
                            sysfs_append_lit(
                                buf, sizeof(buf), &off,
                                "FULL_DESIGN=") < 0 ||
                            sysfs_append_u64(
                                buf, sizeof(buf), &off,
                                (uint64_t)information.design_capacity *
                                    1000ull) < 0 ||
                            sysfs_append_char(
                                buf, sizeof(buf), &off, '\n') < 0)
                            return -1;
                    }
                    if ((attributes & EDGE_ACPI_BATTERY_ATTR_RATE) &&
                        sysfs_append_uevent_u64(
                            buf, sizeof(buf), &off,
                            information.units == 0 ?
                                "POWER_SUPPLY_POWER_NOW" :
                                "POWER_SUPPLY_CURRENT_NOW",
                            (uint64_t)information.rate * 1000ull) < 0)
                        return -1;
                    if ((attributes & EDGE_ACPI_BATTERY_ATTR_CYCLE_COUNT) &&
                        sysfs_append_uevent_u64(
                            buf, sizeof(buf), &off,
                            "POWER_SUPPLY_CYCLE_COUNT",
                            information.cycle_count) < 0)
                        return -1;
                    if ((attributes & EDGE_ACPI_BATTERY_ATTR_TECHNOLOGY) &&
                        sysfs_append_uevent_text(
                            buf, sizeof(buf), &off,
                            "POWER_SUPPLY_TECHNOLOGY",
                            information.technology) < 0)
                        return -1;
                    if ((attributes & EDGE_ACPI_BATTERY_ATTR_SERIAL) &&
                        sysfs_append_uevent_text(
                            buf, sizeof(buf), &off,
                            "POWER_SUPPLY_SERIAL_NUMBER",
                            information.serial) < 0)
                        return -1;
                }
                s = buf;
            } else {
                (void)is_bat;
            }
        }
    }
    else if (strncmp(path, "/sys/class/sound/", 17) == 0) {
        const char *rest = path + 17;
        char node[VFS_NAME_MAX];
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_sound_node_name(node) && rest[i] == '/') {
            const char *file = rest + i + 1;
            uint32_t major = 0;
            uint32_t minor = 0;
            uint32_t off = 0;
            if (strcmp(node, "card0") == 0) {
                if (strcmp(file, "id") == 0) {
                    if (sysfs_append_lit(buf, sizeof(buf), &off, alsa_card_id()) < 0 ||
                        sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0) {
                        return -1;
                    }
                    s = buf;
                } else if (strcmp(file, "number") == 0) {
                    s = "0\n";
                } else if (strcmp(file, "uevent") == 0) {
                    s = "SOUND_INITIALIZED=1\n";
                }
            } else if (sys_sound_node_dev(node, &major, &minor)) {
                if (strcmp(file, "dev") == 0) {
                    if (sysfs_append_u32(buf, sizeof(buf), &off, major) < 0 ||
                        sysfs_append_char(buf, sizeof(buf), &off, ':') < 0 ||
                        sysfs_append_u32(buf, sizeof(buf), &off, minor) < 0 ||
                        sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0) {
                        return -1;
                    }
                    s = buf;
                } else if (strcmp(file, "name") == 0) {
                    if (sysfs_append_lit(buf, sizeof(buf), &off, alsa_card_longname()) < 0 ||
                        sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0) {
                        return -1;
                    }
                    s = buf;
                } else if (strcmp(file, "uevent") == 0) {
                    if (sysfs_append_lit(buf, sizeof(buf), &off, "MAJOR=") < 0 ||
                        sysfs_append_u32(buf, sizeof(buf), &off, major) < 0 ||
                        sysfs_append_lit(buf, sizeof(buf), &off, "\nMINOR=") < 0 ||
                        sysfs_append_u32(buf, sizeof(buf), &off, minor) < 0 ||
                        sysfs_append_lit(buf, sizeof(buf), &off, "\nDEVNAME=snd/") < 0 ||
                        sysfs_append_lit(buf, sizeof(buf), &off, node) < 0 ||
                        sysfs_append_lit(buf, sizeof(buf), &off, "\nSOUND_INITIALIZED=1\n") < 0) {
                        return -1;
                    }
                    s = buf;
                }
            }
        }
    }
    else if (strncmp(path, "/sys/class/tty/", 15) == 0) {
        const char *rest = path + 15;
        char node[VFS_NAME_MAX];
        uint32_t major = 0;
        uint32_t minor = 0;
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_tty_node_dev(node, &major, &minor) && rest[i] == '/') {
            const char *file = rest + i + 1;
            uint32_t off = 0;
            buf[0] = 0;
            if (strcmp(file, "dev") == 0) {
                if (sysfs_append_u32(buf, sizeof(buf), &off, major) < 0 ||
                    sysfs_append_char(buf, sizeof(buf), &off, ':') < 0 ||
                    sysfs_append_u32(buf, sizeof(buf), &off, minor) < 0 ||
                    sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0) {
                    return -1;
                }
                s = buf;
            } else if (strcmp(file, "uevent") == 0) {
                if (sysfs_append_lit(buf, sizeof(buf), &off, "MAJOR=") < 0 ||
                    sysfs_append_u32(buf, sizeof(buf), &off, major) < 0 ||
                    sysfs_append_lit(buf, sizeof(buf), &off, "\nMINOR=") < 0 ||
                    sysfs_append_u32(buf, sizeof(buf), &off, minor) < 0 ||
                    sysfs_append_lit(buf, sizeof(buf), &off, "\nDEVNAME=") < 0 ||
                    sysfs_append_lit(buf, sizeof(buf), &off, node) < 0 ||
                    sysfs_append_char(buf, sizeof(buf), &off, '\n') < 0) {
                    return -1;
                }
                s = buf;
            } else if ((strcmp(node, "tty0") == 0 ||
                        strcmp(node, "console") == 0) &&
                       strcmp(file, "active") == 0) {
                int length = strcmp(node, "console") == 0 ?
                    kernel_console_configured_names(buf, sizeof(buf)) :
                    kernel_console_active_names(buf, sizeof(buf));
                if (length < 0) return -1;
                s = buf;
            }
        }
    }
    else if (strncmp(path, "/sys/class/input/", 17) == 0) {
        const char *rest = path + 17;
        char node[VFS_NAME_MAX];
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_input_node_name(node) && rest[i] == '/') {
            const char *file = rest + i + 1;
            if (strcmp(file, "name") == 0) {
                int ev = 0;
                const char *registered_name;

                (void)parse_decimal_str(node + 5, &ev);
                registered_name = ev >= 0 &&
                    ev < (int)EDGE_INPUT_DEVICE_MAX ?
                    input_name((uint32_t)ev) : 0;
                if (registered_name) {
                    uint32_t name_length =
                        (uint32_t)strlen(registered_name);
                    if (name_length >= sizeof(buf) - 1u)
                        name_length = sizeof(buf) - 2u;
                    memcpy(buf, registered_name, name_length);
                    buf[name_length++] = '\n';
                    buf[name_length] = 0;
                    s = buf;
                }
            }
            else if (strcmp(file, "dev") == 0) {
                if (strcmp(node, "mice") == 0) s = "13:63\n";
                else if (strcmp(node, "mouse0") == 0) s = "13:32\n";
                else {
                    int ev = 0;
                    (void)parse_decimal_str(node + 5, &ev);
                    buf[0] = 0;
                    strcpy(buf, "13:");
                    {
                        int n = 64 + ev;
                        int j = 0;
                        char tmp[16];
                        if (n == 0) tmp[j++] = '0';
                        while (n > 0 && j < (int)sizeof(tmp)) {
                            tmp[j++] = (char)('0' + (n % 10));
                            n /= 10;
                        }
                        for (int k = j - 1; k >= 0; --k) {
                            int l = (int)strlen(buf);
                            buf[l] = tmp[k];
                            buf[l + 1] = 0;
                        }
                    }
                    strcat(buf, "\n");
                    s = buf;
                }
            } else if (strcmp(file, "uevent") == 0) {
                if (strcmp(node, "mice") == 0) s = "MAJOR=13\nMINOR=63\nDEVNAME=input/mice\n";
                else if (strcmp(node, "mouse0") == 0) s = "MAJOR=13\nMINOR=32\nDEVNAME=input/mouse0\n";
                else {
                    int ev = 0;
                    uint32_t off = 0;

                    (void)parse_decimal_str(node + 5, &ev);
                    buf[0] = 0;
                    if (ev < 0 || ev >= (int)EDGE_INPUT_DEVICE_MAX ||
                        sysfs_append_lit(
                            buf, sizeof(buf), &off,
                            "MAJOR=13\nMINOR=") < 0 ||
                        sysfs_append_u32(
                            buf, sizeof(buf), &off,
                            64u + (uint32_t)ev) < 0 ||
                        sysfs_append_lit(
                            buf, sizeof(buf), &off,
                            "\nDEVNAME=input/event") < 0 ||
                        sysfs_append_u32(
                            buf, sizeof(buf), &off,
                            (uint32_t)ev) < 0 ||
                        sysfs_append_char(
                            buf, sizeof(buf), &off, '\n') < 0)
                        return -1;
                    s = buf;
                }
            }
        }
    }
    if (!s) return -1;
    {
        uint32_t n = (uint32_t)strlen(s);
        if (n > max) n = max;
        memcpy(out, s, n);
        return (int)n;
    }
}

static int vfs_sys_class_read_file_at(const char *path, uint32_t offset,
                                      char *out, uint32_t max) {
#ifdef CONFIG_ACPI
    if (path && acpi_available() &&
        strncmp(path, "/sys/firmware/acpi/tables/", 26) == 0) {
        const char *name = path + 26;
        if (!sysfs_leaf_has_slash(name))
            return acpi_sysfs_table_read(name, offset, out, max);
    }
#endif
    if (offset == 0) return vfs_sys_class_read_file(path, out, max);
    {
        /* Linux text sysfs attributes emit at most one page per read. */
        char page[4096];
        int length = vfs_sys_class_read_file(path, page, sizeof(page));
        uint32_t count;
        if (length < 0) return -1;
        if (offset >= (uint32_t)length) return 0;
        count = (uint32_t)length - offset;
        if (count > max) count = max;
        memcpy(out, page + offset, count);
        return (int)count;
    }
}

int vfs_readlink(const char *path, char *out, uint32_t max) {
    const char *target = 0;
    uint32_t n;
    if (!path || !out || max == 0) return -1;
    {
        vfs_inode_t inode;
        vfs_superblock_t *sb = 0;
        if (vfs_resolve_nofollow(path, &inode, &sb) == 0 && sb && sb->ops &&
            sb->ops->readlink &&
            (inode.mode & 0xF000u) == VFS_INODE_LNK)
            return sb->ops->readlink(sb, &inode, out, max);
    }
#ifdef CONFIG_PCI
    if (pci_sysfs_path_kind(path) == PCI_SYSFS_PATH_LINK) {
        return pci_sysfs_readlink(path, out, max);
    }
#endif
    if (block_sysfs_path_kind(path) == BLOCK_SYSFS_PATH_LINK) {
        return block_sysfs_readlink(path, out, max);
    }
    /*
     * Xorg's fbdev probe reads this sysfs link and rejects the framebuffer if
     * it points at PCI.  EdgeOS currently exposes a synthetic platform
     * framebuffer, so model the non-PCI sysfs topology Linux exposes for simple
     * platform framebuffers.
     */
    if (strcmp(path, "/sys/class/graphics/fb0/device") == 0) {
        target = "../../../devices/virtual/drm/device0";
    } else if (strcmp(path, "/sys/class/graphics/fb0/device/subsystem") == 0) {
        target = "../../../../bus/platform";
    } else if (strcmp(path, "/sys/class/graphics/fb0/subsystem") == 0) {
        target = "../../graphics";
    } else if (strncmp(path, "/sys/class/sound/", 17) == 0) {
        const char *rest = path + 17;
        char node[VFS_NAME_MAX];
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_sound_node_name(node) && strcmp(rest + i, "/subsystem") == 0) {
            target = "../../sound";
        }
    } else if (strncmp(path, "/sys/class/tty/", 15) == 0) {
        const char *rest = path + 15;
        char node[VFS_NAME_MAX];
        int i = 0;
        while (rest[i] && rest[i] != '/' && i < VFS_NAME_MAX - 1) {
            node[i] = rest[i];
            ++i;
        }
        node[i] = 0;
        if (sys_tty_node_name(node) && strcmp(rest + i, "/subsystem") == 0) {
            target = "../../tty";
        }
    }
    if (!target) return -1;
    n = (uint32_t)strlen(target);
    if (n > max) n = max;
    memcpy(out, target, n);
    return (int)n;
}

static int dev_fd_alias_number(const char *name, int *fd_out) {
    const char *n = name;
    int fd = 0;
    if (!name || !fd_out) return -1;
    if (strcmp(name, "stdin") == 0) {
        *fd_out = 0;
        return 0;
    }
    if (strcmp(name, "stdout") == 0) {
        *fd_out = 1;
        return 0;
    }
    if (strcmp(name, "stderr") == 0) {
        *fd_out = 2;
        return 0;
    }
    if (strncmp(name, "fd/", 3) != 0) return -1;
    n = name + 3;
    if (!n[0]) return -1;
    for (const char *p = n; *p; ++p) {
        if (*p < '0' || *p > '9') return -1;
        fd = fd * 10 + (*p - '0');
        if (fd > 1000000) return -1;
    }
    *fd_out = fd;
    return 0;
}

static uint16_t vfs_current_umask(void) {
    return kernel_current_umask();
}

static int vfs_try_resolve_devpath(const char *abs, vfs_inode_t *out_inode, vfs_superblock_t **out_sb, vfs_inode_t *out_parent) {
    if (!abs) return -1;
    if (strcmp(abs, "/dev") == 0) return -1;
    if (strncmp(abs, "/dev/", 5) != 0) return -1;
    const char *name = abs + 5;
    if (strcmp(name, "fd") == 0) {
        if (out_parent) {
            vfs_inode_t devdir;
            if (vfs_resolve("/dev", &devdir, 0, 0, 0) == 0) *out_parent = devdir;
            else memset(out_parent, 0, sizeof(*out_parent));
        }
        if (out_sb) *out_sb = 0;
        if (out_inode) {
            memset(out_inode, 0, sizeof(*out_inode));
            out_inode->ino = 0xD0FFD000u;
            out_inode->mode = VFS_INODE_DIR | 0555;
            out_inode->uid = 0;
            out_inode->gid = 0;
            out_inode->size = 0;
            vfs_inode_set_ptr(out_inode, 0);
        }
        return 0;
    }
    {
        int fd_alias = -1;
        if (dev_fd_alias_number(name, &fd_alias) == 0) {
            if (out_parent) {
                memset(out_parent, 0, sizeof(*out_parent));
                out_parent->ino = (strncmp(name, "fd/", 3) == 0) ? 0xD0FFD000u : 0;
                out_parent->mode = VFS_INODE_DIR | 0555;
                out_parent->uid = 0;
                out_parent->gid = 0;
                out_parent->size = 0;
                vfs_inode_set_ptr(out_parent, 0);
            }
            if (out_sb) *out_sb = 0;
            if (out_inode) {
                memset(out_inode, 0, sizeof(*out_inode));
                out_inode->ino = 0xD0FFD100u + (uint32_t)fd_alias;
                out_inode->mode = VFS_INODE_CHR | 0666;
                out_inode->uid = 0;
                out_inode->gid = 0;
                out_inode->size = 0;
                vfs_inode_set_ptr(out_inode, 0);
            }
            return 0;
        }
    }
    if (strcmp(name, "pts") == 0) {
        if (out_parent) {
            vfs_inode_t devdir;
            if (vfs_resolve("/dev", &devdir, 0, 0, 0) == 0) *out_parent = devdir;
            else memset(out_parent, 0, sizeof(*out_parent));
        }
        if (out_sb) *out_sb = 0;
        if (out_inode) {
            memset(out_inode, 0, sizeof(*out_inode));
            out_inode->ino = 0xD0FFF000u;
            out_inode->mode = VFS_INODE_DIR | 0755;
            out_inode->uid = 0;
            out_inode->gid = 0;
            out_inode->size = 0;
            vfs_inode_set_ptr(out_inode, 0);
        }
        return 0;
    }
    if (strcmp(name, "input") == 0) {
        if (out_parent) {
            vfs_inode_t devdir;
            if (vfs_resolve("/dev", &devdir, 0, 0, 0) == 0) *out_parent = devdir;
            else memset(out_parent, 0, sizeof(*out_parent));
        }
        if (out_sb) *out_sb = 0;
        if (out_inode) {
            memset(out_inode, 0, sizeof(*out_inode));
            out_inode->ino = 0xD0FFE000u;
            out_inode->mode = VFS_INODE_DIR | 0755;
            out_inode->uid = 0;
            out_inode->gid = 0;
            out_inode->size = 0;
            vfs_inode_set_ptr(out_inode, 0);
        }
        return 0;
    }
    if (strcmp(name, "dri") == 0) {
        if (out_parent) {
            vfs_inode_t devdir;
            if (vfs_resolve("/dev", &devdir, 0, 0, 0) == 0) *out_parent = devdir;
            else memset(out_parent, 0, sizeof(*out_parent));
        }
        if (out_sb) *out_sb = 0;
        if (out_inode) {
            memset(out_inode, 0, sizeof(*out_inode));
            out_inode->ino = 0xD0FFD800u;
            out_inode->mode = VFS_INODE_DIR | 0755;
            out_inode->uid = 0;
            out_inode->gid = 0;
            out_inode->size = 0;
            vfs_inode_set_ptr(out_inode, 0);
        }
        return 0;
    }
    if (strcmp(name, "snd") == 0) {
        if (!alsa_available()) return -1;
        if (out_parent) {
            vfs_inode_t devdir;
            if (vfs_resolve("/dev", &devdir, 0, 0, 0) == 0) *out_parent = devdir;
            else memset(out_parent, 0, sizeof(*out_parent));
        }
        if (out_sb) *out_sb = 0;
        if (out_inode) {
            memset(out_inode, 0, sizeof(*out_inode));
            out_inode->ino = alsa_inode_from_kind(EDGE_ALSA_NODE_SND_DIR);
            out_inode->mode = VFS_INODE_DIR | 0755;
            out_inode->uid = 0;
            out_inode->gid = 0;
            out_inode->size = 0;
            vfs_inode_set_ptr(out_inode, 0);
        }
        return 0;
    }
    if (strcmp(name, "kmsg") == 0) {
        if (out_parent) {
            vfs_inode_t devdir;
            if (vfs_resolve("/dev", &devdir, 0, 0, 0) == 0) *out_parent = devdir;
            else memset(out_parent, 0, sizeof(*out_parent));
        }
        if (out_sb) *out_sb = 0;
        if (out_inode) {
            memset(out_inode, 0, sizeof(*out_inode));
            out_inode->ino = 0xD0FF0B00u;
            out_inode->mode = VFS_INODE_CHR | 0400;
            out_inode->uid = 0;
            out_inode->gid = 0;
            out_inode->size = 0;
            vfs_inode_set_ptr(out_inode, 0);
        }
        return 0;
    }
    if (dev_input_is_mouse_stream(name) || dev_input_is_event_stream(name)) {
        if (out_parent) {
            memset(out_parent, 0, sizeof(*out_parent));
            out_parent->ino = 0xD0FFE000u;
            out_parent->mode = VFS_INODE_DIR | 0755;
            out_parent->uid = 0;
            out_parent->gid = 0;
            out_parent->size = 0;
            vfs_inode_set_ptr(out_parent, 0);
        }
        if (out_sb) *out_sb = 0;
        if (out_inode) {
            memset(out_inode, 0, sizeof(*out_inode));
            if (dev_input_is_event_stream(name)) {
                int evn = 0;
                (void)parse_decimal_str(name + 11, &evn);
                out_inode->ino = 0xD0FFE101u + (uint32_t)evn;
            } else {
                out_inode->ino = 0xD0FFE100u;
            }
            out_inode->mode = VFS_INODE_CHR | 0666;
            out_inode->uid = 0;
            out_inode->gid = 0;
            out_inode->size = 0;
            vfs_inode_set_ptr(out_inode, 0);
        }
        return 0;
    }
    if (dev_dri_is_node(name)) {
        if (out_parent) {
            memset(out_parent, 0, sizeof(*out_parent));
            out_parent->ino = 0xD0FFD800u;
            out_parent->mode = VFS_INODE_DIR | 0755;
            out_parent->uid = 0;
            out_parent->gid = 0;
            out_parent->size = 0;
            vfs_inode_set_ptr(out_parent, 0);
        }
        if (out_sb) *out_sb = 0;
        if (out_inode) {
            memset(out_inode, 0, sizeof(*out_inode));
            out_inode->ino =
                strcmp(name, "dri/renderD128") == 0 ?
                    0xD0FFD880u : 0xD0FFD801u;
            out_inode->mode = VFS_INODE_CHR | 0660;
            out_inode->uid = 0;
            out_inode->gid = 0;
            out_inode->size = 0;
            vfs_inode_set_ptr(out_inode, 0);
        }
        return 0;
    }
    {
        char full[VFS_PATH_MAX];
        int kind;
        uint32_t flen;
        strcpy(full, "/dev/");
        flen = (uint32_t)strlen(full);
        for (uint32_t i = 0; name[i] && flen + 1 < sizeof(full); ++i) full[flen++] = name[i];
        full[flen] = 0;
        kind = alsa_path_kind(full);
        if (kind == EDGE_ALSA_NODE_CONTROL || kind == EDGE_ALSA_NODE_PCM_PLAYBACK ||
            kind == EDGE_ALSA_NODE_PCM_CAPTURE ||
            kind == EDGE_ALSA_NODE_TIMER) {
            if (!alsa_available()) return -1;
            if (out_parent) {
                memset(out_parent, 0, sizeof(*out_parent));
                out_parent->ino = alsa_inode_from_kind(EDGE_ALSA_NODE_SND_DIR);
                out_parent->mode = VFS_INODE_DIR | 0755;
                out_parent->uid = 0;
                out_parent->gid = 0;
                out_parent->size = 0;
                vfs_inode_set_ptr(out_parent, 0);
            }
            if (out_sb) *out_sb = 0;
            if (out_inode) {
                memset(out_inode, 0, sizeof(*out_inode));
                out_inode->ino = alsa_inode_from_kind(kind);
                out_inode->mode = VFS_INODE_CHR | 0660;
                out_inode->uid = 0;
                out_inode->gid = 0;
                out_inode->size = 0;
                vfs_inode_set_ptr(out_inode, 0);
            }
            return 0;
        }
    }
    if (!name[0]) return -1;
    for (const char *p = name; *p; ++p) if (*p == '/') return -1;

    int idx = vfs_devnode_find(name);
    if (idx < 0) return -1;

    if (out_parent) {
        vfs_inode_t devdir;
        if (vfs_resolve("/dev", &devdir, 0, 0, 0) == 0) *out_parent = devdir;
        else memset(out_parent, 0, sizeof(*out_parent));
    }
    if (out_sb) *out_sb = 0;
    if (out_inode) {
        memset(out_inode, 0, sizeof(*out_inode));
        out_inode->ino = (uint32_t)(0xD0000000u + (uint32_t)idx);
        out_inode->mode = g_devnodes[idx].mode;
        out_inode->uid = 0;
        out_inode->gid = 0;
        out_inode->size = 0;
        out_inode->rdev = vfs_memory_device_rdev(g_devnodes[idx].kind,
                                                 g_devnodes[idx].name);
        vfs_inode_set_ptr(out_inode, g_devnodes[idx].ptr);
    }
    return 0;
}

void vfs_bootstrap_init(void) {
    vfs_mount_namespace_bootstrap();
    vfs_path_cache_runtime_reset();
    vfs_filesystem_registry_reset();
    g_devnode_count = 0;
    strcpy(g_cwd, "/");
}

void vfs_init(void) {
    vfs_bootstrap_init();
#ifdef CONFIG_FS_EXT2
    vfs_register("ext2", ext2_mount);
#endif
#ifdef CONFIG_FS_EXT4
    vfs_register("ext4", ext4_mount);
#endif
#ifdef CONFIG_FS_FAT32
    vfs_register("fat32", fat32_mount);
#endif
#ifdef CONFIG_FS_EXFAT
    vfs_register("exfat", exfat_mount);
#endif
#ifdef CONFIG_FS_NTFS
    vfs_register("ntfs", ntfs_mount);
#endif
#ifdef CONFIG_FS_ISO9660
    vfs_register("iso9660", iso9660_mount);
#endif
#ifdef CONFIG_FS_UDF
    vfs_register("udf", udf_mount);
#endif
#ifdef CONFIG_FS_SQUASHFS
    vfs_register("squashfs", squashfs_mount);
#endif
#ifdef CONFIG_FS_EROFS
    vfs_register("erofs", erofs_mount);
#endif
#ifdef CONFIG_FS_XFS
    vfs_register("xfs", xfs_mount);
#endif
#ifdef CONFIG_FS_BTRFS
    vfs_register("btrfs", btrfs_mount);
#endif
    vfs_register("proc", procfs_mount);
    vfs_register("sysfs", sysfs_mount);
    vfs_register("tmpfs", tmpfs_mount);
#ifdef CONFIG_BPF_SYSCALL
    vfs_register("bpf", bpffs_mount);
#endif
    vfs_register("devtmpfs", devtmpfs_mount);
    vfs_register("cgroup2", cgroupfs_mount);
#ifdef CONFIG_OVERLAY_FS
    vfs_register("overlay", overlayfs_mount);
#endif
    vfs_build_devnodes();
}

int vfs_register(const char *name, int (*mount_fn)(const char *dev, const char *target)) {
    return vfs_filesystem_registry_register(name, mount_fn);
}

static vfs_superblock_t *vfs_find_mount(const char *path) {
    vfs_superblock_t *current = 0;
    int current_index = -1;
    if (!path || path[0] != '/') return 0;

    for (int i = 0; i < g_mount_count; ++i) {
        if (g_mount_at(i).parent_mount_id == 0 &&
            strcmp(g_mount_at(i).mountpoint, "/") == 0) {
            current = &g_mount_at(i);
            current_index = i;
        }
    }
    if (!current) return 0;

    for (int depth = 0; depth < g_mount_count; ++depth) {
        int child = -1;
        for (int i = 0; i < g_mount_count; ++i) {
            int length;
            if (i == current_index ||
                g_mount_at(i).parent_mount_id != current->mount_id)
                continue;
            length = (int)strlen(g_mount_at(i).mountpoint);
            if (strncmp(path, g_mount_at(i).mountpoint, length) != 0 ||
                !(path[length] == 0 || path[length] == '/' || length == 1))
                continue;
            /* Later siblings are the top of an overmount stack. */
            child = i;
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
    if (!mount || !ancestor_mount_id) return 0;
    parent_mount_id = mount->parent_mount_id;
    for (int depth = 0; depth < g_mount_count && parent_mount_id; ++depth) {
        vfs_superblock_t *parent = 0;
        if (parent_mount_id == ancestor_mount_id) return 1;
        for (int index = 0; index < g_mount_count; ++index) {
            if (g_mount_at(index).mount_id != parent_mount_id) continue;
            parent = &g_mount_at(index);
            break;
        }
        if (!parent || parent->parent_mount_id == parent_mount_id) break;
        parent_mount_id = parent->parent_mount_id;
    }
    return 0;
}

int vfs_mount(const char *dev, const char *target, const char *fsname) {
    return vfs_filesystem_registry_mount(fsname, dev, target);
}

int vfs_mount_blockdev(block_device_t *dev, const char *target, const char *fsname) {
    if (!dev || !target || !fsname) return -1;
#ifdef CONFIG_FS_EXT4
    if (strcmp((char *)fsname, "ext4") == 0) return ext4_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_EXT2
    if (strcmp((char *)fsname, "ext2") == 0) return ext2_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_FAT32
    if (strcmp((char *)fsname, "fat32") == 0) return fat32_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_EXFAT
    if (strcmp((char *)fsname, "exfat") == 0) return exfat_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_NTFS
    if (strcmp((char *)fsname, "ntfs") == 0) return ntfs_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_ISO9660
    if (strcmp((char *)fsname, "iso9660") == 0) return iso9660_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_UDF
    if (strcmp((char *)fsname, "udf") == 0) return udf_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_SQUASHFS
    if (strcmp((char *)fsname, "squashfs") == 0)
        return squashfs_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_EROFS
    if (strcmp((char *)fsname, "erofs") == 0)
        return erofs_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_XFS
    if (strcmp((char *)fsname, "xfs") == 0)
        return xfs_mount_block(dev, target);
#endif
#ifdef CONFIG_FS_BTRFS
    if (strcmp((char *)fsname, "btrfs") == 0)
        return btrfs_mount_block(dev, target);
#endif
    return -1;
}

static int vfs_add_superblock_internal(vfs_superblock_t *sb,
                                       int notify_change) {
    vfs_superblock_t *covered;
    uint64_t parent_mount_id = 0;
    if (!sb || g_mount_count < 0 ||
        vfs_mount_table_reserve(
            &g_mount_table, (uint32_t)g_mount_count + 1u) < 0)
        return -1;
    covered = vfs_find_mount(sb->mountpoint);
    if (covered) {
        parent_mount_id = strcmp(covered->mountpoint, sb->mountpoint) == 0 ?
            covered->parent_mount_id : covered->mount_id;
    }
    g_mount_at(g_mount_count) = *sb;
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
    /*
     * The registration object and the installed mount wrapper describe the
     * same filesystem.  Publish the stable identity back to the source so any
     * backend-owned handle retained after registration cannot allocate a
     * second identity for the same fs_private state.
     */
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

int vfs_set_mount_propagation(const char *target, uint32_t propagation,
                              int recursive) {
    static uint32_t propagation_failure_budget = 12;
    int changed = 0;
    vfs_superblock_t *selected;
    if (!target || target[0] != '/' || propagation < VFS_MOUNT_SHARED ||
        propagation > VFS_MOUNT_UNBINDABLE) return -1;
    selected = vfs_find_mount(target);
    if (!selected) {
        if (propagation_failure_budget) {
            --propagation_failure_budget;
            printf("[mount-propagation] ns=%u target=%s selected=%s mounts=%d\n",
                   vfs_mount_namespace_current(), target,
                   selected ? selected->mountpoint : "(none)", g_mount_count);
            for (int index = 0; index < g_mount_count; ++index) {
                printf("[mount-propagation] mount=%s id=%llu parent=%llu\n",
                       g_mount_at(index).mountpoint,
                       (unsigned long long)g_mount_at(index).mount_id,
                       (unsigned long long)g_mount_at(index).parent_mount_id);
            }
        }
        return -1;
    }
    for (int i = 0; i < g_mount_count; ++i) {
        vfs_superblock_t *mount = &g_mount_at(i);
        if (mount != selected &&
            (!recursive ||
             !vfs_mount_has_ancestor(mount, selected->mount_id))) continue;
        mount->propagation = propagation;
        if (propagation == VFS_MOUNT_SHARED) {
            if (!mount->peer_group) mount->peer_group = g_next_mount_peer_group++;
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
    vfs_superblock_t *source_sb;
    vfs_superblock_t bind;
    int original_mount_count;
    if (!source || !target || source[0] != '/' || target[0] != '/') return -1;
    if (vfs_resolve(source, &source_inode, &source_sb, 0, 0) < 0 || !source_sb ||
        vfs_resolve(target, &target_inode, 0, 0, 0) < 0) return -1;
    if (((source_inode.mode & 0xf000u) == VFS_INODE_DIR) !=
        ((target_inode.mode & 0xf000u) == VFS_INODE_DIR)) return -1;
    if (source_sb->propagation == VFS_MOUNT_UNBINDABLE) return -1;
    original_mount_count = g_mount_count;
    bind = *source_sb;
    bind.root = source_inode;
    strncpy(bind.mountpoint, target, sizeof(bind.mountpoint) - 1u);
    bind.mountpoint[sizeof(bind.mountpoint) - 1u] = 0;
    bind.propagation = VFS_MOUNT_PRIVATE;
    bind.peer_group = 0;
    bind.master_group = 0;
    bind.mount_id = 0;
    bind.parent_mount_id = 0;
    if (vfs_add_superblock_internal(&bind, 0) < 0) return -1;
    if (recursive) {
        char nested_mountpoint[VFS_PATH_MAX];
        uint32_t source_length = (uint32_t)strlen(source);
        for (int index = 0; index < original_mount_count; ++index) {
            vfs_superblock_t nested;
            const char *suffix;
            if (!mount_path_is_at_or_below(g_mount_at(index).mountpoint,
                                            source) ||
                strcmp(g_mount_at(index).mountpoint, source) == 0 ||
                g_mount_at(index).propagation == VFS_MOUNT_UNBINDABLE)
                continue;
            nested = g_mount_at(index);
            suffix = nested.mountpoint + (source_length == 1u ? 0u :
                                                               source_length);
            if (mount_path_copy_join(nested_mountpoint, target, suffix) < 0)
                goto rollback;
            memcpy(nested.mountpoint, nested_mountpoint,
                   strlen(nested_mountpoint) + 1u);
            nested.mount_id = 0;
            nested.parent_mount_id = 0;
            if (vfs_add_superblock_internal(&nested, 0) < 0) goto rollback;
        }
    }
    vfs_mount_namespace_note_change();
    return 0;

rollback:
    for (int index = original_mount_count; index < g_mount_count; ++index) {
        vfs_superblock_release(&g_mount_at(index));
    }
    g_mount_count = original_mount_count;
    vfs_path_cache_invalidate_all();
    return -1;
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
            (strcmp(g_mount_at(index).dev_name, device_name) == 0 ||
             strcmp(g_mount_at(index).dev_name, basename) == 0))
            return &g_mount_at(index);
    return 0;
}

int vfs_remount(const char *target, uint32_t mount_flags) {
    vfs_superblock_t *mount;
    if (!target || target[0] != '/') return -1;
    mount = vfs_find_mount(target);
    if (!mount || strcmp(mount->mountpoint, target) != 0) return -1;
    mount->mount_flags = mount_flags;
    vfs_mount_namespace_note_change();
    return 0;
}

static int mount_path_is_at_or_below(const char *mountpoint,
                                     const char *target) {
    uint32_t index = 0;
    while (target[index] && mountpoint[index] == target[index]) ++index;
    if (target[index]) return 0;
    if (index == 1u && target[0] == '/') return 1;
    return !mountpoint[index] || mountpoint[index] == '/';
}

int vfs_umount(const char *target, int detach) {
    vfs_superblock_t *selected_mount;
    uint64_t selected_mount_id;
    int selected = -1;
    int output = 0;
    if (!target || target[0] != '/') return -1;
    if (strcmp(target, "/") == 0) {
        if (!detach) return -1;
        target = "/.edgeos-pivot-old";
    }
    selected_mount = vfs_find_mount(target);
    if (!selected_mount || strcmp(selected_mount->mountpoint, target) != 0)
        return -1;
    selected_mount_id = selected_mount->mount_id;
    for (int index = 0; index < g_mount_count; ++index)
        if (&g_mount_at(index) == selected_mount) selected = index;
    if (selected < 0 || !selected_mount_id) return -1;
    if (!detach) {
        for (int index = 0; index < g_mount_count; ++index)
            if (vfs_mount_has_ancestor(&g_mount_at(index), selected_mount_id))
                return -2;
    }
    for (int index = 0; index < g_mount_count; ++index) {
        int remove = index == selected;
        if (detach &&
            vfs_mount_has_ancestor(&g_mount_at(index), selected_mount_id)) {
            remove = 1;
        }
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

static int mount_path_copy_join(char out[VFS_PATH_MAX], const char *prefix,
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

    if (!new_root || !put_old || new_root[0] != '/' || put_old[0] != '/' ||
        strcmp(new_root, "/") == 0) return -1;
    while (new_root[new_length]) ++new_length;
    if (strcmp(new_root, put_old) != 0 &&
        (!mount_path_is_at_or_below(put_old, new_root) ||
         put_old[new_length] != '/')) return -1;
    if (vfs_resolve(new_root, &new_inode, 0, 0, 0) < 0 ||
        vfs_resolve(put_old, &old_inode, 0, 0, 0) < 0 ||
        (new_inode.mode & 0xf000u) != VFS_INODE_DIR ||
        (old_inode.mode & 0xf000u) != VFS_INODE_DIR) return -1;
    new_root_mount = vfs_find_mount(new_root);
    old_root_mount = vfs_find_mount("/");
    if (!new_root_mount || !old_root_mount ||
        strcmp(new_root_mount->mountpoint, new_root) != 0)
        return -1;

    old_relative = strcmp(new_root, put_old) == 0 ? detached_old_root :
                                                   put_old + new_length;
    workspace = vfs_mount_path_workspace_allocate(
        (uint32_t)g_mount_count, &workspace_pages);
    if (!workspace) return -1;
    for (int index = 0; index < g_mount_count; ++index) {
        char *rebased = workspace + (uint64_t)index * VFS_PATH_MAX;
        const char *mountpoint = g_mount_at(index).mountpoint;
        if (&g_mount_at(index) == new_root_mount ||
            vfs_mount_has_ancestor(&g_mount_at(index),
                                   new_root_mount->mount_id)) {
            const char *suffix = mountpoint + new_length;
            if (!suffix[0]) suffix = "/";
            if (mount_path_copy_join(rebased, "/", suffix) < 0) {
                vfs_mount_path_workspace_release(
                    workspace, workspace_pages);
                return -1;
            }
        } else {
            const char *suffix = strcmp(mountpoint, "/") == 0 ? "" :
                                                                     mountpoint;
            if (mount_path_copy_join(rebased, old_relative, suffix) < 0) {
                vfs_mount_path_workspace_release(
                    workspace, workspace_pages);
                return -1;
            }
        }
    }
    for (int index = 0; index < g_mount_count; ++index) {
        const char *rebased =
            workspace + (uint64_t)index * VFS_PATH_MAX;
        strncpy(g_mount_at(index).mountpoint, rebased,
                sizeof(g_mount_at(index).mountpoint) - 1u);
        g_mount_at(index).mountpoint[
            sizeof(g_mount_at(index).mountpoint) - 1u] = 0;
    }
    new_root_mount->parent_mount_id = 0;
    old_root_mount->parent_mount_id = new_root_mount->mount_id;
    vfs_mount_path_workspace_release(workspace, workspace_pages);
    vfs_path_cache_invalidate_all();
    vfs_mount_namespace_note_change();
    return 0;
}

int vfs_mount_exists(const char *target, const char *fsname, const char *dev) {
    if (!target || !fsname) return 0;
    for (int i = 0; i < g_mount_count; ++i) {
        const char *mounted_dev = g_mount_at(i).dev_name[0] ? g_mount_at(i).dev_name : "";
        if (strcmp(g_mount_at(i).mountpoint, target) != 0) continue;
        if (strcmp(g_mount_at(i).fs_name, fsname) != 0) continue;
        if (dev && dev[0] && strcmp(mounted_dev, dev) != 0) continue;
        return 1;
    }
    return 0;
}

static void normalize_path_components(const char *input, char *out, int *out_length) {
    int offset = 0;
    int length;

    if (!input || !out || !out_length) return;
    length = *out_length;
    while (input[offset]) {
        int start;
        int component_length;

        while (input[offset] == '/') offset++;
        if (!input[offset]) break;
        start = offset;
        while (input[offset] && input[offset] != '/') offset++;
        component_length = offset - start;
        if (component_length == 1 && input[start] == '.') continue;
        if (component_length == 2 && input[start] == '.' &&
            input[start + 1] == '.') {
            if (length > 1) {
                length--;
                while (length > 1 && out[length - 1] != '/') length--;
                out[length] = 0;
            }
            continue;
        }
        if (length > 1 && length < VFS_PATH_MAX - 1) out[length++] = '/';
        for (int index = 0;
             index < component_length && length < VFS_PATH_MAX - 1;
             ++index)
            out[length++] = input[start + index];
        out[length] = 0;
    }
    *out_length = length;
}

static void normalize_path(const char *in, char *out) {
    char cwd[VFS_PATH_MAX];
    int length = 1;

    if (vfs_getcwd(cwd, sizeof(cwd)) < 0) strcpy(cwd, "/");
    out[0] = '/';
    out[1] = 0;
    if (!in || !in[0]) {
        normalize_path_components(cwd, out, &length);
        return;
    }
    if (in[0] != '/') normalize_path_components(cwd, out, &length);
    normalize_path_components(in, out, &length);
}

static int path_append_limited(char *dst, uint32_t max, const char *src) {
    uint32_t d;
    if (!dst || !src || max == 0) return -1;
    d = (uint32_t)strlen(dst);
    while (*src) {
        if (d + 1 >= max) return -1;
        dst[d++] = *src++;
    }
    dst[d] = 0;
    return 0;
}

void vfs_path_cache_invalidate(const char *path) {
    char abs[VFS_PATH_MAX];
    if (!path) return;
    normalize_path(path, abs);
    vfs_path_cache_runtime_invalidate_absolute(abs);
}

static int path_split_last(const char *path, char *parent, char *leaf) {
    int len = (int)strlen(path);
    while (len > 1 && path[len - 1] == '/') len--;
    int cut = len - 1;
    while (cut > 0 && path[cut] != '/') cut--;
    int n = len - cut - 1;
    if (n <= 0 || n >= VFS_NAME_MAX) return -1;
    memcpy(leaf, path + cut + 1, n); leaf[n] = 0;
    if (cut == 0) strcpy(parent, "/");
    else { memcpy(parent, path, cut); parent[cut] = 0; }
    return 0;
}

int vfs_resolve(const char *path, vfs_inode_t *out_inode, vfs_superblock_t **out_sb, vfs_inode_t *out_parent, char *leaf) {
    if (out_inode) memset(out_inode, 0, sizeof(*out_inode));
    if (out_sb) *out_sb = 0;
    if (out_parent) memset(out_parent, 0, sizeof(*out_parent));
    if (leaf) leaf[0] = 0;
    return vfs_resolve_inner(path, out_inode, out_sb, out_parent, leaf, 0, 1,
                             0, 0, "/");
}

static int vfs_resolve_inner(const char *path, vfs_inode_t *out_inode, vfs_superblock_t **out_sb,
                             vfs_inode_t *out_parent, char *leaf, int symlink_depth,
                             int follow_final_symlink, char *resolved,
                             uint32_t resolved_capacity,
                             const char *resolution_root) {
    char abs[VFS_PATH_MAX];
    const char *rel;
    vfs_superblock_t *sb;
    if (symlink_depth > VFS_MAX_SYMLINK_FOLLOWS) return -1;
    normalize_path(path, abs);
    sb = vfs_find_mount(abs);
    /*
     * The legacy sysfs model is synthesized over the root or /sys mount.  A
     * real nested mount must take precedence, just as a Linux mount hides the
     * covered sysfs dentry.  This is required for /sys/fs/cgroup and for any
     * future cgroup or tracing filesystem mounted below sysfs.
     */
    if ((!sb || strcmp(sb->mountpoint, "/") == 0) &&
        vfs_try_resolve_syspath(abs, out_inode, out_sb, out_parent) == 0)
        return 0;
    if (!out_parent && !leaf && !resolved) {
        vfs_inode_t cached_inode;
        uint32_t cached_sb_index = 0;
        int cached_miss = 0;
        if (vfs_path_cache_lookup(abs, &cached_inode, &cached_sb_index,
                                  &cached_miss)) {
            vfs_mount_table_t *mount_table =
                vfs_mount_namespace_active_table();
            if (cached_miss) return -1;
            if (cached_sb_index >= (uint32_t)mount_table->mount_count)
                return -1;
            if (out_inode) *out_inode = cached_inode;
            if (out_sb)
                *out_sb = vfs_mount_table_at(
                    mount_table, cached_sb_index);
            if (resolved) {
                uint32_t length = (uint32_t)strlen(abs);
                if (!resolved_capacity || length >= resolved_capacity)
                    return -1;
                memcpy(resolved, abs, length + 1u);
            }
            return 0;
        }
    }
    VFS_DEBUG("resolve input='%s' abs='%s'", path ? path : "", abs);
    if (!sb) {
        if (vfs_try_resolve_devpath(abs, out_inode, out_sb, out_parent) == 0)
            return 0;
        VFS_DEBUG("resolve failed: no mount for '%s'", abs);
        if (!out_parent && !leaf) vfs_path_cache_store(abs, 1, 0, 0);
        return -1;
    }

    int ml = (int)strlen(sb->mountpoint);
    if (ml == 1) rel = abs + 1;
    else rel = abs + ml + (abs[ml] == '/' ? 1 : 0);
    VFS_DEBUG("resolve mount='%s' rel='%s'", sb->mountpoint, rel);

    vfs_inode_t cur = sb->root;
    if (out_parent) *out_parent = cur;
    if (!rel[0]) {
        if (out_inode) *out_inode = cur;
        if (out_sb) *out_sb = sb;
        if (!out_parent && !leaf) vfs_path_cache_store(abs, 0, &cur, sb);
        if (resolved) {
            uint32_t length = (uint32_t)strlen(abs);
            if (!resolved_capacity || length >= resolved_capacity) return -1;
            memcpy(resolved, abs, length + 1u);
        }
        VFS_DEBUG("resolve success inode=%u (root)", cur.ino);
        return 0;
    }

    char part[VFS_NAME_MAX];
    const char *p = rel;
    if (!sb->ops || !sb->ops->lookup) return -1;
    while (*p) {
        int pi = 0;
        while (*p && *p != '/') { if (pi < VFS_NAME_MAX - 1) part[pi++] = *p; p++; }
        part[pi] = 0;
        if (*p == '/') p++;
        if (!part[0] || strcmp(part, ".") == 0) continue;
        if (strcmp(part, "..") == 0) continue;
        if (out_parent) *out_parent = cur;
        VFS_DEBUG("resolve step part='%s' parent_ino=%u", part, cur.ino);
        if (sb->ops->lookup(sb, &cur, part, &cur) < 0) {
            /*
             * Once sysfs is mounted, its real superblock must own every path
             * it implements so directory descriptors, statfs, and *at
             * syscalls retain mount identity.  Keep the older synthetic
             * device model only for dynamic paths not represented by the
             * sysfs filesystem yet.
             */
            if (strcmp(sb->mountpoint, "/sys") == 0 &&
                vfs_try_resolve_syspath(abs, out_inode, out_sb,
                                        out_parent) == 0)
                return 0;
            /*
             * Built-in device nodes are the pre-devtmpfs fallback for the
             * root filesystem only.  Once a filesystem is mounted on /dev,
             * it owns that namespace completely; synthesizing a missing node
             * through the covered root makes devtmpfs population observe a
             * false EEXIST and forces the mount to roll back.
             */
            if (strcmp(sb->mountpoint, "/") == 0 &&
                vfs_try_resolve_devpath(abs, out_inode, out_sb,
                                        out_parent) == 0)
                return 0;
            if (leaf) strcpy(leaf, part);
            if (out_sb) *out_sb = sb;
            if (!out_parent && !leaf) vfs_path_cache_store(abs, 1, 0, 0);
            VFS_DEBUG("resolve miss part='%s' under parent_ino=%u", part, out_parent ? out_parent->ino : 0);
            return -1;
        }
        if ((cur.mode & 0xF000u) == VFS_INODE_LNK) {
            char target[VFS_PATH_MAX];
            char next[VFS_PATH_MAX];
            uint32_t next_len;
            int rn;

            if (!*p && !follow_final_symlink) {
                if (out_inode) *out_inode = cur;
                if (out_sb) *out_sb = sb;
                if (resolved) {
                    uint32_t length = (uint32_t)strlen(abs);
                    if (!resolved_capacity || length >= resolved_capacity)
                        return -1;
                    memcpy(resolved, abs, length + 1u);
                }
                return 0;
            }
            if (!sb->ops->readlink) return -1;
            rn = sb->ops->readlink(sb, &cur, target, sizeof(target) - 1);
            if (rn < 0 || rn >= (int)sizeof(target)) return -1;
            target[rn] = 0;

            if (target[0] != '/') {
                uint32_t consumed = (uint32_t)(p - rel);
                uint32_t rel_start = (ml == 1) ? 1u : (uint32_t)ml + 1u;
                uint32_t end = rel_start + consumed;
                if (end >= sizeof(abs)) end = (uint32_t)strlen(abs);
                while (end > 1 && abs[end - 1] == '/') end--;
                while (end > 1 && abs[end - 1] != '/') end--;
                if (end == 0) end = 1;
                memcpy(next, abs, end);
                next[end] = 0;
            } else {
                next[0] = '/';
                next[1] = 0;
            }

            next_len = (uint32_t)strlen(target);
            if (*p) {
                if (next_len + 1 >= sizeof(target)) return -1;
                if (target[next_len - 1] != '/') {
                    target[next_len++] = '/';
                    target[next_len] = 0;
                }
                if (path_append_limited(target, sizeof(target), p) < 0)
                    return -1;
            }
            if (kernel_fs_path_resolve(
                    resolution_root ? resolution_root : "/", next,
                    target, abs, sizeof(abs), next, sizeof(next)) < 0)
                return -1;
            return vfs_resolve_inner(next, out_inode, out_sb, out_parent, leaf,
                                     symlink_depth + 1, follow_final_symlink,
                                     resolved, resolved_capacity,
                                     resolution_root);
        }
        VFS_DEBUG("resolve hit part='%s' inode=%u", part, cur.ino);
    }
    if (out_inode) *out_inode = cur;
    if (out_sb) *out_sb = sb;
    if (!out_parent && !leaf) vfs_path_cache_store(abs, 0, &cur, sb);
    if (resolved) {
        uint32_t length = (uint32_t)strlen(abs);
        if (!resolved_capacity || length >= resolved_capacity) return -1;
        memcpy(resolved, abs, length + 1u);
    }
    VFS_DEBUG("resolve success inode=%u", cur.ino);
    return 0;
}

int vfs_resolve_nofollow(const char *path, vfs_inode_t *out_inode,
                         vfs_superblock_t **out_sb) {
    if (out_inode) memset(out_inode, 0, sizeof(*out_inode));
    if (out_sb) *out_sb = 0;
    return vfs_resolve_inner(path, out_inode, out_sb, 0, 0, 0, 0, 0, 0,
                             "/");
}

int vfs_resolve_canonical(const char *path, char *resolved,
                          uint32_t resolved_capacity,
                          vfs_inode_t *out_inode,
                          vfs_superblock_t **out_sb) {
    if (out_inode) memset(out_inode, 0, sizeof(*out_inode));
    if (out_sb) *out_sb = 0;
    if (!resolved || !resolved_capacity) return -1;
    resolved[0] = 0;
    return vfs_resolve_inner(path, out_inode, out_sb, 0, 0, 0, 1,
                             resolved, resolved_capacity, "/");
}

int vfs_resolve_canonical_rooted(const char *path, const char *root,
                                 char *resolved,
                                 uint32_t resolved_capacity,
                                 vfs_inode_t *out_inode,
                                 vfs_superblock_t **out_sb) {
    if (out_inode) memset(out_inode, 0, sizeof(*out_inode));
    if (out_sb) *out_sb = 0;
    if (!root || root[0] != '/' || !resolved || !resolved_capacity)
        return -1;
    resolved[0] = 0;
    return vfs_resolve_inner(path, out_inode, out_sb, 0, 0, 0, 1,
                             resolved, resolved_capacity, root);
}

int vfs_resolve_cached(const char *path, vfs_inode_t *out_inode,
                       vfs_superblock_t **out_sb, int *negative) {
    vfs_mount_table_t *table;
    uint32_t superblock_index = 0;
    int miss = 0;

    if (!path || path[0] != '/') return 0;
    if (!vfs_path_cache_lookup(
            path, out_inode, &superblock_index, &miss))
        return 0;
    if (negative) *negative = miss;
    if (miss) {
        if (out_sb) *out_sb = 0;
        return 1;
    }
    table = vfs_mount_namespace_active_table();
    if (superblock_index >= (uint32_t)table->mount_count) return 0;
    if (out_sb) *out_sb = vfs_mount_table_at(table, superblock_index);
    return 1;
}

int vfs_pread(const char *path, uint32_t off, void *out, uint32_t len) {
    vfs_inode_t ino;
    vfs_superblock_t *sb = 0;
    int result;
    if (!path || (!out && len)) return -1;
    if (len == 0) return 0;
    result = vfs_sys_class_read_file_at(path, off, (char *)out, len);
    if (result >= 0) return result;
    if (vfs_resolve(path, &ino, &sb, 0, 0) < 0 || !sb || !sb->ops ||
        !sb->ops->read || vfs_permission_check(&ino, 4) < 0)
        return -1;
    if (off >= ino.size) return 0;
    if (len > ino.size - off) len = ino.size - off;
    return sb->ops->read(sb, &ino, off, out, len);
}

int vfs_read_file(const char *path, char *out, uint32_t max) {
    vfs_inode_t ino; vfs_superblock_t *sb = 0;
    {
        int rn = vfs_sys_class_read_file_at(path, 0, out, max);
        if (rn >= 0) return rn;
    }
    if (vfs_resolve(path, &ino, &sb, 0, 0) < 0) return -1;
    if (vfs_permission_check(&ino, 4) < 0) return -1;
    if (path && strcmp(path, "/etc/resolv.conf") == 0 && ino.size == 0) {
        const char *dns = "nameserver 10.0.2.3\nnameserver 1.1.1.1\n";
        uint32_t n = (uint32_t)strlen(dns);
        if (n > max) n = max;
        memcpy(out, dns, n);
        return (int)n;
    }
    if (path && (strcmp(path, "/dev/input/mice") == 0 || strcmp(path, "/dev/input/mouse0") == 0)) {
        return keyboard_mouse_read(out, max, 0);
    }
    if (path && strcmp(path, "/dev/kmsg") == 0) {
        uint64_t pos = bootlog_kmsg_first_offset();
        return bootlog_kmsg_read_from(&pos, out, max);
    }
    if (path && strncmp(path, "/dev/input/event", 16) == 0) {
        int ev = 0;
        const char *p = path + 16;
        if (!*p) return -1;
        while (*p >= '0' && *p <= '9') {
            ev = ev * 10 + (*p - '0');
            ++p;
        }
        if (*p == 0 && ev >= 0 && ev < (int)EDGE_INPUT_DEVICE_MAX)
            return keyboard_event_read(ev, out, max, 0);
    }
    if ((ino.mode & 0xF000) == VFS_INODE_CHR) {
        int result = edge_memdev_read(ino.rdev, out, max);
        if (result != EDGE_MEMDEV_NOT_HANDLED) return result;
        int idx = vfs_devnode_from_inode(&ino);
        if (idx >= 0) return vfs_dev_read_chr(&g_devnodes[idx], out, max);
        if (alsa_path_kind(path) != EDGE_ALSA_NODE_NONE) return alsa_read(path, out, max);
        return vfs_read_tty(out, max);
    }
    if ((ino.mode & 0xF000) == VFS_INODE_BLK) {
        block_device_t *device = 0;
        int64_t result;
        if (vfs_inode_get_block_device(&ino, &device) < 0) return -1;
        result = block_read_bytes(device, 0, out, max);
        return result < 0 ? -1 : (int)result;
    }
    if (!sb || !sb->ops || !sb->ops->read) return -1;
    return sb->ops->read(sb, &ino, 0, out, max);
}

int vfs_write_file(const char *path, const char *buf, uint32_t len) {
    vfs_inode_t ino, parent; vfs_superblock_t *sb = 0; char leaf[VFS_NAME_MAX]; char parent_path[VFS_PATH_MAX];
    char abs[VFS_PATH_MAX];
    normalize_path(path, abs);
    if (vfs_resolve(abs, &ino, &sb, 0, 0) == 0) {
        if (vfs_permission_check(&ino, 2) < 0) return -1;
        if ((ino.mode & 0xF000) == VFS_INODE_CHR) {
            int result = edge_memdev_write(ino.rdev, buf, len);
            if (result != EDGE_MEMDEV_NOT_HANDLED) return result;
            int idx = vfs_devnode_from_inode(&ino);
            if (idx >= 0) return vfs_dev_write_chr(&g_devnodes[idx], buf, len);
            if (alsa_path_kind(abs) != EDGE_ALSA_NODE_NONE) return alsa_write(abs, buf, len);
            for (uint32_t i = 0; i < len; ++i) console_putchar(buf[i]);
            return (int)len;
        }
        if ((ino.mode & 0xF000) == VFS_INODE_BLK) {
            block_device_t *device = 0;
            int64_t result;
            if (vfs_inode_get_block_device(&ino, &device) < 0) return -1;
            result = block_write_bytes(device, 0, buf, len);
            return result < 0 ? -1 : (int)result;
        }
        if (!sb || !sb->ops || !sb->ops->write) return -1;
        {
            int rc = sb->ops->write(sb, &ino, 0, buf, len);
            if (rc >= 0) {
                if (vfs_sync_mutation_if_required(sb, 0) < 0) return -1;
                vfs_path_cache_invalidate(abs);
                edge_mmap_file_cache_invalidate_path(abs);
                edge_inotify_notify_path(abs, EDGE_IN_MODIFY, 0);
            }
            return rc;
        }
    }
    if (path_split_last(abs, parent_path, leaf) < 0) return -1;
    if (vfs_resolve(parent_path, &parent, &sb, 0, 0) < 0 || !sb ||
        !sb->ops || !sb->ops->create) return -1;
    if (vfs_permission_check(&parent, 3) < 0) return -1;
    VFS_DEBUG("create path='%s' parent='%s' parent_ino=%u leaf='%s'", abs, parent_path, parent.ino, leaf);
    if (sb->ops->create(sb, &parent, leaf, VFS_INODE_FILE | (0644 & (uint16_t)~vfs_current_umask()), &ino) < 0) return -1;
    if (!sb->ops->write) return -1;
    {
        int rc = sb->ops->write(sb, &ino, 0, buf, len);
        if (rc >= 0) {
            if (vfs_sync_mutation_if_required(sb, 1) < 0) return -1;
            vfs_path_cache_invalidate(abs);
            edge_mmap_file_cache_invalidate_path(abs);
            edge_inotify_notify_path(abs, EDGE_IN_CREATE, 0);
            if (len > 0) edge_inotify_notify_path(abs, EDGE_IN_MODIFY, 0);
        }
        return rc;
    }
}

int vfs_truncate(const char *path, uint32_t len) {
    vfs_inode_t ino;
    vfs_superblock_t *sb;
    char abs[VFS_PATH_MAX];
    normalize_path(path, abs);
    if (vfs_resolve(abs, &ino, &sb, 0, 0) < 0) return -1;
    if (vfs_permission_check(&ino, 2) < 0) return -1;
    if ((ino.mode & 0xF000) == VFS_INODE_DIR) return -1;
    if (!sb || !sb->ops || !sb->ops->truncate) return -1;
    if (sb->ops->truncate(sb, &ino, len) < 0) return -1;
    if (vfs_sync_mutation_if_required(sb, 0) < 0) return -1;
    vfs_path_cache_invalidate(abs);
    edge_mmap_file_cache_invalidate_path(abs);
    edge_inotify_notify_path(abs, EDGE_IN_MODIFY, 0);
    return 0;
}

int vfs_mkdir_mode(const char *path, uint16_t mode) {
    vfs_inode_t parent, out, existing;
    vfs_superblock_t *sb = 0;
    char leaf[VFS_NAME_MAX]; char parent_path[VFS_PATH_MAX];
    char abs[VFS_PATH_MAX];
    int rc;
    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    normalize_path(path, abs);
    if (vfs_resolve(abs, &existing, 0, 0, 0) == 0)
        return -EDGE_LINUX_EEXIST;
    if (path_split_last(abs, parent_path, leaf) < 0)
        return -EDGE_LINUX_EINVAL;
    if (vfs_resolve(parent_path, &parent, &sb, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    if ((parent.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (vfs_permission_check(&parent, 3) < 0)
        return -EDGE_LINUX_EACCES;
    if (vfs_mount_flags_for_path(parent_path) & VFS_MOUNT_READONLY)
        return -EDGE_LINUX_EROFS;
    if (!sb || !sb->ops || !sb->ops->mkdir)
        return -EDGE_LINUX_EROFS;
    VFS_DEBUG("mkdir path='%s' parent='%s' parent_ino=%u leaf='%s'", abs, parent_path, parent.ino, leaf);
    mode = (uint16_t)(VFS_INODE_DIR | (mode & 07777u));
    rc = sb->ops->mkdir(sb, &parent, leaf, mode, &out);
    if (rc < 0) return -EDGE_LINUX_EIO;
    if (vfs_sync_mutation_if_required(sb, 1) < 0)
        return -EDGE_LINUX_EIO;
    /*
     * Directory creation can also traverse an alias such as /var/run ->
     * /run.  Flush cached negative aliases so the new directory is
     * immediately visible through every equivalent path.
     */
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_mkdir(const char *path) {
    return vfs_mkdir_mode(
        path, (uint16_t)(0755u & (uint16_t)~vfs_current_umask()));
}

int vfs_create_file(const char *path, uint16_t mode, vfs_inode_t *out_inode,
                    vfs_superblock_t **out_sb) {
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_inode_t created;
    vfs_superblock_t *sb = 0;
    char leaf[VFS_NAME_MAX];
    char parent_path[VFS_PATH_MAX];
    char absolute[VFS_PATH_MAX];
    int result;

    if (!path || path[0] != '/') return VFS_PATH_ERR_INVALID;
    normalize_path(path, absolute);
    if (vfs_resolve(absolute, &existing, 0, 0, 0) == 0)
        return VFS_PATH_ERR_EXISTS;
    if (path_split_last(absolute, parent_path, leaf) < 0)
        return VFS_PATH_ERR_INVALID;
    if (vfs_resolve(parent_path, &parent, &sb, 0, 0) < 0)
        return VFS_PATH_ERR_NOT_FOUND;
    if ((parent.mode & 0xf000u) != VFS_INODE_DIR)
        return VFS_PATH_ERR_NOT_DIRECTORY;
    if (vfs_permission_check(&parent, 3) < 0)
        return VFS_PATH_ERR_ACCESS;
    if (vfs_mount_flags_for_path(parent_path) & VFS_MOUNT_READONLY)
        return VFS_PATH_ERR_READ_ONLY;
    if (!sb || !sb->ops || !sb->ops->create)
        return VFS_PATH_ERR_READ_ONLY;
    result = sb->ops->create(
        sb, &parent, leaf,
        (uint16_t)(VFS_INODE_FILE | (mode & 07777u)), &created);
    if (result < 0) return result;
    if (vfs_sync_mutation_if_required(sb, 1) < 0)
        return VFS_PATH_ERR_IO;
    if (out_inode) *out_inode = created;
    if (out_sb) *out_sb = sb;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_touch(const char *path) { return vfs_write_file(path, "", 0) >= 0 ? 0 : -1; }

int vfs_symlink(const char *target, const char *path) {
    vfs_inode_t ino;
    vfs_inode_t parent;
    vfs_superblock_t *sb;
    char leaf[VFS_NAME_MAX];
    char parent_path[VFS_PATH_MAX];
    char abs[VFS_PATH_MAX];

    if (!target || !target[0] || !path || !path[0]) return -1;
    normalize_path(path, abs);
    if (vfs_resolve(abs, &ino, &sb, 0, 0) == 0) return -1;
    if (path_split_last(abs, parent_path, leaf) < 0) return -1;
    if (vfs_resolve(parent_path, &parent, &sb, 0, 0) < 0) return -1;
    if (!sb || !sb->ops || !sb->ops->symlink) return -1;
    if (vfs_permission_check(&parent, 3) < 0) return -1;
    if (sb->ops->symlink(sb, &parent, leaf, target, 0777, &ino) < 0) return -1;
    if (vfs_sync_mutation_if_required(sb, 1) < 0) return -1;
    vfs_path_cache_invalidate(abs);
    return 0;
}

int vfs_link(const char *old_path, const char *new_path, int follow_source) {
    vfs_inode_t source;
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_superblock_t *source_sb = 0;
    vfs_superblock_t *destination_sb = 0;
    char destination[VFS_PATH_MAX];
    char parent_path[VFS_PATH_MAX];
    char leaf[VFS_NAME_MAX];

    if (!old_path || !new_path || old_path[0] != '/' ||
        new_path[0] != '/')
        return -1;
    if ((follow_source ?
         vfs_resolve(old_path, &source, &source_sb, 0, 0) :
         vfs_resolve_nofollow(old_path, &source, &source_sb)) < 0 ||
        !source_sb || (source.mode & 0xf000u) == VFS_INODE_DIR)
        return -1;
    normalize_path(new_path, destination);
    if (vfs_resolve_nofollow(destination, &existing, 0) == 0 ||
        path_split_last(destination, parent_path, leaf) < 0 || !leaf[0] ||
        vfs_resolve(parent_path, &parent, &destination_sb, 0, 0) < 0 ||
        !vfs_superblock_same_filesystem(destination_sb, source_sb) ||
        !destination_sb->ops ||
        !destination_sb->ops->link ||
        vfs_permission_check(&parent, 3) < 0)
        return -1;
    if (destination_sb->ops->link(
            destination_sb, &source, &parent, leaf) < 0)
        return -1;
    if (vfs_sync_mutation_if_required(destination_sb, 1) < 0)
        return -1;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_link_inode(vfs_superblock_t *source_sb, const vfs_inode_t *source,
                   const char *new_path) {
    vfs_inode_t source_copy;
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_superblock_t *destination_sb = 0;
    char destination[VFS_PATH_MAX];
    char parent_path[VFS_PATH_MAX];
    char leaf[VFS_NAME_MAX];

    if (!source_sb || !source || !new_path || new_path[0] != '/' ||
        (source->mode & 0xf000u) == VFS_INODE_DIR)
        return -1;
    normalize_path(new_path, destination);
    if (vfs_resolve_nofollow(destination, &existing, 0) == 0 ||
        path_split_last(destination, parent_path, leaf) < 0 || !leaf[0] ||
        vfs_resolve(parent_path, &parent, &destination_sb, 0, 0) < 0 ||
        !vfs_superblock_same_filesystem(destination_sb, source_sb) ||
        !destination_sb->ops ||
        !destination_sb->ops->link ||
        vfs_permission_check(&parent, 3) < 0)
        return -1;
    source_copy = *source;
    {
        int result = destination_sb->ops->link(
            destination_sb, &source_copy, &parent, leaf);
        if (result < 0) return result;
    }
    if (vfs_sync_mutation_if_required(destination_sb, 1) < 0)
        return -1;
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_mknod(const char *path, uint16_t mode, uint64_t rdev) {
    vfs_inode_t ino, parent;
    vfs_superblock_t *sb;
    vfs_superblock_t *existing_sb = 0;
    char leaf[VFS_NAME_MAX];
    char parent_path[VFS_PATH_MAX];
    char abs[VFS_PATH_MAX];
    uint16_t kind;
    int result;

    if (!path || !path[0] || path[0] != '/')
        return -EDGE_LINUX_EINVAL;
    kind = (uint16_t)(mode & 0xF000u);
    if (!kind) kind = VFS_INODE_FILE;
    if (kind != VFS_INODE_FILE && kind != VFS_INODE_SOCK &&
        kind != VFS_INODE_FIFO && kind != VFS_INODE_CHR &&
        kind != VFS_INODE_BLK)
        return -EDGE_LINUX_EINVAL;
    normalize_path(path, abs);
    /*
     * Early synthetic /dev entries have no backing superblock.  They remain
     * usable before a root filesystem exists, but must not prevent tmpfs or
     * devtmpfs from materializing the corresponding persistent inode.
     */
    if (vfs_resolve_nofollow(abs, &ino, &existing_sb) == 0 && existing_sb)
        return -EDGE_LINUX_EEXIST;
    if (path_split_last(abs, parent_path, leaf) < 0 || !leaf[0])
        return -EDGE_LINUX_EINVAL;
    if (vfs_resolve(parent_path, &parent, &sb, 0, 0) < 0 || !sb ||
        !sb->ops)
        return -EDGE_LINUX_ENOENT;
    if ((parent.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (sb->ops->lookup && sb->ops->lookup(sb, &parent, leaf, &ino) == 0)
        return -EDGE_LINUX_EEXIST;
    if (vfs_permission_check(&parent, 3) < 0)
        return -EDGE_LINUX_EACCES;

    /*
     * Linux pathname AF_UNIX bind and mkfifo(2) create typed filesystem
     * inodes.  A regular zero-byte placeholder is not equivalent: stat(2),
     * directory entries, and client libraries branch on S_IFSOCK/S_IFIFO.
     */
    mode = (uint16_t)(kind | (mode & 07777u));
    if (kind == VFS_INODE_FILE) {
        if (!sb->ops->create) return -EDGE_LINUX_EROFS;
        result = sb->ops->create(sb, &parent, leaf, mode, &ino);
    } else if (sb->ops->mknod) {
        result = sb->ops->mknod(sb, &parent, leaf, mode, rdev, &ino);
    } else if (sb->ops->create) {
        result = sb->ops->create(sb, &parent, leaf, mode, &ino);
    } else {
        return -EDGE_LINUX_EROFS;
    }
    if (result < 0) return -EDGE_LINUX_EIO;
    if (vfs_sync_mutation_if_required(sb, 1) < 0)
        return -EDGE_LINUX_EIO;
    /*
     * The requested path may traverse a symbolic-link alias such as
     * /var/run -> /run.  A negative lookup can therefore be cached under both
     * the user-visible path and its resolved target.  Invalidating only the
     * spelling passed to mknod leaves the resolved miss behind, so a FIFO can
     * be visible in readdir while an immediate open still reports ENOENT.
     * Special-node creation is uncommon enough that a generation change is
     * preferable to retaining an alias-dependent stale lookup.
     */
    vfs_path_cache_invalidate_all();
    return 0;
}

int vfs_create_special_node(const char *path, uint16_t mode) {
    int result = vfs_mknod(path, mode, 0);
    if (result == 0)
        edge_inotify_notify_path(path, EDGE_IN_CREATE, 0);
    return result;
}

int vfs_create_socket_node(const char *path, uint16_t mode) {
    return vfs_create_special_node(path, (uint16_t)(VFS_INODE_SOCK | (mode & 07777u)));
}

int vfs_unlink(const char *path) {
    vfs_inode_t parent, victim; vfs_superblock_t *sb = 0; char leaf[VFS_NAME_MAX]; char parent_path[VFS_PATH_MAX];
    char abs[VFS_PATH_MAX];
    int victim_found = 0;
    int victim_pinned = 0;
    normalize_path(path, abs);
    if (path_split_last(abs, parent_path, leaf) < 0) return -1;
    if (vfs_resolve(parent_path, &parent, &sb, 0, 0) < 0 || !sb ||
        !sb->ops || !sb->ops->unlink) return -1;
    if (vfs_permission_check(&parent, 3) < 0) return -1;
    if (sb->ops->lookup &&
        sb->ops->lookup(sb, &parent, leaf, &victim) == 0) {
        uint32_t euid;
        victim_found = 1;
        /* A directory must reach the filesystem rmdir operation so link counts,
         * dot entries, and parent metadata are updated atomically. */
        if ((victim.mode & 0xF000u) == VFS_INODE_DIR) return -1;
        if ((parent.mode & 01000) &&
            kernel_current_identity(0, &euid, 0) == 0 &&
            euid != 0 && euid != parent.uid && euid != victim.uid)
            return -1;
    }
    /*
     * Keep the inode alive across the namespace mutation and lifetime
     * notification.  A page-cache backend may need to acquire its own orphan
     * reference after the link count reaches zero; without this temporary
     * reference, the filesystem could reclaim the inode inside unlink before
     * the shared lifetime policy can observe it.
     */
    if (victim_found) {
        if (vfs_inode_open(sb, &victim) < 0) return -1;
        victim_pinned = 1;
    }
    {
        int rc = sb->ops->unlink(sb, &parent, leaf);
        if (rc >= 0) {
            if (victim_found)
                vfs_inode_lifetime_orphan_inode(sb, &victim);
            if (victim_pinned) {
                vfs_inode_close(sb, &victim);
                victim_pinned = 0;
            }
            if (vfs_sync_mutation_if_required(sb, 1) < 0) return -1;
            vfs_path_cache_invalidate_all();
        }
        if (victim_pinned) vfs_inode_close(sb, &victim);
        return rc;
    }
}

int vfs_rmdir(const char *path) {
    vfs_inode_t parent;
    vfs_inode_t victim;
    vfs_superblock_t *sb = 0;
    vfs_superblock_t *victim_sb = 0;
    char leaf[VFS_NAME_MAX];
    char parent_path[VFS_PATH_MAX];
    char abs[VFS_PATH_MAX];
    uint32_t euid;
    int rc;

    if (!path || !path[0]) return VFS_PATH_ERR_INVALID;
    normalize_path(path, abs);
    if (strcmp(abs, "/") == 0) return VFS_PATH_ERR_BUSY;
    if (path_split_last(abs, parent_path, leaf) < 0 || !leaf[0])
        return VFS_PATH_ERR_INVALID;
    if (vfs_resolve_nofollow(abs, &victim, &victim_sb) < 0)
        return VFS_PATH_ERR_NOT_FOUND;
    if ((victim.mode & 0xF000u) != VFS_INODE_DIR)
        return VFS_PATH_ERR_NOT_DIRECTORY;
    if (vfs_resolve(parent_path, &parent, &sb, 0, 0) < 0 || !sb)
        return VFS_PATH_ERR_NOT_FOUND;
    if (!vfs_superblock_same_filesystem(sb, victim_sb))
        return VFS_PATH_ERR_CROSS_DEVICE;
    if (!sb->ops || !sb->ops->rmdir) return VFS_PATH_ERR_INVALID;
    if (vfs_permission_check(&parent, 3) < 0)
        return VFS_PATH_ERR_ACCESS;
    if ((parent.mode & 01000) &&
        kernel_current_identity(0, &euid, 0) == 0 &&
        euid != 0 && euid != parent.uid && euid != victim.uid)
        return VFS_PATH_ERR_ACCESS;

    rc = sb->ops->rmdir(sb, &parent, leaf);
    if (rc >= 0) {
        if (vfs_sync_mutation_if_required(sb, 1) < 0)
            return VFS_PATH_ERR_IO;
        vfs_path_cache_invalidate_all();
    }
    return rc;
}

int vfs_rename(const char *old_path, const char *new_path) {
    vfs_inode_t old_parent, new_parent, old_ino, new_ino;
    vfs_superblock_t *old_sb = 0;
    vfs_superblock_t *new_sb = 0;
    char old_leaf[VFS_NAME_MAX], new_leaf[VFS_NAME_MAX];
    char old_parent_path[VFS_PATH_MAX], new_parent_path[VFS_PATH_MAX];
    char old_abs[VFS_PATH_MAX], new_abs[VFS_PATH_MAX];
    uint32_t euid = 0;
    int new_exists;
    int target_pinned = 0;
    int result;

    if (!old_path || !old_path[0] || !new_path || !new_path[0])
        return VFS_PATH_ERR_INVALID;
    normalize_path(old_path, old_abs);
    normalize_path(new_path, new_abs);
    if (strcmp(old_abs, new_abs) == 0) return 0;
    if (strcmp(old_abs, "/") == 0 || strcmp(new_abs, "/") == 0)
        return VFS_PATH_ERR_BUSY;
    if (path_split_last(old_abs, old_parent_path, old_leaf) < 0 ||
        path_split_last(new_abs, new_parent_path, new_leaf) < 0 ||
        !old_leaf[0] || !new_leaf[0])
        return VFS_PATH_ERR_INVALID;
    if (vfs_resolve(old_parent_path, &old_parent, &old_sb, 0, 0) < 0 ||
        !old_sb)
        return VFS_PATH_ERR_NOT_FOUND;
    if (vfs_resolve(new_parent_path, &new_parent, &new_sb, 0, 0) < 0 ||
        !new_sb)
        return VFS_PATH_ERR_NOT_FOUND;
    if (!vfs_superblock_same_filesystem(old_sb, new_sb))
        return VFS_PATH_ERR_CROSS_DEVICE;
    if (!old_sb->ops || !old_sb->ops->lookup || !old_sb->ops->rename)
        return VFS_PATH_ERR_INVALID;
    if (old_sb->ops->lookup(old_sb, &old_parent, old_leaf, &old_ino) < 0)
        return VFS_PATH_ERR_NOT_FOUND;
    if ((old_ino.mode & 0xF000u) == VFS_INODE_DIR &&
        mount_path_is_at_or_below(new_parent_path, old_abs))
        return VFS_PATH_ERR_INVALID;

    new_exists = old_sb->ops->lookup(old_sb, &new_parent, new_leaf,
                                     &new_ino) == 0;
    if (new_exists &&
        vfs_inode_same_object(old_sb, &old_ino, old_sb, &new_ino))
        return 0;
    if (new_exists) {
        uint16_t old_kind = old_ino.mode & 0xF000u;
        uint16_t new_kind = new_ino.mode & 0xF000u;
        if (old_kind == VFS_INODE_DIR && new_kind != VFS_INODE_DIR)
            return VFS_PATH_ERR_NOT_DIRECTORY;
        if (old_kind != VFS_INODE_DIR && new_kind == VFS_INODE_DIR)
            return VFS_PATH_ERR_IS_DIRECTORY;
    }
    if (vfs_permission_check(&old_parent, 3) < 0 ||
        vfs_permission_check(&new_parent, 3) < 0)
        return VFS_PATH_ERR_ACCESS;
    if (kernel_current_identity(0, &euid, 0) == 0 && euid != 0) {
        if ((old_parent.mode & 01000) && euid != old_parent.uid &&
            euid != old_ino.uid)
            return VFS_PATH_ERR_ACCESS;
        if (new_exists && (new_parent.mode & 01000) &&
            euid != new_parent.uid && euid != new_ino.uid)
            return VFS_PATH_ERR_ACCESS;
    }

    if (new_exists) {
        if (vfs_inode_open(old_sb, &new_ino) < 0)
            return VFS_PATH_ERR_IO;
        target_pinned = 1;
    }
    result = old_sb->ops->rename(old_sb, &old_parent, old_leaf,
                                 &new_parent, new_leaf);
    if (result < 0) {
        if (target_pinned) vfs_inode_close(old_sb, &new_ino);
        return result;
    }
    if (new_exists)
        vfs_inode_lifetime_orphan_inode(old_sb, &new_ino);
    if (target_pinned) vfs_inode_close(old_sb, &new_ino);
    vfs_path_cache_invalidate_all();
    if (vfs_sync_mutation_if_required(old_sb, 1) < 0)
        return VFS_PATH_ERR_IO;
    return 0;
}

void vfs_list(const char *path, int longf) {
    vfs_inode_t dir, ino; vfs_superblock_t *sb;
    char abs[VFS_PATH_MAX];
    int is_dev_dir;
    int is_dev_input_dir;
    int is_dev_dri_dir;
    int is_dev_snd_dir;
    int is_sys_class = 0;
    normalize_path(path ? path : g_cwd, abs);
    is_dev_dir = (strcmp(abs, "/dev") == 0);
    is_dev_input_dir = (strcmp(abs, "/dev/input") == 0);
    is_dev_dri_dir = (strcmp(abs, "/dev/dri") == 0);
    is_dev_snd_dir = (strcmp(abs, "/dev/snd") == 0);
    is_sys_class = (strcmp(abs, "/sys") == 0 || strcmp(abs, "/sys/fs") == 0 ||
                    strcmp(abs, "/sys/fs/cgroup") == 0 ||
                    strcmp(abs, "/sys/class") == 0 ||
                    strcmp(abs, "/sys/firmware") == 0 ||
#ifdef CONFIG_ACPI
                    (acpi_available() &&
                     (strcmp(abs, "/sys/firmware/acpi") == 0 ||
                      strcmp(abs, "/sys/firmware/acpi/tables") == 0 ||
                      strcmp(abs, "/sys/firmware/acpi/tables/dynamic") == 0)) ||
#endif
                    strcmp(abs, "/sys/devices") == 0 ||
                    strcmp(abs, "/sys/devices/system") == 0 ||
                    strcmp(abs, "/sys/devices/system/clocksource") == 0 ||
                    strcmp(abs, "/sys/devices/system/clocksource/clocksource0") == 0 ||
                    strcmp(abs, "/sys/block") == 0 ||
                    strcmp(abs, "/sys/class/block") == 0 ||
                    strcmp(abs, "/sys/bus") == 0 ||
                    strcmp(abs, "/sys/bus/pci") == 0 ||
                    strcmp(abs, "/sys/bus/pci/devices") == 0 ||
                    strcmp(abs, "/sys/class/drm") == 0 ||
                    strcmp(abs, "/sys/class/graphics") == 0 ||
                    strcmp(abs, "/sys/class/input") == 0 ||
                    strcmp(abs, "/sys/class/power_supply") == 0 ||
                    strncmp(abs, "/sys/class/power_supply/", 24) == 0 ||
                    strcmp(abs, "/sys/class/rtc") == 0 ||
                    strcmp(abs, "/sys/class/rtc/rtc0") == 0 ||
                    strcmp(abs, "/sys/class/sound") == 0 ||
                    strncmp(abs, "/sys/class/sound/", 17) == 0 ||
                    strcmp(abs, "/sys/class/tty") == 0 ||
                    strncmp(abs, "/sys/class/tty/", 15) == 0);
    if (vfs_resolve(abs, &dir, &sb, 0, 0) < 0) return;
    if (sb && strncmp(sb->mountpoint, "/sys/", 5) == 0) is_sys_class = 0;
    char name[VFS_NAME_MAX];
    if (sb && sb->ops && sb->ops->readdir) {
        for (uint32_t i = 0;; ++i) {
            name[0] = 0;
            name[VFS_NAME_MAX - 1] = 0;
            if (sb->ops->readdir(sb, &dir, i, name, &ino) < 0) break;
            name[VFS_NAME_MAX - 1] = 0;
            if (longf) {
                char t = '-';
                uint16_t mt = (ino.mode & 0xF000);
                if (mt == VFS_INODE_DIR) t = 'd';
                else if (mt == VFS_INODE_BLK) t = 'b';
                else if (mt == VFS_INODE_CHR) t = 'c';
                else if (mt == VFS_INODE_SOCK) t = 's';
                else if (mt == VFS_INODE_FIFO) t = 'p';
                printf("%c%03o %5u %8u %s\n", t, ino.mode & 0777, ino.ino, ino.size, name);
            }
            else printf("%s  ", name);
        }
    }
    if (is_dev_dir) {
        if (longf) printf("d%03o %5u %8u input\n", 0755, 0, 0);
        else printf("input  ");
        if (longf) printf("d%03o %5u %8u dri\n", 0755, 0, 0);
        else printf("dri  ");
        if (alsa_available()) {
            if (longf) printf("d%03o %5u %8u snd\n", 0755, 0, 0);
            else printf("snd  ");
        }
        if (longf) printf("c%03o %5u %8u kmsg\n", 0400, 0, 0);
        else printf("kmsg  ");
        for (int i = 0; i < g_devnode_count; ++i) {
            if (longf) {
                char t = ((g_devnodes[i].mode & 0xF000) == VFS_INODE_BLK) ? 'b' : 'c';
                printf("%c%03o %5u %8u %s\n", t, g_devnodes[i].mode & 0777, 0, 0, g_devnodes[i].name);
            } else {
                printf("%s  ", g_devnodes[i].name);
            }
        }
    }
    if (is_dev_input_dir) {
        int pointer_present = 0;

        for (uint32_t device = 0;
             device < EDGE_INPUT_DEVICE_MAX; ++device)
            if (input_device_role(device) == EDGE_INPUT_ROLE_POINTER)
                pointer_present = 1;
        if (pointer_present) {
            if (longf) {
                printf("c%03o %5u %8u mice\n", 0660, 0, 0);
                printf("c%03o %5u %8u mouse0\n", 0660, 0, 0);
            } else {
                printf("mice  mouse0  ");
            }
        }
        for (uint32_t device = 0;
             device < EDGE_INPUT_DEVICE_MAX; ++device) {
            if (!input_device_present(device)) continue;
            if (longf)
                printf("c%03o %5u %8u event%u\n",
                       0660, 0, 0, device);
            else
                printf("event%u  ", device);
        }
    }
    if (is_dev_snd_dir && alsa_available()) {
        if (longf) {
            printf("c%03o %5u %8u controlC0\n", 0660, 0, 0);
            printf("c%03o %5u %8u pcmC0D0p\n", 0660, 0, 0);
            if (alsa_capture_available())
                printf("c%03o %5u %8u pcmC0D0c\n", 0660, 0, 0);
            printf("c%03o %5u %8u timer\n", 0660, 0, 0);
        } else {
            printf("controlC0  pcmC0D0p  ");
            if (alsa_capture_available()) printf("pcmC0D0c  ");
            printf("timer  ");
        }
    }
    if (is_dev_dri_dir) {
        if (longf) {
            printf("c%03o %5u %8u card0\n", 0660, 0, 0);
            if (edge_drm_path_is_render("/dev/dri/renderD128"))
                printf("c%03o %5u %8u renderD128\n",
                       0660, 0, 0);
        } else {
            printf("card0  ");
            if (edge_drm_path_is_render("/dev/dri/renderD128"))
                printf("renderD128  ");
        }
    }
    if (is_sys_class) {
        const char *names[80];
        char acpi_names[64][16];
        char input_names[EDGE_INPUT_DEVICE_MAX * 2u][16];
        char tty_names[EDGE_FB_VT_COUNT + 1u][8];
        char pci_name[24];
        int n = 0;
        if (strcmp(abs, "/sys") == 0) {
            names[n++] = "class";
            names[n++] = "bus";
            names[n++] = "block";
            names[n++] = "devices";
            names[n++] = "firmware";
            names[n++] = "fs";
        }
        else if (strcmp(abs, "/sys/fs") == 0) names[n++] = "cgroup";
        else if (strcmp(abs, "/sys/fs/cgroup") == 0) {
        }
        else if (strcmp(abs, "/sys/class") == 0) {
            names[n++] = "block";
            names[n++] = "drm";
            names[n++] = "graphics";
            names[n++] = "input";
            names[n++] = "power_supply";
            names[n++] = "rtc";
            if (alsa_available()) names[n++] = "sound";
            names[n++] = "tty";
        } else if (strcmp(abs, "/sys/firmware") == 0) {
#ifdef CONFIG_ACPI
            if (acpi_available()) names[n++] = "acpi";
#endif
        } else if (strcmp(abs, "/sys/firmware/acpi") == 0) {
            names[n++] = "tables";
            names[n++] = "pm_profile";
        } else if (strcmp(abs, "/sys/firmware/acpi/tables") == 0) {
            names[n++] = "dynamic";
#ifdef CONFIG_ACPI
            for (uint32_t idx = 0; n < (int)(sizeof(names) / sizeof(names[0])) &&
                                 idx < (uint32_t)(sizeof(acpi_names) / sizeof(acpi_names[0])) &&
                                 acpi_sysfs_table_name(idx, acpi_names[idx], sizeof(acpi_names[idx])) == 0; ++idx) {
                names[n++] = acpi_names[idx];
            }
#endif
        } else if (strcmp(abs, "/sys/firmware/acpi/tables/dynamic") == 0) {
        } else if (strcmp(abs, "/sys/devices") == 0) {
            names[n++] = "system";
        } else if (strcmp(abs, "/sys/devices/system") == 0) {
            names[n++] = "clocksource";
        } else if (strcmp(abs, "/sys/devices/system/clocksource") == 0) {
            names[n++] = "clocksource0";
        } else if (strcmp(abs, "/sys/devices/system/clocksource/clocksource0") == 0) {
            names[n++] = "available_clocksource";
            names[n++] = "current_clocksource";
        } else if (strcmp(abs, "/sys/bus") == 0) {
            names[n++] = "pci";
        } else if (strcmp(abs, "/sys/bus/pci") == 0) {
            names[n++] = "devices";
        } else if (strcmp(abs, "/sys/class/drm") == 0) {
            names[n++] = "card0";
        } else if (strcmp(abs, "/sys/class/graphics") == 0) {
            names[n++] = "fb0";
        } else if (strcmp(abs, "/sys/class/input") == 0) {
            for (uint32_t device = 0;
                 device < EDGE_INPUT_DEVICE_MAX; ++device) {
                uint32_t length;

                if (!input_device_present(device)) continue;
                length = 0;
                memcpy(input_names[n], "input", 5u);
                length = 5u;
                if (device >= 10u)
                    input_names[n][length++] =
                        (char)('0' + device / 10u);
                input_names[n][length++] =
                    (char)('0' + device % 10u);
                input_names[n][length] = 0;
                names[n] = input_names[n];
                ++n;
                memcpy(input_names[n], "event", 5u);
                length = 5u;
                if (device >= 10u)
                    input_names[n][length++] =
                        (char)('0' + device / 10u);
                input_names[n][length++] =
                    (char)('0' + device % 10u);
                input_names[n][length] = 0;
                names[n] = input_names[n];
                ++n;
            }
        } else if (strcmp(abs, "/sys/class/power_supply") == 0) {
            if (sys_power_supply_node_name("AC")) names[n++] = "AC";
            if (sys_power_supply_node_name("BAT0")) names[n++] = "BAT0";
        } else if (strncmp(abs, "/sys/class/power_supply/", 24) == 0) {
            const char *node = abs + 24;
            if (sys_power_supply_node_name(node)) {
                names[n++] = "type";
                names[n++] = "scope";
                names[n++] = "model_name";
                names[n++] = "manufacturer";
                names[n++] = "uevent";
                if (strcmp(node, "AC") == 0)
                    names[n++] = "online";
                if (strcmp(node, "BAT0") == 0) {
                    struct edge_acpi_battery_info information;
                    static const char *battery_optional[] = {
                        "capacity", "technology", "serial_number",
                        "cycle_count", "voltage_now", "voltage_min_design",
                        "energy_now", "energy_full", "energy_full_design",
                        "charge_now", "charge_full", "charge_full_design",
                        "power_now", "current_now", "time_to_empty_now"
                    };

                    names[n++] = "status";
                    names[n++] = "present";
                    if (acpi_get_battery_info(0, &information) == 0) {
                        for (uint32_t index = 0;
                             index < sizeof(battery_optional) /
                                     sizeof(battery_optional[0]);
                             ++index) {
                            if (sys_power_supply_file_name(
                                    node, battery_optional[index]))
                                names[n++] = battery_optional[index];
                        }
                    }
                }
            }
        } else if (strcmp(abs, "/sys/class/rtc") == 0) {
            names[n++] = "rtc0";
        } else if (strcmp(abs, "/sys/class/rtc/rtc0") == 0) {
            names[n++] = "dev";
            names[n++] = "name";
            names[n++] = "date";
            names[n++] = "time";
            names[n++] = "since_epoch";
            names[n++] = "hctosys";
            names[n++] = "max_user_freq";
            names[n++] = "uevent";
        } else if (strcmp(abs, "/sys/class/sound") == 0) {
            if (alsa_available()) {
                names[n++] = "card0";
                names[n++] = "controlC0";
                names[n++] = "pcmC0D0p";
                if (alsa_capture_available()) names[n++] = "pcmC0D0c";
                names[n++] = "timer";
            }
        } else if (strncmp(abs, "/sys/class/sound/", 17) == 0) {
            const char *node = abs + 17;
            if (strcmp(node, "card0") == 0) {
                names[n++] = "id";
                names[n++] = "number";
                names[n++] = "uevent";
                names[n++] = "subsystem";
            } else {
                names[n++] = "dev";
                names[n++] = "name";
                names[n++] = "uevent";
                names[n++] = "subsystem";
            }
        } else if (strcmp(abs, "/sys/class/tty") == 0) {
            kernel_console_device_t serial;

            names[n++] = "console";
            names[n++] = "tty";
            for (uint32_t vt = 0u; vt <= EDGE_FB_VT_COUNT; ++vt) {
                uint32_t offset = 3u;

                memcpy(tty_names[vt], "tty", 3u);
                if (vt >= 10u)
                    tty_names[vt][offset++] = (char)('0' + vt / 10u);
                tty_names[vt][offset++] = (char)('0' + vt % 10u);
                tty_names[vt][offset] = 0;
                names[n++] = tty_names[vt];
            }
            if (kernel_arch_serial_console_device(&serial) == 0)
                names[n++] = serial.name;
        } else if (strncmp(abs, "/sys/class/tty/", 15) == 0) {
            const char *node = abs + 15;
            names[n++] = "dev";
            names[n++] = "uevent";
            if (strcmp(node, "tty0") == 0 || strcmp(node, "console") == 0) {
                names[n++] = "active";
            }
            names[n++] = "subsystem";
        } else if (strcmp(abs, "/sys/block") == 0) {
            char block_name[BLOCK_NAME_MAX];
            for (uint32_t idx = 0; n < (int)(sizeof(names) / sizeof(names[0])) &&
                                 block_disk_name_by_index(idx, block_name, sizeof(block_name)) == 0; ++idx) {
                if (longf) printf("d%03o %5u %8u %s\n", 0755, 0, 0, block_name);
                else printf("%s  ", block_name);
            }
        } else if (strcmp(abs, "/sys/class/block") == 0) {
            char block_name[BLOCK_NAME_MAX];
            for (uint32_t idx = 0; n < (int)(sizeof(names) / sizeof(names[0])) &&
                                 block_device_name_by_index(idx, block_name, sizeof(block_name)) == 0; ++idx) {
                if (longf) printf("l%03o %5u %8u %s\n", 0777, 0, 0, block_name);
                else printf("%s  ", block_name);
            }
        }
#ifdef CONFIG_PCI
        else if (strcmp(abs, "/sys/bus/pci/devices") == 0) {
            for (uint32_t idx = 0; n < (int)(sizeof(names) / sizeof(names[0])) &&
                                 pci_device_name_by_index(idx, pci_name, sizeof(pci_name)) == 0; ++idx) {
                if (longf) printf("d%03o %5u %8u %s\n", 0755, 0, 0, pci_name);
                else printf("%s  ", pci_name);
            }
        }
#endif
        for (int i = 0; i < n; ++i) {
            if (longf) printf("d%03o %5u %8u %s\n", 0755, 0, 0, names[i]);
            else printf("%s  ", names[i]);
        }
    }
    if (!longf) printf("\n");
}

int vfs_readdir(const char *path, uint32_t idx, char *name_out, vfs_inode_t *inode_out) {
    vfs_inode_t dir;
    vfs_superblock_t *sb;
    if (!path || !name_out || !inode_out) return -1;
    if (vfs_resolve(path, &dir, &sb, 0, 0) < 0) return -1;
    if (!sb || !sb->ops || !sb->ops->readdir) return -1;
    if ((dir.mode & 0xF000u) != VFS_INODE_DIR) return -1;
    return sb->ops->readdir(sb, &dir, idx, name_out, inode_out);
}

int vfs_getcwd(char *buffer, uint32_t capacity) {
    char root[VFS_PATH_MAX];
    uint32_t length;
    if (!buffer || !capacity) return -1;
    if (kernel_current_fs_snapshot(
            buffer, capacity, root, sizeof(root)) == 0) {
        if (!buffer[0]) {
            if (capacity < 2u) return -1;
            buffer[0] = '/';
            buffer[1] = 0;
        }
        return 0;
    }
    length = (uint32_t)strlen(g_cwd);
    if (length >= capacity) return -1;
    memcpy(buffer, g_cwd, length + 1u);
    return 0;
}

int vfs_chdir(const char *path) {
    vfs_inode_t ino;
    char abs[VFS_PATH_MAX];
    normalize_path(path, abs);
    if (vfs_resolve(abs, &ino, 0, 0, 0) < 0 || (ino.mode & 0xF000u) != VFS_INODE_DIR) return -1;
    if (vfs_permission_check(&ino, 1) < 0) return -1;
    return kernel_current_fs_set_cwd(abs) < 0 ? -1 : 0;
}

int vfs_chroot(const char *path) {
    vfs_inode_t ino;
    char abs[VFS_PATH_MAX];
    if (!path) return -1;
    normalize_path(path, abs);
    if (vfs_resolve(abs, &ino, 0, 0, 0) < 0 || (ino.mode & 0xF000u) != VFS_INODE_DIR) return -1;
    if (vfs_permission_check(&ino, 1) < 0) return -1;
    return kernel_current_fs_set_root(abs) < 0 ? -1 : 0;
}

void vfs_list_mounts(void) {
    for (int i = 0; i < g_mount_count; ++i) printf("%s on %s type %s\n", g_mount_at(i).dev_name, g_mount_at(i).mountpoint, g_mount_at(i).fs_name);
}

int vfs_statfs_path(const char *path, uint32_t *total_kb, uint32_t *used_kb) {
    vfs_superblock_t *sb = 0;
    char cwd[VFS_PATH_MAX];
    const char *resolved_path = path;
    if (!resolved_path || !resolved_path[0]) {
        if (vfs_getcwd(cwd, sizeof(cwd)) < 0) return -1;
        resolved_path = cwd;
    }
    if (vfs_resolve(resolved_path, 0, &sb, 0, 0) < 0) return -1;
    if (!sb || !sb->ops || !sb->ops->statfs) return -1;
    return sb->ops->statfs(sb, total_kb, used_kb);
}

int vfs_has_mounts(void) {
    return g_mount_count > 0;
}

int vfs_inode_get_block_device(const vfs_inode_t *inode, block_device_t **out) {
    if (!inode || !out) return -1;
    if ((inode->mode & 0xF000) != VFS_INODE_BLK) return -1;
    *out = (block_device_t *)vfs_inode_get_ptr(inode);
    if (!*out && inode->rdev)
        *out = block_find_linux_device(inode->rdev);
    return *out ? 0 : -1;
}

int vfs_inode_is_dir(const vfs_inode_t *inode) {
    return inode && ((inode->mode & 0xF000u) == VFS_INODE_DIR);
}

int vfs_dev_ioctl(const char *path, uint32_t cmd, void *arg) {
    vfs_inode_t ino;
    int idx;
    static int fbio_vfs_trace_budget = 0;
    if (!path) return -EINVAL;
    if (cmd == LINUX_FBIOGET_FSCREENINFO || cmd == LINUX_FBIOGET_VSCREENINFO ||
        cmd == LINUX_FBIOPUT_VSCREENINFO || cmd == LINUX_FBIOPAN_DISPLAY) {
        if (fbio_vfs_trace_budget-- > 0) {
            printf("[fbio-vfs] path=%s cmd=0x%x enter budget=%d\n",
                   path, cmd, fbio_vfs_trace_budget);
        }
    }
    if (alsa_path_kind(path) != EDGE_ALSA_NODE_NONE) return alsa_ioctl_kernel(path, cmd, arg);
    if (uvc_path_kind(path)) return uvc_ioctl_kernel(path, cmd, arg);
    if (vfs_resolve(path, &ino, 0, 0, 0) < 0) {
        if ((cmd == LINUX_FBIOGET_FSCREENINFO || cmd == LINUX_FBIOGET_VSCREENINFO ||
             cmd == LINUX_FBIOPUT_VSCREENINFO || cmd == LINUX_FBIOPAN_DISPLAY) &&
            fbio_vfs_trace_budget > 0) {
            printf("[fbio-vfs] path=%s cmd=0x%x resolve=EINVAL\n", path, cmd);
        }
        return -EINVAL;
    }
    if ((ino.mode & 0xF000) != VFS_INODE_CHR) {
        if ((cmd == LINUX_FBIOGET_FSCREENINFO || cmd == LINUX_FBIOGET_VSCREENINFO ||
             cmd == LINUX_FBIOPUT_VSCREENINFO || cmd == LINUX_FBIOPAN_DISPLAY) &&
            fbio_vfs_trace_budget > 0) {
            printf("[fbio-vfs] path=%s cmd=0x%x mode=0x%x not-chr\n", path, cmd, ino.mode);
        }
        return -EINVAL;
    }
    idx = vfs_devnode_from_inode(&ino);
    if (idx < 0) {
        if ((cmd == LINUX_FBIOGET_FSCREENINFO || cmd == LINUX_FBIOGET_VSCREENINFO ||
             cmd == LINUX_FBIOPUT_VSCREENINFO || cmd == LINUX_FBIOPAN_DISPLAY) &&
            fbio_vfs_trace_budget > 0) {
            printf("[fbio-vfs] path=%s cmd=0x%x ino=0x%x no-devnode\n", path, cmd, ino.ino);
        }
        return -EINVAL;
    }

    if (g_devnodes[idx].kind == DEV_KIND_FB0) {
        struct edge_fb_var_screeninfo var;
        if (cmd == FB_IOCTL_GET_INFO_LEGACY) {
            if (!arg) return -EINVAL;
            ((struct fb_info *)arg)->width = fb.width;
            ((struct fb_info *)arg)->height = fb.height;
            ((struct fb_info *)arg)->pitch = fb.pitch;
            ((struct fb_info *)arg)->bpp = fb.bpp;
            return 0;
        }
        if (cmd == LINUX_FBIOGET_FSCREENINFO) {
            struct edge_fb_fix_screeninfo fix;
            uint64_t phys_base = 0;
            uint64_t phys_off = 0;
            uint32_t phys_pages = 0;
            if (!arg) return -EINVAL;
            memset(&fix, 0, sizeof(fix));
            strcpy(fix.id, "EdgeOS fb0");
            if (fb_get_2m_phys_window(&phys_base, &phys_pages, &phys_off)) {
                (void)phys_pages;
                /*
                 * Linux fb_fix_screeninfo.smem_start reports the framebuffer
                 * start address, not a synthetic mmap return value.  Xorg's
                 * fbdev helper uses this for aperture offset calculations and
                 * may compare it with the mapped range.  EdgeOS maps exactly
                 * these fbdev backing PDEs user-accessible in process.c, so
                 * keep the externally visible ABI Linux-style here.
                 *
                 * Red flag: do not encode Xorg or rootfs policy here.  The
                 * mmap path still returns a safe Linux-visible alias when
                 * callers use mmap(2); smem_start remains the fbdev backing
                 * address used for normal Linux offset math.
                 */
                fix.smem_start = phys_base + phys_off;
            } else {
                fix.smem_start = (uint64_t)(uintptr_t)fb.addr;
            }
            fix.smem_len = fb.pitch * fb.height;
            fix.type = 0;   /* FB_TYPE_PACKED_PIXELS */
            fix.visual = 2; /* FB_VISUAL_TRUECOLOR */
            fix.line_length = fb.pitch;
            return memcpy(arg, &fix, sizeof(fix)), 0;
        }
        if (cmd == LINUX_FBIOGET_VSCREENINFO) {
            if (!arg) return -EINVAL;
            memset(&var, 0, sizeof(var));
            var.xres = fb.width;
            var.yres = fb.height;
            var.xres_virtual = fb.width;
            var.yres_virtual = fb.height;
            var.bits_per_pixel = fb.bpp;
            var.red.offset = fb.r_pos;
            var.green.offset = fb.g_pos;
            var.blue.offset = fb.b_pos;
            var.red.length = 8;
            var.green.length = 8;
            var.blue.length = 8;
            var.transp.offset = 24;
            var.transp.length = (fb.bpp == 32) ? 8u : 0u;
            /*
             * Linux fb_var_screeninfo width/height are physical dimensions in
             * millimeters.  Returning UINT_MAX as "unknown" looks harmless to
             * simple fbdev clients, but Xorg can propagate it as the screen's
             * physical size and GTK/GDK then computes native windows larger
             * than 32767 pixels.  Provide a conservative 96-DPI equivalent
             * instead.  Red flag: this is display geometry, not an Alpine/XFCE
             * special case; keep it tied to the active framebuffer mode.
             */
            var.width = (fb.width * 254u + 480u) / 960u;
            var.height = (fb.height * 254u + 480u) / 960u;
            if (var.width == 0) var.width = 1;
            if (var.height == 0) var.height = 1;
            return memcpy(arg, &var, sizeof(var)), 0;
        }
        if (cmd == LINUX_FBIOGETCMAP || cmd == LINUX_FBIOPUTCMAP) {
            /*
             * The EdgeOS framebuffer is true-color, so Xorg's fbdev palette
             * save/restore calls do not need hardware work.  Linux true-color
             * fbdev drivers commonly accept these operations as no-ops.
             */
            return 0;
        }
        if (cmd == LINUX_FBIOPUT_VSCREENINFO || cmd == LINUX_FBIOPAN_DISPLAY) {
            if (!arg) return -EINVAL;
            memcpy(&var, arg, sizeof(var));
            if (var.xres != fb.width || var.yres != fb.height) return -EINVAL;
            if (var.bits_per_pixel != fb.bpp) return -EINVAL;
            if (var.xres_virtual < var.xres || var.yres_virtual < var.yres) return -EINVAL;
            if (var.xoffset > (var.xres_virtual - var.xres)) return -EINVAL;
            if (var.yoffset > (var.yres_virtual - var.yres)) return -EINVAL;
            return 0;
        }
        if (cmd == LINUX_FBIOBLANK) {
            /*
             * Linux FBIOBLANK takes the blanking mode as the ioctl argument
             * value, not as a pointer.  Valid callers pass 0 for unblank and
             * 1..4 for normal/VSYNC/HSYNC/powerdown blanking.  The virtio-gpu
             * fbdev path has no DPMS state to program, but rejecting arg == 0
             * is an ABI bug: Xorg uses it while restoring the screen and treats
             * EINVAL as a real fbdev failure.
             */
            if ((uint64_t)(uintptr_t)arg > 4u) return -EINVAL;
            return 0;
        }
        return -ENOSYS;
    }
    return -ENOSYS;
}

int vfs_dev_mmap(const char *path, uint64_t req_len, uint64_t off,
                 uint64_t selected_addr, uint64_t *addr_out, uint64_t *len_out) {
    vfs_inode_t ino;
    int idx;
    const uint64_t page_mask = 4095ULL;
    if (!path || !addr_out) return -EINVAL;
    if (vfs_resolve(path, &ino, 0, 0, 0) < 0) return -EINVAL;
    if ((ino.mode & 0xF000) != VFS_INODE_CHR) return -EINVAL;
    idx = vfs_devnode_from_inode(&ino);
    if (idx < 0) return -EINVAL;
    if (g_devnodes[idx].kind != DEV_KIND_FB0) return -ENOSYS;
    if (!fb.addr || fb.pitch == 0 || fb.height == 0) return -1;
    {
        uint64_t phys_base = 0, phys_off = 0;
        uint64_t page_off;
        uint64_t aperture_off;
        uint64_t map_len;
        uint32_t pages = 0;
        if (fb_get_2m_phys_window(&phys_base, &pages, &phys_off)) {
            (void)phys_base;
            if (pages > 0 && pages <= EDGE_FBDEV_USER_MAX_PAGES) {
                /*
                 * Linux fbdev mmap starts at the page containing smem_start.
                 * Callers such as Xorg add (smem_start & PAGE_MASK) via
                 * fbdevHWLinearOffset(), so the returned userspace mapping
                 * must be page-aligned instead of already adjusted to fb.addr.
                 */
                page_off = phys_off & page_mask;
                aperture_off = phys_off & ~page_mask;
                map_len = ((page_off + (uint64_t)fb.pitch * (uint64_t)fb.height + page_mask) & ~page_mask);
                if (off > map_len || req_len > map_len - off) return -EINVAL;
                /*
                 * Linux fbdev mmap returns the VMA address selected by the
                 * normal mmap allocator.  smem_start remains physical metadata
                 * used by clients to compute the low page offset; it is not a
                 * magic userspace VA.  EdgeOS maps the real framebuffer pages
                 * lazily from process.c, so keep the externally visible address
                 * as the caller-selected VMA base instead of forcing every
                 * process through a fixed alias.
                 */
                (void)aperture_off;
                *addr_out = selected_addr;
                if (len_out) *len_out = map_len;
                fb_note_user_mmap();
                return 0;
            }
        }
    }
    if (off > (uint64_t)fb.pitch * (uint64_t)fb.height ||
        req_len > (uint64_t)fb.pitch * (uint64_t)fb.height - off) {
        return -EINVAL;
    }
    *addr_out = selected_addr;
    if (len_out) *len_out = (uint64_t)fb.pitch * (uint64_t)fb.height;
    fb_note_user_mmap();
    return 0;
}

int vfs_dev_pwrite(const char *path, const char *buf, uint32_t len, uint64_t off) {
    vfs_inode_t ino;
    int idx;
    if (!path || (!buf && len)) return -EINVAL;
    if (alsa_path_kind(path) != EDGE_ALSA_NODE_NONE) {
        /*
         * Linux PCM character devices are stream endpoints.  The file offset
         * maintained by write(2) is not a seek position into device memory, so
         * multi-chunk VFS writes must keep feeding the backend instead of
         * rejecting the second chunk with EINVAL.
         */
        (void)off;
        return alsa_write(path, buf, len);
    }
    if (vfs_resolve(path, &ino, 0, 0, 0) < 0) return -EINVAL;
    if ((ino.mode & 0xF000) != VFS_INODE_CHR) return -EINVAL;
    {
        int result = edge_memdev_write(ino.rdev, buf, len);
        if (result != EDGE_MEMDEV_NOT_HANDLED) return result;
    }
    idx = vfs_devnode_from_inode(&ino);
    if (idx < 0) return -EINVAL;
    if (g_devnodes[idx].kind == DEV_KIND_FB0) {
        uint32_t fb_bytes;
        uint32_t n;
        uint8_t *dst;
        uint32_t bpp_bytes;
        uint32_t first_row;
        uint32_t last_row;
        uint32_t first_col;
        uint32_t last_col;
        if (!fb.addr || fb.pitch == 0 || fb.height == 0) return -1;
        fb_bytes = fb.pitch * fb.height;
        if (off >= fb_bytes) return 0;
        n = len;
        if (off + n < off || off + n > fb_bytes) n = (uint32_t)(fb_bytes - off);
        /*
         * /dev/fb0 is device memory, not the kernel text-console backing
         * store.  Once a Linux fbdev client has mmap'd the framebuffer, writes
         * to /dev/fb0 must update the same visible aperture that mmap users
         * see.  Red flag: do not route fbdev writes through fb_backbuffer while
         * Xorg/fbdev owns the display; doing so makes diagnostic fills visible
         * but leaves the actual mmap scanout path stale.
         */
        dst = fb_user_mmap_active() ? fb.addr : fb_get_draw_buffer();
        if (!dst) dst = fb.addr;
        if (n) memcpy(dst + (uint32_t)off, buf, n);
        if (dst != fb.addr) {
            fb_present();
        } else if (n) {
            bpp_bytes = (fb.bpp + 7u) / 8u;
            if (bpp_bytes == 0) bpp_bytes = 1;
            first_row = (uint32_t)off / fb.pitch;
            last_row = (uint32_t)(off + n - 1u) / fb.pitch;
            first_col = ((uint32_t)off % fb.pitch) / bpp_bytes;
            last_col = ((uint32_t)(off + n - 1u) % fb.pitch) / bpp_bytes;
            if (first_row >= fb.height) first_row = fb.height - 1u;
            if (last_row >= fb.height) last_row = fb.height - 1u;
            /*
             * Byte ranges can start/end mid-row; flushing the whole covered row
             * span is simple and still bounded.  The periodic mmap scanner will
             * catch later mmap-only writes.
             */
            if (last_row > first_row) {
                first_col = 0;
                last_col = fb.width ? fb.width - 1u : 0;
            } else {
                if (first_col >= fb.width) first_col = fb.width - 1u;
                if (last_col >= fb.width) last_col = fb.width - 1u;
                if (last_col < first_col) last_col = first_col;
            }
            if (fb_user_mmap_active()) {
                /*
                 * Linux fbdev writes target the same scanout memory that mmap
                 * users see.  Under virtio-gpu, coalesce those writes into the
                 * normal fbdev mmap pump instead of blocking each write on a
                 * synchronous transfer.  Real clients commonly write one row at
                 * a time; flushing every row makes the desktop unresponsive.
                 */
                fb_note_user_mmap_dirty((uint32_t)off, n);
            } else {
                fb_flush_rect((int)first_col, (int)first_row,
                              (int)(last_col - first_col + 1u),
                              (int)(last_row - first_row + 1u));
            }
        }
        return (int)n;
    }
    /* Fallback to legacy device write semantics for other char devices. */
    return vfs_write_file(path, buf, len);
}

int vfs_chmod(const char *path, uint16_t mode) {
    vfs_inode_t ino;
    vfs_superblock_t *sb = 0;
    int rc;
    char abs[VFS_PATH_MAX];
    if (!path) return -EINVAL;
    normalize_path(path, abs);
    if (vfs_resolve(abs, &ino, &sb, 0, 0) < 0) return -1;
    rc = vfs_inode_chmod(sb, &ino, mode);
    if (rc >= 0) edge_inotify_notify_path(abs, EDGE_IN_ATTRIB, 0);
    return rc;
}

static int vfs_chown_common(const char *path, uint32_t uid, uint32_t gid,
                            int follow_final_symlink) {
    vfs_inode_t ino;
    vfs_superblock_t *sb = 0;
    int rc;
    char abs[VFS_PATH_MAX];
    if (!path) return -EINVAL;
    normalize_path(path, abs);
    if (follow_final_symlink) {
        if (vfs_resolve(abs, &ino, &sb, 0, 0) < 0) return -1;
    } else {
        if (vfs_resolve_nofollow(abs, &ino, &sb) < 0) return -1;
    }
    rc = vfs_inode_chown(sb, &ino, uid, gid,
                         VFS_SETATTR_UID | VFS_SETATTR_GID);
    if (rc >= 0) edge_inotify_notify_path(abs, EDGE_IN_ATTRIB, 0);
    return rc;
}

int vfs_chown(const char *path, uint32_t uid, uint32_t gid) {
    return vfs_chown_common(path, uid, gid, 1);
}

int vfs_lchown(const char *path, uint32_t uid, uint32_t gid) {
    return vfs_chown_common(path, uid, gid, 0);
}

int vfs_utimens(const char *path, uint32_t atime, uint32_t mtime, int set_atime, int set_mtime) {
    vfs_inode_t ino;
    vfs_superblock_t *sb = 0;
    int rc;
    char abs[VFS_PATH_MAX];
    if (!path) return -EINVAL;
    if (!set_atime && !set_mtime) return 0;
    normalize_path(path, abs);
    if (vfs_resolve(abs, &ino, &sb, 0, 0) < 0) return -1;
    rc = vfs_inode_utimens(sb, &ino, atime, mtime,
                           set_atime, set_mtime);
    if (rc >= 0) edge_inotify_notify_path(abs, EDGE_IN_ATTRIB, 0);
    return rc;
}
