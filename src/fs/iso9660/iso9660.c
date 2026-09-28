/*
 * EdgeOS ISO9660 filesystem support.
 *
 * Copyright (c) EdgeOS Contributors.
 * Licensed under the Mozilla Public License, v. 2.0.
 */
#include "iso9660/iso9660.h"
#include "vfs/vfs.h"
#include "block/block.h"
#include "stdio.h"
#include "string.h"

#define ISO_SECTOR_SIZE 2048u
#define ISO_PVD_SECTOR 16u
#define ISO_STD_ID "CD001"
#define ISO_MAX_MOUNTS 4
#define ISO_ROOT_RECORD_OFF 156u
#define ISO_FLAG_DIR 0x02u

typedef struct {
    block_device_t *bdev;
    uint32_t volume_blocks;
    uint32_t root_extent;
    uint32_t root_size;
    uint8_t scratch[ISO_SECTOR_SIZE];
} iso9660_fs_t;

typedef struct {
    uint8_t len;
    uint8_t ext_attr_len;
    uint32_t extent;
    uint32_t size;
    uint8_t flags;
    uint8_t name_len;
    const uint8_t *name;
} iso_dirent_t;

static iso9660_fs_t g_iso_mounts[ISO_MAX_MOUNTS];
static int g_iso_mount_count;

static uint16_t iso_le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t iso_le32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint16_t iso_mode_from_flags(uint8_t flags) {
    return ((flags & ISO_FLAG_DIR) ? VFS_INODE_DIR : VFS_INODE_FILE) | 0555u;
}

static uint32_t iso_inode_number(uint32_t extent, uint32_t size, uint8_t flags) {
    uint32_t h = extent ^ (size << 7) ^ ((uint32_t)flags << 24);
    if (h < 2u) h += 2u;
    return h;
}

static void iso_fill_inode(uint32_t extent, uint32_t size, uint8_t flags, vfs_inode_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->ino = iso_inode_number(extent, size, flags);
    out->mode = iso_mode_from_flags(flags);
    out->uid = 0;
    out->gid = 0;
    out->size = size;
    out->fs_private[0] = extent;
    out->fs_private[1] = size;
    out->fs_private[2] = flags;
}

static int iso_read_sectors(iso9660_fs_t *fs, uint32_t iso_lba, uint32_t count, void *out) {
    uint32_t sectors_per_iso;
    uint32_t dev_lba;
    uint32_t dev_count;
    if (!fs || !fs->bdev || !out || fs->bdev->sector_size == 0) return -1;
    if (ISO_SECTOR_SIZE % fs->bdev->sector_size != 0) return -1;
    sectors_per_iso = ISO_SECTOR_SIZE / fs->bdev->sector_size;
    dev_lba = iso_lba * sectors_per_iso;
    dev_count = count * sectors_per_iso;
    if (dev_count == 0) return -1;
    return block_read_sectors(fs->bdev, dev_lba, dev_count, out);
}

static int iso_read_bytes(iso9660_fs_t *fs, uint32_t byte_off, void *buf, uint32_t len) {
    uint8_t *dst = (uint8_t *)buf;
    uint32_t done = 0;
    if (!fs || !buf) return -1;
    while (done < len) {
        uint32_t pos = byte_off + done;
        uint32_t lba = pos / ISO_SECTOR_SIZE;
        uint32_t in_sector = pos % ISO_SECTOR_SIZE;
        uint32_t chunk = ISO_SECTOR_SIZE - in_sector;
        if (chunk > len - done) chunk = len - done;
        if (iso_read_sectors(fs, lba, 1, fs->scratch) < 0) return -1;
        memcpy(dst + done, fs->scratch + in_sector, chunk);
        done += chunk;
    }
    return (int)done;
}

static int iso_parse_dirent(const uint8_t *p, uint32_t remain, iso_dirent_t *out) {
    uint8_t len;
    uint8_t name_len;
    if (!p || !out || remain < 1) return -1;
    len = p[0];
    if (len == 0) return 0;
    if (len < 34u || len > remain) return -1;
    name_len = p[32];
    if ((uint32_t)33u + name_len > len) return -1;
    memset(out, 0, sizeof(*out));
    out->len = len;
    out->ext_attr_len = p[1];
    out->extent = iso_le32(p + 2);
    out->size = iso_le32(p + 10);
    out->flags = p[25];
    out->name_len = name_len;
    out->name = p + 33;
    return 1;
}

static int iso_char_fold(int c) {
    if (c >= 'a' && c <= 'z') return c - ('a' - 'A');
    return c;
}

static uint8_t iso_visible_name_len(const uint8_t *name, uint8_t len) {
    uint8_t out = len;
    for (uint8_t i = 0; i < len; ++i) {
        if (name[i] == ';') {
            out = i;
            break;
        }
    }
    if (out > 0 && name[out - 1u] == '.') out--;
    return out;
}

static int iso_name_eq(const uint8_t *iso_name, uint8_t iso_len, const char *want) {
    uint8_t visible;
    if (!iso_name || !want) return 0;
    if (iso_len == 1u && iso_name[0] < 2u) return 0;
    visible = iso_visible_name_len(iso_name, iso_len);
    if ((uint32_t)visible != strlen(want)) return 0;
    for (uint8_t i = 0; i < visible; ++i) {
        if (iso_char_fold(iso_name[i]) != iso_char_fold((uint8_t)want[i])) return 0;
    }
    return 1;
}

static void iso_name_copy(const uint8_t *iso_name, uint8_t iso_len, char *out) {
    uint8_t visible = iso_visible_name_len(iso_name, iso_len);
    if (!out) return;
    if (iso_len == 1u && iso_name[0] == 0) {
        strcpy(out, ".");
        return;
    }
    if (iso_len == 1u && iso_name[0] == 1) {
        strcpy(out, "..");
        return;
    }
    if (visible >= VFS_NAME_MAX) visible = VFS_NAME_MAX - 1;
    for (uint8_t i = 0; i < visible; ++i) out[i] = (char)iso_name[i];
    out[visible] = 0;
}

static int iso_dir_iter(iso9660_fs_t *fs, const vfs_inode_t *dir, uint32_t want_idx,
                        const char *want_name, iso_dirent_t *found, char *name_out) {
    uint32_t extent;
    uint32_t size;
    uint32_t off = 0;
    uint32_t idx = 0;
    if (!fs || !dir || ((dir->mode & 0xF000u) != VFS_INODE_DIR)) return -1;
    extent = dir->fs_private[0];
    size = dir->fs_private[1];
    while (off < size) {
        uint32_t abs = extent * ISO_SECTOR_SIZE + off;
        uint32_t sector_off = abs % ISO_SECTOR_SIZE;
        uint32_t remain = ISO_SECTOR_SIZE - sector_off;
        iso_dirent_t de;
        int rc;
        if (remain > size - off) remain = size - off;
        if (iso_read_bytes(fs, abs, fs->scratch, remain) < 0) return -1;
        rc = iso_parse_dirent(fs->scratch, remain, &de);
        if (rc < 0) return -1;
        if (rc == 0) {
            off += remain;
            continue;
        }
        if (de.name_len == 1u && de.name[0] < 2u) {
            off += de.len;
            continue;
        }
        if (want_name) {
            if (iso_name_eq(de.name, de.name_len, want_name)) {
                if (found) *found = de;
                return 0;
            }
        } else if (idx == want_idx) {
            if (found) *found = de;
            if (name_out) iso_name_copy(de.name, de.name_len, name_out);
            return 0;
        }
        idx++;
        off += de.len;
    }
    return -1;
}

static int iso_lookup(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    iso9660_fs_t *fs = sb ? (iso9660_fs_t *)sb->fs_private : 0;
    iso_dirent_t de;
    if (!fs || !dir || !name || !out) return -1;
    if (strcmp(name, ".") == 0) {
        *out = *dir;
        return 0;
    }
    if (iso_dir_iter(fs, dir, 0, name, &de, 0) < 0) return -1;
    iso_fill_inode(de.extent, de.size, de.flags, out);
    return 0;
}

static int iso_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    iso9660_fs_t *fs = sb ? (iso9660_fs_t *)sb->fs_private : 0;
    uint32_t size;
    uint32_t extent;
    if (!fs || !inode || !buf) return -1;
    if ((inode->mode & 0xF000u) != VFS_INODE_FILE) return -1;
    size = inode->fs_private[1];
    extent = inode->fs_private[0];
    if (off >= size) return 0;
    if (len > size - off) len = size - off;
    if (len == 0) return 0;
    return iso_read_bytes(fs, extent * ISO_SECTOR_SIZE + off, buf, len);
}

static int iso_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx, char *name_out, vfs_inode_t *inode_out) {
    iso9660_fs_t *fs = sb ? (iso9660_fs_t *)sb->fs_private : 0;
    iso_dirent_t de;
    if (!fs || !dir || !name_out || !inode_out) return -1;
    if (iso_dir_iter(fs, dir, idx, 0, &de, name_out) < 0) return -1;
    iso_fill_inode(de.extent, de.size, de.flags, inode_out);
    return 0;
}

static int iso_statfs(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) {
    iso9660_fs_t *fs = sb ? (iso9660_fs_t *)sb->fs_private : 0;
    uint32_t kb;
    if (!fs || !total_kb || !used_kb) return -1;
    kb = (fs->volume_blocks * ISO_SECTOR_SIZE) / 1024u;
    *total_kb = kb;
    *used_kb = kb;
    return 0;
}

static filesystem_ops_t g_iso_ops = {
    .lookup = iso_lookup,
    .read = iso_read,
    .readdir = iso_readdir,
    .statfs = iso_statfs,
};

static int iso_mount_common(block_device_t *bdev, const char *dev, const char *target) {
    iso9660_fs_t *fs;
    vfs_superblock_t sb;
    uint8_t *pvd;
    iso_dirent_t root;
    if (!bdev || !target) return -1;
    if (g_iso_mount_count >= ISO_MAX_MOUNTS) return -1;
    fs = &g_iso_mounts[g_iso_mount_count];
    memset(fs, 0, sizeof(*fs));
    fs->bdev = bdev;
    if (iso_read_sectors(fs, ISO_PVD_SECTOR, 1, fs->scratch) < 0) return -1;
    pvd = fs->scratch;
    if (pvd[0] != 1u || memcmp(pvd + 1, ISO_STD_ID, 5) != 0 || pvd[6] != 1u) {
        printf("[iso9660] invalid primary volume descriptor on %s\n", dev ? dev : bdev->name);
        return -1;
    }
    fs->volume_blocks = iso_le32(pvd + 80);
    if (iso_le16(pvd + 128) != ISO_SECTOR_SIZE) {
        printf("[iso9660] unsupported logical block size %u on %s\n",
               (uint32_t)iso_le16(pvd + 128), dev ? dev : bdev->name);
        return -1;
    }
    if (iso_parse_dirent(pvd + ISO_ROOT_RECORD_OFF, ISO_SECTOR_SIZE - ISO_ROOT_RECORD_OFF, &root) <= 0) return -1;
    if ((root.flags & ISO_FLAG_DIR) == 0) return -1;
    fs->root_extent = root.extent;
    fs->root_size = root.size;

    memset(&sb, 0, sizeof(sb));
    strcpy(sb.fs_name, "iso9660");
    strncpy(sb.dev_name, dev ? dev : bdev->name, sizeof(sb.dev_name) - 1);
    strncpy(sb.mountpoint, target, sizeof(sb.mountpoint) - 1);
    iso_fill_inode(root.extent, root.size, root.flags, &sb.root);
    sb.ops = &g_iso_ops;
    sb.fs_private = fs;
    if (vfs_add_superblock(&sb) < 0) return -1;
    g_iso_mount_count++;
    printf("[iso9660] mounted %s on %s blocks=%u\n", sb.dev_name, target, fs->volume_blocks);
    return 0;
}

int iso9660_mount(const char *dev, const char *target) {
    block_device_t *b;
    if (!dev || !target) return -1;
    b = block_find(dev[0] == '/' ? dev + 5 : dev);
    if (!b) return -1;
    return iso_mount_common(b, dev, target);
}

int iso9660_mount_block(block_device_t *bdev, const char *target) {
    if (!bdev) return -1;
    return iso_mount_common(bdev, bdev->name, target);
}
