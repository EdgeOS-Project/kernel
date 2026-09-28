/*
 * EdgeOS exFAT filesystem support.
 *
 * Copyright (c) EdgeOS Contributors.
 * Licensed under the Mozilla Public License, v. 2.0.
 */
#include "exfat/exfat.h"
#include "vfs/vfs.h"
#include "block/block.h"
#include "stdio.h"
#include "string.h"

#define EXFAT_MAX_MOUNTS 4u
#define EXFAT_SIGNATURE "EXFAT   "
#define EXFAT_ENTRY_EOD 0x00u
#define EXFAT_ENTRY_FILE 0x85u
#define EXFAT_ENTRY_STREAM 0xC0u
#define EXFAT_ENTRY_NAME 0xC1u
#define EXFAT_ATTR_DIRECTORY 0x10u
#define EXFAT_FAT_EOC 0xFFFFFFF8u
#define EXFAT_STREAM_NO_FAT_CHAIN 0x02u

typedef struct {
    block_device_t *bdev;
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t fat_offset;
    uint32_t fat_length;
    uint32_t cluster_heap_offset;
    uint32_t cluster_count;
    uint32_t root_cluster;
    uint8_t scratch[4096];
} exfat_fs_t;

typedef struct {
    uint32_t first_cluster;
    uint64_t size;
    uint8_t attr;
    uint8_t flags;
    char name[VFS_NAME_MAX];
} exfat_dirent_t;

typedef struct {
    uint32_t first_cluster;
    uint64_t size;
    uint8_t attr;
    uint8_t flags;
} exfat_node_t;

static exfat_fs_t g_exfat_mounts[EXFAT_MAX_MOUNTS];
static uint32_t g_exfat_mount_count;

static uint16_t exfat_le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t exfat_le32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t exfat_le64(const uint8_t *p) {
    return (uint64_t)exfat_le32(p) | ((uint64_t)exfat_le32(p + 4) << 32);
}

static int exfat_valid_cluster(const exfat_fs_t *fs, uint32_t cluster) {
    return fs && cluster >= 2u && cluster < fs->cluster_count + 2u;
}

static uint32_t exfat_cluster_lba(const exfat_fs_t *fs, uint32_t cluster) {
    return fs->cluster_heap_offset + (cluster - 2u) * fs->sectors_per_cluster;
}

static int exfat_read_sectors(exfat_fs_t *fs, uint32_t lba, uint32_t count, void *out) {
    if (!fs || !fs->bdev || !out || count == 0) return -1;
    if (fs->bdev->sector_size != fs->bytes_per_sector) return -1;
    return block_read_sectors(fs->bdev, lba, count, out);
}

static int exfat_read_sector(exfat_fs_t *fs, uint32_t lba, void *out) {
    return exfat_read_sectors(fs, lba, 1, out);
}

static int exfat_next_cluster(exfat_fs_t *fs, uint32_t cluster, uint32_t *next_out) {
    uint32_t fat_byte;
    uint32_t sector;
    uint32_t off;

    if (!fs || !next_out || !exfat_valid_cluster(fs, cluster)) return -1;
    fat_byte = cluster * 4u;
    sector = fs->fat_offset + fat_byte / fs->bytes_per_sector;
    off = fat_byte % fs->bytes_per_sector;
    if (off + 4u > sizeof(fs->scratch)) return -1;
    if (exfat_read_sector(fs, sector, fs->scratch) < 0) return -1;
    *next_out = exfat_le32(fs->scratch + off);
    return 0;
}

static int exfat_name_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + ('a' - 'A'));
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static void exfat_name_append(exfat_dirent_t *de, const uint8_t *entry) {
    uint32_t pos;
    if (!de || !entry) return;
    pos = (uint32_t)strlen(de->name);
    for (uint32_t i = 0; i < 15u && pos + 1u < VFS_NAME_MAX; ++i) {
        uint16_t ch = exfat_le16(entry + 2u + i * 2u);
        if (ch == 0x0000u || ch == 0xFFFFu) break;
        de->name[pos++] = (ch < 0x80u) ? (char)ch : '?';
    }
    de->name[pos] = 0;
}

static void exfat_fill_inode(const exfat_node_t *node, vfs_inode_t *out) {
    uint16_t kind;
    if (!node || !out) return;
    memset(out, 0, sizeof(*out));
    kind = (node->attr & EXFAT_ATTR_DIRECTORY) ? VFS_INODE_DIR : VFS_INODE_FILE;
    out->ino = node->first_cluster ? node->first_cluster : 2u;
    out->mode = kind | 0555u;
    out->uid = 0;
    out->gid = 0;
    out->size = (uint32_t)(node->size > 0xFFFFFFFFull ? 0xFFFFFFFFu : node->size);
    out->fs_private[0] = node->first_cluster;
    out->fs_private[1] = (uint32_t)(node->size & 0xFFFFFFFFu);
    out->fs_private[2] = (uint32_t)(node->size >> 32);
    out->fs_private[3] = (uint32_t)node->attr | ((uint32_t)node->flags << 8);
}

static void exfat_node_from_inode(const vfs_inode_t *inode, exfat_node_t *node) {
    if (!inode || !node) return;
    node->first_cluster = inode->fs_private[0];
    node->size = ((uint64_t)inode->fs_private[2] << 32) | inode->fs_private[1];
    node->attr = (uint8_t)(inode->fs_private[3] & 0xFFu);
    node->flags = (uint8_t)((inode->fs_private[3] >> 8) & 0xFFu);
}

static int exfat_read_node_bytes(exfat_fs_t *fs, const exfat_node_t *node,
                                 uint64_t off, void *buf, uint32_t len) {
    uint8_t *dst = (uint8_t *)buf;
    uint32_t cluster;
    uint32_t cluster_size;
    uint64_t skip_clusters;
    uint32_t cluster_off;
    uint32_t done = 0;

    if (!fs || !node || !buf) return -1;
    if (off >= node->size) return 0;
    if ((uint64_t)len > node->size - off) len = (uint32_t)(node->size - off);
    if (len == 0) return 0;
    cluster = node->first_cluster;
    if (!exfat_valid_cluster(fs, cluster)) return -1;
    cluster_size = fs->bytes_per_sector * fs->sectors_per_cluster;
    skip_clusters = off / cluster_size;
    cluster_off = (uint32_t)(off % cluster_size);
    if (node->flags & EXFAT_STREAM_NO_FAT_CHAIN) {
        cluster += (uint32_t)skip_clusters;
    } else {
        for (uint64_t i = 0; i < skip_clusters; ++i) {
            if (exfat_next_cluster(fs, cluster, &cluster) < 0) return -1;
        }
    }
    while (done < len && exfat_valid_cluster(fs, cluster)) {
        uint32_t first_lba = exfat_cluster_lba(fs, cluster);
        for (uint32_t s = 0; s < fs->sectors_per_cluster && done < len; ++s) {
            uint32_t sector_off = 0;
            uint32_t chunk = fs->bytes_per_sector;
            if (cluster_off >= fs->bytes_per_sector) {
                cluster_off -= fs->bytes_per_sector;
                continue;
            }
            if (cluster_off) {
                sector_off = cluster_off;
                chunk -= cluster_off;
                cluster_off = 0;
            }
            if (chunk > len - done) chunk = len - done;
            if (exfat_read_sector(fs, first_lba + s, fs->scratch) < 0) return -1;
            memcpy(dst + done, fs->scratch + sector_off, chunk);
            done += chunk;
        }
        if (done < len) {
            if (node->flags & EXFAT_STREAM_NO_FAT_CHAIN) {
                cluster++;
            } else if (exfat_next_cluster(fs, cluster, &cluster) < 0) {
                return -1;
            }
        }
    }
    return done == len ? (int)done : -1;
}

static int exfat_read_dir_entry(exfat_fs_t *fs, const exfat_node_t *dir,
                                uint64_t off, uint8_t entry[32]) {
    return exfat_read_node_bytes(fs, dir, off, entry, 32u) == 32 ? 0 : -1;
}

static int exfat_dir_iter(exfat_fs_t *fs, const exfat_node_t *dir, uint32_t want_idx,
                          const char *want_name, exfat_dirent_t *found) {
    uint64_t off = 0;
    uint32_t idx = 0;
    exfat_dirent_t cur;
    uint8_t entry[32];
    uint8_t in_set = 0;
    uint8_t secondaries_left = 0;
    uint8_t have_stream = 0;

    if (!fs || !dir || !(dir->attr & EXFAT_ATTR_DIRECTORY)) return -1;
    memset(&cur, 0, sizeof(cur));
    while (off + 32u <= dir->size) {
        if (exfat_read_dir_entry(fs, dir, off, entry) < 0) return -1;
        off += 32u;
        if (entry[0] == EXFAT_ENTRY_EOD) break;
        if ((entry[0] & 0x80u) == 0) {
            in_set = 0;
            secondaries_left = 0;
            have_stream = 0;
            continue;
        }
        if (entry[0] == EXFAT_ENTRY_FILE) {
            memset(&cur, 0, sizeof(cur));
            cur.attr = (uint8_t)(exfat_le16(entry + 4) & 0xFFu);
            secondaries_left = entry[1];
            in_set = secondaries_left ? 1 : 0;
            have_stream = 0;
            continue;
        }
        if (!in_set || secondaries_left == 0) continue;
        secondaries_left--;
        if (entry[0] == EXFAT_ENTRY_STREAM) {
            cur.flags = entry[1];
            cur.first_cluster = exfat_le32(entry + 20);
            cur.size = exfat_le64(entry + 24);
            have_stream = 1;
        } else if (entry[0] == EXFAT_ENTRY_NAME && have_stream) {
            exfat_name_append(&cur, entry);
        }
        if (in_set && secondaries_left == 0) {
            if (have_stream && cur.name[0]) {
                if (want_name) {
                    if (exfat_name_eq(cur.name, want_name)) {
                        if (found) *found = cur;
                        return 0;
                    }
                } else if (idx == want_idx) {
                    if (found) *found = cur;
                    return 0;
                }
                idx++;
            }
            in_set = 0;
            have_stream = 0;
        }
    }
    return -1;
}

static int exfat_lookup(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    exfat_fs_t *fs = sb ? (exfat_fs_t *)sb->fs_private : 0;
    exfat_node_t dnode;
    exfat_dirent_t de;
    exfat_node_t node;

    if (!fs || !dir || !name || !out) return -1;
    if (strcmp(name, ".") == 0) {
        *out = *dir;
        return 0;
    }
    exfat_node_from_inode(dir, &dnode);
    if (exfat_dir_iter(fs, &dnode, 0, name, &de) < 0) return -1;
    node.first_cluster = de.first_cluster;
    node.size = de.size;
    node.attr = de.attr;
    node.flags = de.flags;
    exfat_fill_inode(&node, out);
    return 0;
}

static int exfat_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    exfat_fs_t *fs = sb ? (exfat_fs_t *)sb->fs_private : 0;
    exfat_node_t node;
    if (!fs || !inode || !buf) return -1;
    if ((inode->mode & 0xF000u) != VFS_INODE_FILE) return -1;
    exfat_node_from_inode(inode, &node);
    return exfat_read_node_bytes(fs, &node, off, buf, len);
}

static int exfat_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx,
                         char *name_out, vfs_inode_t *inode_out) {
    exfat_fs_t *fs = sb ? (exfat_fs_t *)sb->fs_private : 0;
    exfat_node_t dnode;
    exfat_dirent_t de;
    exfat_node_t node;

    if (!fs || !dir || !name_out || !inode_out) return -1;
    exfat_node_from_inode(dir, &dnode);
    if (exfat_dir_iter(fs, &dnode, idx, 0, &de) < 0) return -1;
    strncpy(name_out, de.name, VFS_NAME_MAX - 1);
    name_out[VFS_NAME_MAX - 1] = 0;
    node.first_cluster = de.first_cluster;
    node.size = de.size;
    node.attr = de.attr;
    node.flags = de.flags;
    exfat_fill_inode(&node, inode_out);
    return 0;
}

static int exfat_statfs(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) {
    exfat_fs_t *fs = sb ? (exfat_fs_t *)sb->fs_private : 0;
    uint64_t total;
    if (!fs || !total_kb || !used_kb) return -1;
    total = (uint64_t)fs->cluster_count * fs->sectors_per_cluster * fs->bytes_per_sector / 1024u;
    *total_kb = total > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)total;
    *used_kb = *total_kb;
    return 0;
}

static filesystem_ops_t g_exfat_ops = {
    .lookup = exfat_lookup,
    .read = exfat_read,
    .readdir = exfat_readdir,
    .statfs = exfat_statfs,
};

static int exfat_mount_common(block_device_t *bdev, const char *dev, const char *target) {
    exfat_fs_t *fs;
    vfs_superblock_t sb;
    uint8_t bps_shift;
    uint8_t spc_shift;
    exfat_node_t root;

    if (!bdev || !target) return -1;
    if (g_exfat_mount_count >= EXFAT_MAX_MOUNTS) return -1;
    fs = &g_exfat_mounts[g_exfat_mount_count];
    memset(fs, 0, sizeof(*fs));
    fs->bdev = bdev;
    fs->bytes_per_sector = bdev->sector_size;
    if (fs->bytes_per_sector > sizeof(fs->scratch)) return -1;
    if (exfat_read_sector(fs, 0, fs->scratch) < 0) return -1;
    if (memcmp(fs->scratch + 3, EXFAT_SIGNATURE, 8) != 0 ||
        fs->scratch[510] != 0x55u || fs->scratch[511] != 0xAAu) {
        printf("[exfat] invalid boot sector on %s\n", dev ? dev : bdev->name);
        return -1;
    }
    bps_shift = fs->scratch[108];
    spc_shift = fs->scratch[109];
    if (bps_shift >= 13u || spc_shift >= 25u) return -1;
    fs->bytes_per_sector = 1u << bps_shift;
    fs->sectors_per_cluster = 1u << spc_shift;
    if (fs->bytes_per_sector != bdev->sector_size || fs->bytes_per_sector > sizeof(fs->scratch)) {
        printf("[exfat] unsupported sector size %u on %s\n",
               fs->bytes_per_sector, dev ? dev : bdev->name);
        return -1;
    }
    fs->fat_offset = exfat_le32(fs->scratch + 80);
    fs->fat_length = exfat_le32(fs->scratch + 84);
    fs->cluster_heap_offset = exfat_le32(fs->scratch + 88);
    fs->cluster_count = exfat_le32(fs->scratch + 92);
    fs->root_cluster = exfat_le32(fs->scratch + 96);
    if (!fs->fat_offset || !fs->fat_length || !fs->cluster_heap_offset ||
        !fs->cluster_count || !exfat_valid_cluster(fs, fs->root_cluster)) {
        return -1;
    }
    root.first_cluster = fs->root_cluster;
    root.size = (uint64_t)fs->cluster_count * fs->sectors_per_cluster * fs->bytes_per_sector;
    root.attr = EXFAT_ATTR_DIRECTORY;
    root.flags = 0;

    memset(&sb, 0, sizeof(sb));
    strcpy(sb.fs_name, "exfat");
    strncpy(sb.dev_name, dev ? dev : bdev->name, sizeof(sb.dev_name) - 1);
    strncpy(sb.mountpoint, target, sizeof(sb.mountpoint) - 1);
    exfat_fill_inode(&root, &sb.root);
    sb.ops = &g_exfat_ops;
    sb.fs_private = fs;
    if (vfs_add_superblock(&sb) < 0) return -1;
    g_exfat_mount_count++;
    printf("[exfat] mounted %s on %s clusters=%u spc=%u\n",
           sb.dev_name, target, fs->cluster_count, fs->sectors_per_cluster);
    return 0;
}

int exfat_mount(const char *dev, const char *target) {
    block_device_t *b;
    const char *name;
    if (!dev || !target) return -1;
    name = (strncmp(dev, "/dev/", 5) == 0) ? dev + 5 : dev;
    b = block_find(name);
    if (!b) return -1;
    return exfat_mount_common(b, dev, target);
}

int exfat_mount_block(block_device_t *bdev, const char *target) {
    if (!bdev) return -1;
    return exfat_mount_common(bdev, bdev->name, target);
}
