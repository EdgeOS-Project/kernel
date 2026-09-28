/*
 * EdgeOS FAT32 VFS integration.
 *
 * Copyright (c) EdgeOS Contributors.
 * Licensed under the Mozilla Public License, v. 2.0.
 */
#include "vfs/vfs.h"
#include "block/block.h"
#include "fat32.h"
#include "stdio.h"
#include "string.h"

#define FAT32_MAX_MOUNTS 4u
#define FAT32_SECTOR_SIZE 512u
#define FAT32_ATTR_READ_ONLY 0x01u
#define FAT32_ATTR_DIRECTORY 0x10u
#define FAT32_ATTR_ARCHIVE 0x20u
#define FAT32_ATTR_LFN 0x0Fu
#define FAT32_CLUSTER_EOC 0x0FFFFFF8u
#define FAT32_CLUSTER_BAD 0x0FFFFFF7u
#define FAT32_LFN_LAST 0x40u

typedef struct {
    block_device_t *bdev;
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t reserved_sectors;
    uint32_t fat_count;
    uint32_t fat_size_sectors;
    uint32_t root_cluster;
    uint32_t total_sectors;
    uint32_t fat_lba;
    uint32_t data_lba;
    uint32_t cluster_count;
    uint8_t scratch[FAT32_SECTOR_SIZE];
} fat32_disk_t;

typedef struct {
    uint32_t cluster;
    uint32_t size;
    uint32_t dir_lba;
    uint32_t dir_off;
    uint8_t attr;
    char name[VFS_NAME_MAX];
} fat32_dirent_t;

static fat32_disk_t g_fat32_mounts[FAT32_MAX_MOUNTS];
static uint32_t g_fat32_mount_count;

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void put_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)(v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static int ascii_fold(int c) {
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

static int fat_name_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (ascii_fold((uint8_t)*a) != ascii_fold((uint8_t)*b)) return 0;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static uint32_t fat_first_cluster(const uint8_t *e) {
    return ((uint32_t)le16(e + 20) << 16) | le16(e + 26);
}

static uint32_t fat_cluster_lba(const fat32_disk_t *fs, uint32_t cluster) {
    return fs->data_lba + (cluster - 2u) * fs->sectors_per_cluster;
}

static int fat_read_sector(fat32_disk_t *fs, uint32_t lba, void *out) {
    if (!fs || !fs->bdev || !out) return -1;
    if (fs->bdev->sector_size != FAT32_SECTOR_SIZE) return -1;
    return block_read_sectors(fs->bdev, lba, 1, out);
}

static int fat_valid_cluster(uint32_t cluster) {
    return cluster >= 2u && cluster < FAT32_CLUSTER_BAD;
}

static int fat_cluster_in_volume(const fat32_disk_t *fs, uint32_t cluster) {
    return fs && cluster >= 2u && cluster < fs->cluster_count + 2u;
}

static int fat_next_cluster(fat32_disk_t *fs, uint32_t cluster, uint32_t *next_out) {
    uint32_t fat_off;
    uint32_t sector;
    uint32_t off;
    uint32_t next;

    if (!fs || !next_out || !fat_valid_cluster(cluster)) return -1;
    fat_off = cluster * 4u;
    sector = fs->fat_lba + fat_off / FAT32_SECTOR_SIZE;
    off = fat_off % FAT32_SECTOR_SIZE;
    if (fat_read_sector(fs, sector, fs->scratch) < 0) return -1;
    next = le32(fs->scratch + off) & 0x0FFFFFFFu;
    *next_out = next;
    return 0;
}

static int fat_write_sector(fat32_disk_t *fs, uint32_t lba, const void *in) {
    if (!fs || !fs->bdev || !in) return -1;
    if (fs->bdev->sector_size != FAT32_SECTOR_SIZE) return -1;
    return block_write_sectors(fs->bdev, lba, 1, in);
}

static int fat_write_fat_entry(fat32_disk_t *fs, uint32_t cluster, uint32_t value) {
    uint32_t fat_off;
    uint32_t fat_sector_off;
    uint32_t off;

    if (!fs || !fat_cluster_in_volume(fs, cluster)) return -1;
    fat_off = cluster * 4u;
    fat_sector_off = fat_off / FAT32_SECTOR_SIZE;
    off = fat_off % FAT32_SECTOR_SIZE;
    /*
     * FAT32 stores 28-bit chain values.  Preserve the high nibble in each FAT
     * copy because some formatters keep implementation-specific flags there.
     */
    for (uint32_t i = 0; i < fs->fat_count; ++i) {
        uint32_t sector = fs->fat_lba + i * fs->fat_size_sectors + fat_sector_off;
        uint32_t cur;
        if (fat_read_sector(fs, sector, fs->scratch) < 0) return -1;
        cur = le32(fs->scratch + off);
        put_le32(fs->scratch + off, (cur & 0xF0000000u) | (value & 0x0FFFFFFFu));
        if (fat_write_sector(fs, sector, fs->scratch) < 0) return -1;
    }
    return 0;
}

static int fat_find_free_cluster(fat32_disk_t *fs, uint32_t *cluster_out) {
    if (!fs || !cluster_out) return -1;
    for (uint32_t c = 2u; c < fs->cluster_count + 2u; ++c) {
        uint32_t next;
        if (fat_next_cluster(fs, c, &next) < 0) return -1;
        if (next == 0) {
            *cluster_out = c;
            return 0;
        }
    }
    return -1;
}

static int fat_zero_cluster(fat32_disk_t *fs, uint32_t cluster) {
    uint32_t first_lba;
    if (!fs || !fat_cluster_in_volume(fs, cluster)) return -1;
    memset(fs->scratch, 0, FAT32_SECTOR_SIZE);
    first_lba = fat_cluster_lba(fs, cluster);
    for (uint32_t s = 0; s < fs->sectors_per_cluster; ++s) {
        if (fat_write_sector(fs, first_lba + s, fs->scratch) < 0) return -1;
    }
    return 0;
}

static int fat_free_chain(fat32_disk_t *fs, uint32_t start) {
    uint32_t cluster = start;
    if (!fs || start == 0) return 0;
    if (!fat_cluster_in_volume(fs, start)) return -1;
    while (fat_cluster_in_volume(fs, cluster)) {
        uint32_t next;
        if (fat_next_cluster(fs, cluster, &next) < 0) return -1;
        if (fat_write_fat_entry(fs, cluster, 0) < 0) return -1;
        if (next >= FAT32_CLUSTER_EOC) return 0;
        if (!fat_cluster_in_volume(fs, next)) return -1;
        cluster = next;
    }
    return 0;
}

static uint32_t fat_inode_dir_lba(const vfs_inode_t *inode) {
    return inode ? inode->fs_private[3] : 0;
}

static uint32_t fat_inode_dir_off(const vfs_inode_t *inode) {
    return inode ? (inode->fs_private[2] >> 8) : 0;
}

static void fat_fill_inode(uint32_t cluster, uint32_t size, uint8_t attr,
                           uint32_t dir_lba, uint32_t dir_off, vfs_inode_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->ino = cluster ? cluster : 2u;
    out->mode = (attr & FAT32_ATTR_DIRECTORY) ? (VFS_INODE_DIR | 0777u) : (VFS_INODE_FILE | 0666u);
    out->uid = 0;
    out->gid = 0;
    out->size = size;
    out->fs_private[0] = cluster;
    out->fs_private[1] = size;
    out->fs_private[2] = (uint32_t)attr | (dir_off << 8);
    out->fs_private[3] = dir_lba;
}

static void fat_short_name_copy(const uint8_t *e, char *out) {
    uint32_t pos = 0;
    int base_end = 8;
    int ext_end = 3;

    while (base_end > 0 && e[base_end - 1] == ' ') base_end--;
    while (ext_end > 0 && e[8 + ext_end - 1] == ' ') ext_end--;
    for (int i = 0; i < base_end && pos + 1 < VFS_NAME_MAX; ++i) {
        out[pos++] = (char)ascii_fold(e[i]);
    }
    if (ext_end > 0 && pos + 1 < VFS_NAME_MAX) out[pos++] = '.';
    for (int i = 0; i < ext_end && pos + 1 < VFS_NAME_MAX; ++i) {
        out[pos++] = (char)ascii_fold(e[8 + i]);
    }
    out[pos] = 0;
}

static void fat_lfn_clear(char *lfn, uint8_t *valid) {
    if (lfn) lfn[0] = 0;
    if (valid) *valid = 0;
}

static void fat_lfn_put_char(char *lfn, uint32_t *out_pos, uint16_t ch) {
    if (!lfn || !out_pos) return;
    if (ch == 0x0000u || ch == 0xFFFFu) return;
    if (*out_pos + 1 >= VFS_NAME_MAX) return;
    lfn[(*out_pos)++] = (ch < 0x80u) ? (char)ch : '?';
}

static void fat_lfn_collect(const uint8_t *e, char *lfn, uint8_t *valid) {
    uint8_t seq;
    uint32_t pos;
    static const uint8_t offs[13] = {
        1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30
    };

    if (!e || !lfn || !valid) return;
    seq = (uint8_t)(e[0] & 0x1Fu);
    if (seq == 0 || seq > 20) {
        fat_lfn_clear(lfn, valid);
        return;
    }
    if (e[0] & FAT32_LFN_LAST) {
        memset(lfn, 0, VFS_NAME_MAX);
        *valid = 1;
    } else if (!*valid) {
        return;
    }
    pos = (uint32_t)(seq - 1u) * 13u;
    for (uint32_t i = 0; i < 13u; ++i) {
        uint16_t ch = le16(e + offs[i]);
        fat_lfn_put_char(lfn, &pos, ch);
    }
}

static int fat_emit_dirent(const uint8_t *e, const char *lfn, uint32_t dir_lba,
                           uint32_t dir_off, fat32_dirent_t *out) {
    uint8_t attr;
    if (!e || !out) return -1;
    attr = e[11];
    if (e[0] == 0x00u || e[0] == 0xE5u) return -1;
    if (attr == FAT32_ATTR_LFN) return -1;
    if (attr & 0x08u) return -1; /* volume label */
    memset(out, 0, sizeof(*out));
    out->cluster = fat_first_cluster(e);
    out->size = le32(e + 28);
    out->dir_lba = dir_lba;
    out->dir_off = dir_off;
    out->attr = attr;
    if (lfn && lfn[0]) {
        strncpy(out->name, lfn, sizeof(out->name) - 1);
    } else {
        fat_short_name_copy(e, out->name);
    }
    return 0;
}

static int fat_dir_iter(fat32_disk_t *fs, const vfs_inode_t *dir, uint32_t want_idx,
                        const char *want_name, fat32_dirent_t *found) {
    uint32_t cluster;
    uint32_t idx = 0;
    char lfn[VFS_NAME_MAX];
    uint8_t lfn_valid;

    if (!fs || !dir || ((dir->mode & 0xF000u) != VFS_INODE_DIR)) return -1;
    cluster = dir->fs_private[0] ? dir->fs_private[0] : fs->root_cluster;
    if (!fat_valid_cluster(cluster)) return -1;
    fat_lfn_clear(lfn, &lfn_valid);
    while (fat_valid_cluster(cluster) && cluster < FAT32_CLUSTER_EOC) {
        uint32_t first_lba = fat_cluster_lba(fs, cluster);
        for (uint32_t s = 0; s < fs->sectors_per_cluster; ++s) {
            if (fat_read_sector(fs, first_lba + s, fs->scratch) < 0) return -1;
            for (uint32_t off = 0; off < FAT32_SECTOR_SIZE; off += 32u) {
                const uint8_t *e = fs->scratch + off;
                fat32_dirent_t de;
                if (e[0] == 0x00u) return -1;
                if (e[0] == 0xE5u) {
                    fat_lfn_clear(lfn, &lfn_valid);
                    continue;
                }
                if (e[11] == FAT32_ATTR_LFN) {
                    fat_lfn_collect(e, lfn, &lfn_valid);
                    continue;
                }
                if (fat_emit_dirent(e, lfn_valid ? lfn : 0, first_lba + s, off, &de) == 0) {
                    if (want_name) {
                        if (fat_name_eq(de.name, want_name)) {
                            if (found) *found = de;
                            return 0;
                        }
                    } else if (idx == want_idx) {
                        if (found) *found = de;
                        return 0;
                    }
                    idx++;
                }
                fat_lfn_clear(lfn, &lfn_valid);
            }
        }
        if (fat_next_cluster(fs, cluster, &cluster) < 0) return -1;
    }
    return -1;
}

static int fat_lookup(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    fat32_disk_t *fs = sb ? (fat32_disk_t *)sb->fs_private : 0;
    fat32_dirent_t de;
    if (!fs || !dir || !name || !out) return -1;
    if (strcmp(name, ".") == 0) {
        *out = *dir;
        return 0;
    }
    if (fat_dir_iter(fs, dir, 0, name, &de) < 0) return -1;
    fat_fill_inode(de.cluster, de.size, de.attr, de.dir_lba, de.dir_off, out);
    return 0;
}

static int fat_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    fat32_disk_t *fs = sb ? (fat32_disk_t *)sb->fs_private : 0;
    uint8_t *dst = (uint8_t *)buf;
    uint32_t cluster;
    uint32_t cluster_size;
    uint32_t skip_clusters;
    uint32_t cluster_off;
    uint32_t done = 0;

    if (!fs || !inode || !buf) return -1;
    if ((inode->mode & 0xF000u) != VFS_INODE_FILE) return -1;
    if (off >= inode->fs_private[1]) return 0;
    if (len > inode->fs_private[1] - off) len = inode->fs_private[1] - off;
    if (len == 0) return 0;
    cluster = inode->fs_private[0];
    cluster_size = fs->sectors_per_cluster * FAT32_SECTOR_SIZE;
    skip_clusters = off / cluster_size;
    cluster_off = off % cluster_size;
    for (uint32_t i = 0; i < skip_clusters; ++i) {
        if (fat_next_cluster(fs, cluster, &cluster) < 0) return -1;
    }
    while (done < len && fat_valid_cluster(cluster) && cluster < FAT32_CLUSTER_EOC) {
        uint32_t first_lba = fat_cluster_lba(fs, cluster);
        for (uint32_t s = 0; s < fs->sectors_per_cluster && done < len; ++s) {
            uint32_t sector_off = 0;
            uint32_t chunk = FAT32_SECTOR_SIZE;
            if (cluster_off >= FAT32_SECTOR_SIZE) {
                cluster_off -= FAT32_SECTOR_SIZE;
                continue;
            }
            if (cluster_off) {
                sector_off = cluster_off;
                chunk -= cluster_off;
                cluster_off = 0;
            }
            if (chunk > len - done) chunk = len - done;
            if (fat_read_sector(fs, first_lba + s, fs->scratch) < 0) return -1;
            memcpy(dst + done, fs->scratch + sector_off, chunk);
            done += chunk;
        }
        if (done < len && fat_next_cluster(fs, cluster, &cluster) < 0) return -1;
    }
    return (int)done;
}

static int fat_chain_last(fat32_disk_t *fs, uint32_t start, uint32_t *last_out, uint32_t *count_out) {
    uint32_t cluster = start;
    uint32_t count = 0;

    if (!fs || !last_out || !fat_cluster_in_volume(fs, start)) return -1;
    while (fat_cluster_in_volume(fs, cluster)) {
        uint32_t next;
        count++;
        if (fat_next_cluster(fs, cluster, &next) < 0) return -1;
        if (next >= FAT32_CLUSTER_EOC) {
            *last_out = cluster;
            if (count_out) *count_out = count;
            return 0;
        }
        if (!fat_cluster_in_volume(fs, next)) return -1;
        cluster = next;
    }
    return -1;
}

static int fat_update_inode_dirent(fat32_disk_t *fs, vfs_inode_t *inode) {
    uint32_t dir_lba;
    uint32_t dir_off;
    uint32_t cluster;

    if (!fs || !inode) return -1;
    dir_lba = fat_inode_dir_lba(inode);
    dir_off = fat_inode_dir_off(inode);
    if (!dir_lba || dir_off + 32u > FAT32_SECTOR_SIZE) return -1;
    if (fat_read_sector(fs, dir_lba, fs->scratch) < 0) return -1;
    cluster = inode->fs_private[0];
    put_le16(fs->scratch + dir_off + 20u, (uint16_t)(cluster >> 16));
    put_le16(fs->scratch + dir_off + 26u, (uint16_t)(cluster & 0xFFFFu));
    put_le32(fs->scratch + dir_off + 28u, inode->fs_private[1]);
    return fat_write_sector(fs, dir_lba, fs->scratch);
}

static int fat_ensure_chain_for_size(fat32_disk_t *fs, vfs_inode_t *inode, uint32_t new_size) {
    uint32_t cluster_size;
    uint32_t need_clusters;
    uint32_t have_clusters = 0;
    uint32_t last = 0;

    if (!fs || !inode) return -1;
    if (new_size == 0) return 0;
    cluster_size = fs->sectors_per_cluster * FAT32_SECTOR_SIZE;
    need_clusters = (new_size + cluster_size - 1u) / cluster_size;
    if (inode->fs_private[0]) {
        if (fat_chain_last(fs, inode->fs_private[0], &last, &have_clusters) < 0) return -1;
    }
    while (have_clusters < need_clusters) {
        uint32_t c;
        if (fat_find_free_cluster(fs, &c) < 0) return -1;
        if (fat_write_fat_entry(fs, c, FAT32_CLUSTER_EOC) < 0) return -1;
        if (fat_zero_cluster(fs, c) < 0) return -1;
        if (!inode->fs_private[0]) {
            inode->fs_private[0] = c;
            inode->ino = c;
        } else {
            if (fat_write_fat_entry(fs, last, c) < 0) return -1;
        }
        last = c;
        have_clusters++;
    }
    return fat_update_inode_dirent(fs, inode);
}

static int fat_write_zero_range(fat32_disk_t *fs, vfs_inode_t *inode, uint32_t off, uint32_t len) {
    uint32_t cluster;
    uint32_t cluster_size;
    uint32_t skip_clusters;
    uint32_t cluster_off;
    uint32_t done = 0;

    if (!fs || !inode) return -1;
    if (len == 0) return 0;
    cluster = inode->fs_private[0];
    cluster_size = fs->sectors_per_cluster * FAT32_SECTOR_SIZE;
    skip_clusters = off / cluster_size;
    cluster_off = off % cluster_size;
    for (uint32_t i = 0; i < skip_clusters; ++i) {
        if (fat_next_cluster(fs, cluster, &cluster) < 0) return -1;
    }
    while (done < len && fat_cluster_in_volume(fs, cluster)) {
        uint32_t first_lba = fat_cluster_lba(fs, cluster);
        for (uint32_t s = 0; s < fs->sectors_per_cluster && done < len; ++s) {
            uint32_t sector_off = 0;
            uint32_t chunk = FAT32_SECTOR_SIZE;
            if (cluster_off >= FAT32_SECTOR_SIZE) {
                cluster_off -= FAT32_SECTOR_SIZE;
                continue;
            }
            if (cluster_off) {
                sector_off = cluster_off;
                chunk -= cluster_off;
                cluster_off = 0;
            }
            if (chunk > len - done) chunk = len - done;
            if (chunk != FAT32_SECTOR_SIZE) {
                if (fat_read_sector(fs, first_lba + s, fs->scratch) < 0) return -1;
            } else {
                memset(fs->scratch, 0, FAT32_SECTOR_SIZE);
            }
            memset(fs->scratch + sector_off, 0, chunk);
            if (fat_write_sector(fs, first_lba + s, fs->scratch) < 0) return -1;
            done += chunk;
        }
        if (done < len && fat_next_cluster(fs, cluster, &cluster) < 0) return -1;
    }
    return done == len ? 0 : -1;
}

static int fat_write(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, const void *buf, uint32_t len) {
    fat32_disk_t *fs = sb ? (fat32_disk_t *)sb->fs_private : 0;
    const uint8_t *src = (const uint8_t *)buf;
    uint32_t cluster;
    uint32_t cluster_size;
    uint32_t skip_clusters;
    uint32_t cluster_off;
    uint32_t done = 0;
    uint32_t old_size;
    uint32_t new_end;

    if (!fs || !inode || !buf) return -1;
    if ((inode->mode & 0xF000u) != VFS_INODE_FILE) return -1;
    if (len == 0) return 0;
    if (off > UINT32_MAX - len) return -1;
    old_size = inode->fs_private[1];
    new_end = off + len;
    if (fat_ensure_chain_for_size(fs, inode, new_end) < 0) return -1;
    if (off > old_size && fat_write_zero_range(fs, inode, old_size, off - old_size) < 0) return -1;
    cluster = inode->fs_private[0];
    cluster_size = fs->sectors_per_cluster * FAT32_SECTOR_SIZE;
    skip_clusters = off / cluster_size;
    cluster_off = off % cluster_size;
    for (uint32_t i = 0; i < skip_clusters; ++i) {
        if (fat_next_cluster(fs, cluster, &cluster) < 0) return -1;
    }
    while (done < len && fat_valid_cluster(cluster) && cluster < FAT32_CLUSTER_EOC) {
        uint32_t first_lba = fat_cluster_lba(fs, cluster);
        for (uint32_t s = 0; s < fs->sectors_per_cluster && done < len; ++s) {
            uint32_t sector_off = 0;
            uint32_t chunk = FAT32_SECTOR_SIZE;
            if (cluster_off >= FAT32_SECTOR_SIZE) {
                cluster_off -= FAT32_SECTOR_SIZE;
                continue;
            }
            if (cluster_off) {
                sector_off = cluster_off;
                chunk -= cluster_off;
                cluster_off = 0;
            }
            if (chunk > len - done) chunk = len - done;
            if (chunk != FAT32_SECTOR_SIZE) {
                if (fat_read_sector(fs, first_lba + s, fs->scratch) < 0) return -1;
                memcpy(fs->scratch + sector_off, src + done, chunk);
            } else {
                memcpy(fs->scratch, src + done, FAT32_SECTOR_SIZE);
            }
            if (fat_write_sector(fs, first_lba + s, fs->scratch) < 0) return -1;
            done += chunk;
        }
        if (done < len && fat_next_cluster(fs, cluster, &cluster) < 0) return -1;
    }
    if (done == len && new_end > old_size) {
        inode->fs_private[1] = new_end;
        inode->size = new_end;
        if (fat_update_inode_dirent(fs, inode) < 0) return -1;
    }
    return done == len ? (int)done : -1;
}

static int fat_truncate(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t len) {
    fat32_disk_t *fs = sb ? (fat32_disk_t *)sb->fs_private : 0;
    uint32_t old_size;
    uint32_t cluster_size;
    uint32_t keep_clusters;
    uint32_t cluster;
    if (!fs || !inode) return -1;
    if ((inode->mode & 0xF000u) != VFS_INODE_FILE) return -1;
    old_size = inode->fs_private[1];
    if (len == old_size) return 0;
    if (len > old_size) {
        if (fat_ensure_chain_for_size(fs, inode, len) < 0) return -1;
        if (fat_write_zero_range(fs, inode, old_size, len - old_size) < 0) return -1;
        inode->fs_private[1] = len;
        inode->size = len;
        return fat_update_inode_dirent(fs, inode);
    }
    cluster_size = fs->sectors_per_cluster * FAT32_SECTOR_SIZE;
    keep_clusters = len ? (len + cluster_size - 1u) / cluster_size : 0;
    cluster = inode->fs_private[0];
    if (keep_clusters == 0) {
        if (fat_free_chain(fs, cluster) < 0) return -1;
        inode->fs_private[0] = 0;
        inode->ino = 2u;
    } else {
        uint32_t last = cluster;
        uint32_t next = 0;
        if (!fat_cluster_in_volume(fs, cluster)) return -1;
        for (uint32_t i = 1; i < keep_clusters; ++i) {
            if (fat_next_cluster(fs, last, &next) < 0) return -1;
            if (!fat_cluster_in_volume(fs, next)) return -1;
            last = next;
        }
        if (fat_next_cluster(fs, last, &next) < 0) return -1;
        if (next < FAT32_CLUSTER_EOC && fat_free_chain(fs, next) < 0) return -1;
        if (fat_write_fat_entry(fs, last, FAT32_CLUSTER_EOC) < 0) return -1;
    }
    inode->fs_private[1] = len;
    inode->size = len;
    return fat_update_inode_dirent(fs, inode);
}

static int fat_short_char_ok(char c) {
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= '0' && c <= '9') return 1;
    switch (c) {
        case '$': case '%': case '\'': case '-': case '_':
        case '@': case '~': case '`': case '!': case '(':
        case ')': case '{': case '}': case '^': case '#':
        case '&':
            return 1;
        default:
            return 0;
    }
}

static int fat_make_short_name(const char *name, uint8_t out[11]) {
    uint32_t base = 0;
    uint32_t ext = 0;
    uint8_t seen_dot = 0;

    if (!name || !name[0] || name[0] == '.') return -1;
    memset(out, ' ', 11);
    for (const char *p = name; *p; ++p) {
        char c = *p;
        if (c == '.') {
            if (seen_dot || base == 0) return -1;
            seen_dot = 1;
            continue;
        }
        if (!fat_short_char_ok(c)) return -1;
        if (c >= 'a' && c <= 'z') c = (char)(c - ('a' - 'A'));
        if (!seen_dot) {
            if (base >= 8u) return -1;
            out[base++] = (uint8_t)c;
        } else {
            if (ext >= 3u) return -1;
            out[8u + ext++] = (uint8_t)c;
        }
    }
    if (base == 0 || (seen_dot && ext == 0)) return -1;
    return 0;
}

static int fat_find_free_dir_slot(fat32_disk_t *fs, const vfs_inode_t *dir,
                                  uint32_t *lba_out, uint32_t *off_out) {
    uint32_t cluster;

    if (!fs || !dir || !lba_out || !off_out) return -1;
    cluster = dir->fs_private[0] ? dir->fs_private[0] : fs->root_cluster;
    if (!fat_cluster_in_volume(fs, cluster)) return -1;
    while (fat_cluster_in_volume(fs, cluster)) {
        uint32_t first_lba = fat_cluster_lba(fs, cluster);
        for (uint32_t s = 0; s < fs->sectors_per_cluster; ++s) {
            if (fat_read_sector(fs, first_lba + s, fs->scratch) < 0) return -1;
            for (uint32_t off = 0; off < FAT32_SECTOR_SIZE; off += 32u) {
                uint8_t first = fs->scratch[off];
                if (first == 0x00u || first == 0xE5u) {
                    *lba_out = first_lba + s;
                    *off_out = off;
                    return 0;
                }
            }
        }
        if (fat_next_cluster(fs, cluster, &cluster) < 0) return -1;
    }
    /*
     * Directory growth is intentionally deferred until rename/unlink and LFN
     * updates are in place.  Failing here is better than corrupting a full
     * directory by linking an uninitialized cluster into it.
     */
    return -1;
}

static int fat_create(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name,
                      uint16_t mode, vfs_inode_t *out) {
    fat32_disk_t *fs = sb ? (fat32_disk_t *)sb->fs_private : 0;
    uint8_t short_name[11];
    uint32_t lba;
    uint32_t off;
    fat32_dirent_t existing;

    (void)mode;
    if (!fs || !dir || !name || !out) return -1;
    if ((dir->mode & 0xF000u) != VFS_INODE_DIR) return -1;
    /*
     * This creates plain 8.3 directory entries only.  Linux-compatible long
     * filename creation needs checksum-paired LFN slots, multi-slot rollback,
     * and short-name collision generation; reject those names until that path
     * is implemented instead of creating names that Linux would misinterpret.
     */
    if (fat_make_short_name(name, short_name) < 0) return -1;
    if (fat_dir_iter(fs, dir, 0, name, &existing) == 0) return -1;
    if (fat_find_free_dir_slot(fs, dir, &lba, &off) < 0) return -1;
    if (fat_read_sector(fs, lba, fs->scratch) < 0) return -1;
    memset(fs->scratch + off, 0, 32u);
    memcpy(fs->scratch + off, short_name, 11u);
    fs->scratch[off + 11u] = FAT32_ATTR_ARCHIVE;
    /* Minimum valid FAT date: 1980-01-01.  Time remains midnight. */
    put_le16(fs->scratch + off + 16u, 0x0021u);
    put_le16(fs->scratch + off + 18u, 0x0021u);
    put_le16(fs->scratch + off + 24u, 0x0021u);
    /*
     * Zero-length FAT files have start cluster 0.  The first write allocates
     * the first cluster, mirrors the FAT entry, and patches this dirent.
     */
    if (fat_write_sector(fs, lba, fs->scratch) < 0) return -1;
    fat_fill_inode(0, 0, FAT32_ATTR_ARCHIVE, lba, off, out);
    return 0;
}

static int fat_mark_dir_slot_deleted(fat32_disk_t *fs, uint32_t lba, uint32_t off) {
    if (!fs || off + 32u > FAT32_SECTOR_SIZE) return -1;
    if (fat_read_sector(fs, lba, fs->scratch) < 0) return -1;
    fs->scratch[off] = 0xE5u;
    return fat_write_sector(fs, lba, fs->scratch);
}

static int fat_unlink(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name) {
    fat32_disk_t *fs = sb ? (fat32_disk_t *)sb->fs_private : 0;
    fat32_dirent_t target;
    uint32_t cluster;
    uint32_t lfn_lba[20];
    uint32_t lfn_off[20];
    uint32_t lfn_count = 0;
    if (!fs || !dir || !name || !name[0]) return -1;
    if ((dir->mode & 0xF000u) != VFS_INODE_DIR) return -1;
    if (fat_dir_iter(fs, dir, 0, name, &target) < 0) return -1;
    cluster = dir->fs_private[0] ? dir->fs_private[0] : fs->root_cluster;
    if (!fat_cluster_in_volume(fs, cluster)) return -1;
    while (fat_cluster_in_volume(fs, cluster)) {
        uint32_t first_lba = fat_cluster_lba(fs, cluster);
        for (uint32_t s = 0; s < fs->sectors_per_cluster; ++s) {
            uint32_t lba = first_lba + s;
            if (fat_read_sector(fs, lba, fs->scratch) < 0) return -1;
            for (uint32_t off = 0; off < FAT32_SECTOR_SIZE; off += 32u) {
                uint8_t *e = fs->scratch + off;
                if (e[0] == 0x00u) return -1;
                if (e[0] == 0xE5u) {
                    lfn_count = 0;
                    continue;
                }
                if (e[11] == FAT32_ATTR_LFN) {
                    if (lfn_count < 20u) {
                        lfn_lba[lfn_count] = lba;
                        lfn_off[lfn_count] = off;
                        lfn_count++;
                    }
                    continue;
                }
                {
                    uint32_t first_cluster = fat_first_cluster(e);
                    /*
                     * Resolve the Linux-visible name once, then delete the
                     * matching physical short entry and any immediately
                     * preceding LFN slots.  This avoids reusing the shared
                     * scratch sector buffer from inside the scan.
                     */
                    if (target.dir_lba == lba && target.dir_off == off) {
                        for (uint32_t i = 0; i < lfn_count; ++i) {
                            if (fat_mark_dir_slot_deleted(fs, lfn_lba[i], lfn_off[i]) < 0) return -1;
                        }
                        if (fat_mark_dir_slot_deleted(fs, lba, off) < 0) return -1;
                        return fat_free_chain(fs, first_cluster);
                    }
                }
                lfn_count = 0;
            }
        }
        if (fat_next_cluster(fs, cluster, &cluster) < 0) return -1;
    }
    return -1;
}

static int fat_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx, char *name_out, vfs_inode_t *inode_out) {
    fat32_disk_t *fs = sb ? (fat32_disk_t *)sb->fs_private : 0;
    fat32_dirent_t de;
    if (!fs || !dir || !name_out || !inode_out) return -1;
    if (fat_dir_iter(fs, dir, idx, 0, &de) < 0) return -1;
    strncpy(name_out, de.name, VFS_NAME_MAX - 1);
    name_out[VFS_NAME_MAX - 1] = 0;
    fat_fill_inode(de.cluster, de.size, de.attr, de.dir_lba, de.dir_off, inode_out);
    return 0;
}

static int fat_statfs(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) {
    fat32_disk_t *fs = sb ? (fat32_disk_t *)sb->fs_private : 0;
    if (!fs || !total_kb || !used_kb) return -1;
    *total_kb = fs->total_sectors / 2u;
    *used_kb = *total_kb;
    return 0;
}

static filesystem_ops_t g_fat_disk_ops = {
    .lookup = fat_lookup,
    .read = fat_read,
    .write = fat_write,
    .create = fat_create,
    .unlink = fat_unlink,
    .truncate = fat_truncate,
    .readdir = fat_readdir,
    .statfs = fat_statfs,
};

static int fat_mount_disk_common(block_device_t *bdev, const char *dev, const char *target) {
    fat32_disk_t *fs;
    vfs_superblock_t sb;
    const uint8_t *b;
    uint16_t bytes_per_sector;
    uint32_t total16;
    uint32_t total32;
    uint32_t fatsz16;
    uint32_t fatsz32;

    if (!bdev || !target) return -1;
    if (g_fat32_mount_count >= FAT32_MAX_MOUNTS) return -1;
    if (bdev->sector_size != FAT32_SECTOR_SIZE) return -1;
    fs = &g_fat32_mounts[g_fat32_mount_count];
    memset(fs, 0, sizeof(*fs));
    fs->bdev = bdev;
    if (fat_read_sector(fs, 0, fs->scratch) < 0) return -1;
    b = fs->scratch;
    bytes_per_sector = le16(b + 11);
    total16 = le16(b + 19);
    total32 = le32(b + 32);
    fatsz16 = le16(b + 22);
    fatsz32 = le32(b + 36);
    if (bytes_per_sector != FAT32_SECTOR_SIZE || b[13] == 0 || b[16] == 0) return -1;
    if (b[510] != 0x55u || b[511] != 0xAAu) return -1;
    if (fatsz16 != 0 || fatsz32 == 0) return -1;
    if (memcmp(b + 82, "FAT32", 5) != 0) {
        printf("[fat32] missing FAT32 signature on %s\n", dev ? dev : bdev->name);
        return -1;
    }
    fs->bytes_per_sector = bytes_per_sector;
    fs->sectors_per_cluster = b[13];
    fs->reserved_sectors = le16(b + 14);
    fs->fat_count = b[16];
    fs->fat_size_sectors = fatsz32;
    fs->root_cluster = le32(b + 44);
    fs->total_sectors = total16 ? total16 : total32;
    fs->fat_lba = fs->reserved_sectors;
    fs->data_lba = fs->reserved_sectors + fs->fat_count * fs->fat_size_sectors;
    fs->cluster_count = (fs->total_sectors - fs->data_lba) / fs->sectors_per_cluster;
    if (!fat_valid_cluster(fs->root_cluster) || fs->total_sectors <= fs->data_lba) return -1;

    memset(&sb, 0, sizeof(sb));
    strcpy(sb.fs_name, "fat32");
    strncpy(sb.dev_name, dev ? dev : bdev->name, sizeof(sb.dev_name) - 1);
    strncpy(sb.mountpoint, target, sizeof(sb.mountpoint) - 1);
    fat_fill_inode(fs->root_cluster, 0, FAT32_ATTR_DIRECTORY, 0, 0, &sb.root);
    sb.ops = &g_fat_disk_ops;
    sb.fs_private = fs;
    if (vfs_add_superblock(&sb) < 0) return -1;
    g_fat32_mount_count++;
    printf("[fat32] mounted %s on %s sectors=%u cluster=%u\n",
           sb.dev_name, target, fs->total_sectors, fs->sectors_per_cluster);
    return 0;
}

static int f_lookup(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    (void)sb;
    fat32_node_t *base = dir->ino ? (fat32_node_t *)(uintptr_t)dir->ino : fat32_get_root();
    fat32_node_t *n = fat32_open(name, base);
    if (!n) return -1;
    out->ino = (uint32_t)(uintptr_t)n;
    out->mode = (n->type == FAT32_TYPE_DIR ? VFS_INODE_DIR : VFS_INODE_FILE) | 0777;
    out->size = n->size;
    return 0;
}

static int f_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    (void)sb; (void)off;
    fat32_node_t *n = (fat32_node_t *)(uintptr_t)inode->ino;
    return fat32_read(n, buf, (int)len);
}

static int f_write(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, const void *buf, uint32_t len) {
    (void)sb; (void)off;
    fat32_node_t *n = (fat32_node_t *)(uintptr_t)inode->ino;
    if (!n || n->type != FAT32_TYPE_FILE) return -1;
    if (len > FAT32_CONTENT_MAX) len = FAT32_CONTENT_MAX;
    memcpy(n->content, buf, len);
    n->content[len] = 0;
    n->size = len;
    return (int)len;
}

static int f_create(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    (void)sb; (void)mode;
    fat32_node_t *d = (fat32_node_t *)(uintptr_t)dir->ino;
    if (fat32_touch(name, d) < 0) return -1;
    fat32_node_t *n = fat32_open(name, d);
    out->ino = (uint32_t)(uintptr_t)n; out->mode = VFS_INODE_FILE | 0777; out->size = 0;
    return 0;
}

static int f_mkdir(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    (void)sb; (void)mode;
    fat32_node_t *d = (fat32_node_t *)(uintptr_t)dir->ino;
    if (fat32_mkdir(name, d) < 0) return -1;
    fat32_node_t *n = fat32_open(name, d);
    out->ino = (uint32_t)(uintptr_t)n; out->mode = VFS_INODE_DIR | 0777; out->size = 0;
    return 0;
}

static int f_unlink(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name) { (void)sb; return fat32_rm(name, (fat32_node_t *)(uintptr_t)dir->ino); }
static int f_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx, char *name_out, vfs_inode_t *inode_out) { (void)sb; (void)dir; (void)idx; (void)name_out; (void)inode_out; return -1; }
static int f_statfs(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) { (void)sb; *total_kb = 1024; *used_kb = 128; return 0; }

static filesystem_ops_t g_mem_ops = {
    .lookup = f_lookup,
    .read = f_read,
    .write = f_write,
    .create = f_create,
    .mkdir = f_mkdir,
    .unlink = f_unlink,
    .readdir = f_readdir,
    .statfs = f_statfs,
};

static int fat32_mount_mem(const char *dev, const char *target) {
    (void)dev;
    fat32_init();
    vfs_superblock_t sb;
    memset(&sb, 0, sizeof(sb));
    strcpy(sb.fs_name, "fat32");
    strcpy(sb.dev_name, "memfs");
    strcpy(sb.mountpoint, target);
    sb.root.ino = (uint32_t)(uintptr_t)fat32_get_root();
    sb.root.mode = VFS_INODE_DIR | 0777;
    sb.ops = &g_mem_ops;
    return vfs_add_superblock(&sb);
}

int fat32_mount(const char *dev, const char *target) {
    block_device_t *b;
    const char *name;
    if (!dev || !target) return -1;
    if (strcmp(dev, "mem") == 0) return fat32_mount_mem(dev, target);
    name = (strncmp(dev, "/dev/", 5) == 0) ? dev + 5 : dev;
    b = block_find(name);
    if (!b) return -1;
    return fat_mount_disk_common(b, dev, target);
}

int fat32_mount_block(block_device_t *bdev, const char *target) {
    if (!bdev) return -1;
    return fat_mount_disk_common(bdev, bdev->name, target);
}
