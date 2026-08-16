/*
 * EdgeOS UDF filesystem support.
 *
 * Copyright (c) EdgeOS Contributors.
 * Licensed under the Mozilla Public License, v. 2.0.
 */
#include "udf/udf.h"
#include "vfs/vfs.h"
#include "block/block.h"
#include "stdio.h"
#include "string.h"

#define UDF_SECTOR_SIZE 2048u
#define UDF_MAX_MOUNTS 4
#define UDF_VRS_START 16u
#define UDF_ANCHOR_SECTOR 256u

#define UDF_TAG_PVD 1u
#define UDF_TAG_ANCHOR 2u
#define UDF_TAG_PARTITION 5u
#define UDF_TAG_LVD 6u
#define UDF_TAG_TERMINATING 8u
#define UDF_TAG_FID 257u
#define UDF_TAG_FILE_ENTRY 261u
#define UDF_TAG_EXT_FILE_ENTRY 266u
#define UDF_TAG_FILE_SET 256u

#define UDF_FILE_TYPE_DIRECTORY 4u
#define UDF_FILE_TYPE_REGULAR 5u

#define UDF_ICB_AD_SHORT 0u
#define UDF_ICB_AD_LONG 1u
#define UDF_ICB_AD_INLINE 3u

typedef struct {
    uint32_t len;
    uint32_t loc;
} udf_extent_t;

typedef struct {
    uint32_t lbn;
    uint16_t part;
} udf_lb_addr_t;

typedef struct {
    uint32_t len;
    udf_lb_addr_t loc;
} udf_long_ad_t;

typedef struct {
    uint32_t lbn;
    uint32_t len;
} udf_short_ad_t;

typedef struct {
    block_device_t *bdev;
    uint32_t logical_block_size;
    uint32_t sectors_per_block;
    uint32_t partition_start;
    uint32_t partition_len;
    uint16_t partition_number;
    uint32_t root_lbn;
    uint32_t root_len;
    uint8_t scratch[UDF_SECTOR_SIZE];
    uint8_t scratch2[UDF_SECTOR_SIZE];
} udf_fs_t;

typedef struct {
    uint32_t lbn;
    uint32_t size;
    uint8_t file_type;
    uint8_t ad_type;
} udf_node_t;

typedef struct {
    udf_node_t node;
    char name[VFS_NAME_MAX];
} udf_dirent_t;

static udf_fs_t g_udf_mounts[UDF_MAX_MOUNTS];
static int g_udf_mount_count;

static uint16_t udf_le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t udf_le32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t udf_le64(const uint8_t *p) {
    return (uint64_t)udf_le32(p) | ((uint64_t)udf_le32(p + 4) << 32);
}

static uint16_t udf_tag_id(const uint8_t *p) {
    return udf_le16(p);
}

static uint32_t udf_ad_len(uint32_t raw) {
    return raw & 0x3FFFFFFFu;
}

static int udf_read_sector(udf_fs_t *fs, uint32_t sector, void *out) {
    uint32_t cnt;
    uint32_t lba;
    if (!fs || !fs->bdev || !out || fs->bdev->sector_size == 0) return -1;
    if (UDF_SECTOR_SIZE % fs->bdev->sector_size != 0) return -1;
    cnt = UDF_SECTOR_SIZE / fs->bdev->sector_size;
    lba = sector * cnt;
    return block_read_sectors(fs->bdev, lba, cnt, out);
}

static int udf_read_logical_block(udf_fs_t *fs, uint32_t lbn, void *out) {
    if (!fs || !out) return -1;
    return udf_read_sector(fs, fs->partition_start + lbn * fs->sectors_per_block, out);
}

static int udf_read_partition_bytes(udf_fs_t *fs, uint32_t byte_off, void *buf, uint32_t len) {
    uint8_t *dst = (uint8_t *)buf;
    uint32_t done = 0;
    if (!fs || !buf) return -1;
    while (done < len) {
        uint32_t pos = byte_off + done;
        uint32_t sector = fs->partition_start + pos / UDF_SECTOR_SIZE;
        uint32_t in_sector = pos % UDF_SECTOR_SIZE;
        uint32_t chunk = UDF_SECTOR_SIZE - in_sector;
        if (chunk > len - done) chunk = len - done;
        if (udf_read_sector(fs, sector, fs->scratch2) < 0) return -1;
        memcpy(dst + done, fs->scratch2 + in_sector, chunk);
        done += chunk;
    }
    return (int)done;
}

static int udf_read_extent_bytes(udf_fs_t *fs, uint32_t lbn, uint32_t byte_off, void *buf, uint32_t len) {
    uint32_t base;
    if (!fs || !buf) return -1;
    base = lbn * fs->logical_block_size + byte_off;
    return udf_read_partition_bytes(fs, base, buf, len);
}

static int udf_vrs_valid(udf_fs_t *fs) {
    for (uint32_t s = UDF_VRS_START; s < UDF_VRS_START + 16u; ++s) {
        if (udf_read_sector(fs, s, fs->scratch) < 0) return -1;
        if (memcmp(fs->scratch + 1, "NSR02", 5) == 0 ||
            memcmp(fs->scratch + 1, "NSR03", 5) == 0) {
            return 0;
        }
    }
    return -1;
}

static int udf_read_anchor(udf_fs_t *fs, udf_extent_t *main_vds) {
    if (!fs || !main_vds) return -1;
    if (udf_read_sector(fs, UDF_ANCHOR_SECTOR, fs->scratch) < 0) return -1;
    if (udf_tag_id(fs->scratch) != UDF_TAG_ANCHOR) return -1;
    main_vds->len = udf_le32(fs->scratch + 16);
    main_vds->loc = udf_le32(fs->scratch + 20);
    if (main_vds->len == 0) return -1;
    return 0;
}

static udf_long_ad_t udf_parse_long_ad(const uint8_t *p) {
    udf_long_ad_t ad;
    ad.len = udf_ad_len(udf_le32(p));
    ad.loc.lbn = udf_le32(p + 4);
    ad.loc.part = udf_le16(p + 8);
    return ad;
}

static int udf_parse_descriptor_sequence(udf_fs_t *fs, const udf_extent_t *vds, udf_long_ad_t *fsd_ad) {
    uint32_t count;
    uint8_t have_part = 0;
    uint8_t have_lvd = 0;

    if (!fs || !vds || !fsd_ad) return -1;
    count = vds->len / UDF_SECTOR_SIZE;
    if (count == 0) return -1;
    for (uint32_t i = 0; i < count; ++i) {
        uint16_t tag;
        if (udf_read_sector(fs, vds->loc + i, fs->scratch) < 0) return -1;
        tag = udf_tag_id(fs->scratch);
        if (tag == UDF_TAG_TERMINATING) break;
        if (tag == UDF_TAG_PARTITION) {
            fs->partition_number = udf_le16(fs->scratch + 22);
            fs->partition_start = udf_le32(fs->scratch + 188);
            fs->partition_len = udf_le32(fs->scratch + 192);
            have_part = 1;
        } else if (tag == UDF_TAG_LVD) {
            fs->logical_block_size = udf_le32(fs->scratch + 212);
            *fsd_ad = udf_parse_long_ad(fs->scratch + 248);
            have_lvd = 1;
        }
    }
    if (!have_part || !have_lvd) return -1;
    if (fs->logical_block_size != UDF_SECTOR_SIZE) {
        printf("[udf] unsupported logical block size %u\n", fs->logical_block_size);
        return -1;
    }
    fs->sectors_per_block = 1;
    if (fsd_ad->loc.part != fs->partition_number || fsd_ad->len == 0) return -1;
    return 0;
}

static int udf_decode_name(const uint8_t *src, uint8_t len, char *out) {
    uint32_t pos = 0;
    if (!src || !out) return -1;
    out[0] = 0;
    if (len == 0) return 0;
    /*
     * UDF stores file identifiers as OSTA compressed Unicode.  Compression
     * ID 8 is single-byte Unicode and ID 16 is big-endian 16-bit Unicode.
     * Keep non-ASCII replacement conservative; the VFS path layer is byte
     * oriented today and Linux userspace handles '?' better than malformed
     * UTF-8 from a kernel parser.
     */
    if (src[0] == 8u) {
        for (uint32_t i = 1; i < len && pos + 1 < VFS_NAME_MAX; ++i) {
            uint8_t c = src[i];
            out[pos++] = (c < 0x80u) ? (char)c : '?';
        }
    } else if (src[0] == 16u) {
        for (uint32_t i = 1; i + 1 < len && pos + 1 < VFS_NAME_MAX; i += 2) {
            uint16_t c = (uint16_t)(((uint16_t)src[i] << 8) | src[i + 1]);
            out[pos++] = (c < 0x80u) ? (char)c : '?';
        }
    } else {
        return -1;
    }
    out[pos] = 0;
    return 0;
}

static int udf_name_eq(const char *a, const char *b) {
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

static int udf_load_node(udf_fs_t *fs, uint32_t lbn, udf_node_t *node) {
    uint16_t tag;
    uint8_t file_type;
    uint16_t flags;
    uint32_t info_off;

    if (!fs || !node) return -1;
    if (udf_read_logical_block(fs, lbn, fs->scratch) < 0) return -1;
    tag = udf_tag_id(fs->scratch);
    if (tag != UDF_TAG_FILE_ENTRY && tag != UDF_TAG_EXT_FILE_ENTRY) return -1;
    file_type = fs->scratch[27];
    flags = udf_le16(fs->scratch + 34);
    info_off = (tag == UDF_TAG_EXT_FILE_ENTRY) ? 64u : 56u;
    memset(node, 0, sizeof(*node));
    node->lbn = lbn;
    node->size = (uint32_t)udf_le64(fs->scratch + info_off);
    node->file_type = file_type;
    node->ad_type = (uint8_t)(flags & 0x0007u);
    return 0;
}

static void udf_fill_inode(const udf_node_t *node, vfs_inode_t *out) {
    uint16_t kind;
    if (!node || !out) return;
    memset(out, 0, sizeof(*out));
    kind = (node->file_type == UDF_FILE_TYPE_DIRECTORY) ? VFS_INODE_DIR : VFS_INODE_FILE;
    out->ino = node->lbn ? node->lbn : 2u;
    out->mode = kind | 0555u;
    out->uid = 0;
    out->gid = 0;
    out->size = node->size;
    out->fs_private[0] = node->lbn;
    out->fs_private[1] = node->size;
    out->fs_private[2] = node->file_type;
    out->fs_private[3] = node->ad_type;
}

static int udf_node_from_inode(const vfs_inode_t *inode, udf_node_t *node) {
    if (!inode || !node) return -1;
    node->lbn = inode->fs_private[0];
    node->size = inode->fs_private[1];
    node->file_type = (uint8_t)inode->fs_private[2];
    node->ad_type = (uint8_t)inode->fs_private[3];
    return 0;
}

static int udf_node_alloc_info(udf_fs_t *fs, const udf_node_t *node, uint32_t *ad_off, uint32_t *ad_len) {
    uint16_t tag;
    uint32_t lea;
    uint32_t lad;
    uint32_t base;

    if (!fs || !node || !ad_off || !ad_len) return -1;
    if (udf_read_logical_block(fs, node->lbn, fs->scratch) < 0) return -1;
    tag = udf_tag_id(fs->scratch);
    if (tag == UDF_TAG_FILE_ENTRY) {
        lea = udf_le32(fs->scratch + 168);
        lad = udf_le32(fs->scratch + 172);
        base = 176u;
    } else if (tag == UDF_TAG_EXT_FILE_ENTRY) {
        lea = udf_le32(fs->scratch + 192);
        lad = udf_le32(fs->scratch + 196);
        base = 200u;
    } else {
        return -1;
    }
    if (base + lea + lad > fs->logical_block_size) return -1;
    *ad_off = base + lea;
    *ad_len = lad;
    return 0;
}

static int udf_read_node_bytes(udf_fs_t *fs, const udf_node_t *node, uint32_t off, void *buf, uint32_t len) {
    uint8_t *dst = (uint8_t *)buf;
    uint32_t done = 0;
    uint32_t ad_off;
    uint32_t ad_len;
    uint32_t pos;

    if (!fs || !node || !buf) return -1;
    if (off >= node->size) return 0;
    if (len > node->size - off) len = node->size - off;
    if (len == 0) return 0;
    if (udf_node_alloc_info(fs, node, &ad_off, &ad_len) < 0) return -1;
    if (node->ad_type == UDF_ICB_AD_INLINE) {
        if (off + len > ad_len) return -1;
        memcpy(dst, fs->scratch + ad_off + off, len);
        return (int)len;
    }
    pos = 0;
    while (pos < ad_len && done < len) {
        uint32_t extent_len;
        uint32_t extent_lbn;
        uint32_t in_extent;
        uint32_t chunk;
        if (node->ad_type == UDF_ICB_AD_SHORT) {
            if (pos + 8u > ad_len) return -1;
            extent_len = udf_ad_len(udf_le32(fs->scratch + ad_off + pos));
            extent_lbn = udf_le32(fs->scratch + ad_off + pos + 4u);
            pos += 8u;
        } else if (node->ad_type == UDF_ICB_AD_LONG) {
            udf_long_ad_t ad;
            if (pos + 16u > ad_len) return -1;
            ad = udf_parse_long_ad(fs->scratch + ad_off + pos);
            if (ad.loc.part != fs->partition_number) return -1;
            extent_len = ad.len;
            extent_lbn = ad.loc.lbn;
            pos += 16u;
        } else {
            return -1;
        }
        if (extent_len == 0) continue;
        if (off >= extent_len) {
            off -= extent_len;
            continue;
        }
        in_extent = off;
        chunk = extent_len - in_extent;
        if (chunk > len - done) chunk = len - done;
        if (udf_read_extent_bytes(fs, extent_lbn, in_extent, dst + done, chunk) < 0) return -1;
        done += chunk;
        off = 0;
    }
    return done == len ? (int)done : -1;
}

static int udf_parse_fid(udf_fs_t *fs, const uint8_t *p, uint32_t remain, udf_dirent_t *out) {
    uint16_t tag;
    uint8_t chars;
    uint16_t liu;
    udf_long_ad_t icb;
    uint32_t name_off;

    if (!fs || !p || !out || remain < 38u) return -1;
    tag = udf_tag_id(p);
    if (tag != UDF_TAG_FID) return -1;
    chars = p[18];
    (void)chars;
    if (p[19] == 0) return 1;
    icb = udf_parse_long_ad(p + 20);
    liu = udf_le16(p + 36);
    name_off = 38u + liu;
    if (name_off + p[19] > remain) return -1;
    if (icb.loc.part != fs->partition_number || icb.len == 0) return -1;
    if (udf_decode_name(p + name_off, p[19], out->name) < 0) return -1;
    if (out->name[0] == 0) return 1;
    if (udf_load_node(fs, icb.loc.lbn, &out->node) < 0) return -1;
    return 0;
}

static int udf_fid_len(const uint8_t *p, uint32_t remain, uint32_t *len_out) {
    uint16_t liu;
    uint32_t len;
    if (!p || !len_out || remain < 38u) return -1;
    liu = udf_le16(p + 36);
    len = 38u + liu + p[19];
    len = (len + 3u) & ~3u;
    if (len == 0 || len > remain) return -1;
    *len_out = len;
    return 0;
}

static int udf_dir_iter(udf_fs_t *fs, const udf_node_t *dir, uint32_t want_idx,
                        const char *want_name, udf_dirent_t *found) {
    uint32_t off = 0;
    uint32_t idx = 0;

    if (!fs || !dir || dir->file_type != UDF_FILE_TYPE_DIRECTORY) return -1;
    while (off < dir->size) {
        uint32_t chunk = dir->size - off;
        uint32_t fid_len;
        udf_dirent_t de;
        int rc;
        if (chunk > UDF_SECTOR_SIZE) chunk = UDF_SECTOR_SIZE;
        if (udf_read_node_bytes(fs, dir, off, fs->scratch2, chunk) < 0) return -1;
        if (udf_fid_len(fs->scratch2, chunk, &fid_len) < 0) return -1;
        rc = udf_parse_fid(fs, fs->scratch2, chunk, &de);
        if (rc < 0) return -1;
        if (rc == 0) {
            if (want_name) {
                if (udf_name_eq(de.name, want_name)) {
                    if (found) *found = de;
                    return 0;
                }
            } else if (idx == want_idx) {
                if (found) *found = de;
                return 0;
            }
            idx++;
        }
        off += fid_len;
    }
    return -1;
}

static int udf_lookup(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    udf_fs_t *fs = sb ? (udf_fs_t *)sb->fs_private : 0;
    udf_node_t dnode;
    udf_dirent_t de;
    if (!fs || !dir || !name || !out) return -1;
    if (strcmp(name, ".") == 0) {
        *out = *dir;
        return 0;
    }
    if (udf_node_from_inode(dir, &dnode) < 0) return -1;
    if (udf_dir_iter(fs, &dnode, 0, name, &de) < 0) return -1;
    udf_fill_inode(&de.node, out);
    return 0;
}

static int udf_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    udf_fs_t *fs = sb ? (udf_fs_t *)sb->fs_private : 0;
    udf_node_t node;
    if (!fs || !inode || !buf) return -1;
    if ((inode->mode & 0xF000u) != VFS_INODE_FILE) return -1;
    if (udf_node_from_inode(inode, &node) < 0) return -1;
    return udf_read_node_bytes(fs, &node, off, buf, len);
}

static int udf_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx, char *name_out, vfs_inode_t *inode_out) {
    udf_fs_t *fs = sb ? (udf_fs_t *)sb->fs_private : 0;
    udf_node_t dnode;
    udf_dirent_t de;
    if (!fs || !dir || !name_out || !inode_out) return -1;
    if (udf_node_from_inode(dir, &dnode) < 0) return -1;
    if (udf_dir_iter(fs, &dnode, idx, 0, &de) < 0) return -1;
    strncpy(name_out, de.name, VFS_NAME_MAX - 1);
    name_out[VFS_NAME_MAX - 1] = 0;
    udf_fill_inode(&de.node, inode_out);
    return 0;
}

static int udf_statfs(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) {
    udf_fs_t *fs = sb ? (udf_fs_t *)sb->fs_private : 0;
    if (!fs || !total_kb || !used_kb) return -1;
    *total_kb = (fs->partition_len * fs->logical_block_size) / 1024u;
    *used_kb = *total_kb;
    return 0;
}

static filesystem_ops_t g_udf_ops = {
    .lookup = udf_lookup,
    .read = udf_read,
    .readdir = udf_readdir,
    .statfs = udf_statfs,
};

static int udf_mount_common(block_device_t *bdev, const char *dev, const char *target) {
    udf_fs_t *fs;
    udf_extent_t vds;
    udf_long_ad_t fsd_ad;
    udf_long_ad_t root_ad;
    udf_node_t root;
    vfs_superblock_t sb;

    if (!bdev || !target) return -1;
    if (g_udf_mount_count >= UDF_MAX_MOUNTS) return -1;
    fs = &g_udf_mounts[g_udf_mount_count];
    memset(fs, 0, sizeof(*fs));
    fs->bdev = bdev;
    if (udf_vrs_valid(fs) < 0) return -1;
    if (udf_read_anchor(fs, &vds) < 0) return -1;
    if (udf_parse_descriptor_sequence(fs, &vds, &fsd_ad) < 0) return -1;
    if (udf_read_logical_block(fs, fsd_ad.loc.lbn, fs->scratch) < 0) return -1;
    if (udf_tag_id(fs->scratch) != UDF_TAG_FILE_SET) return -1;
    root_ad = udf_parse_long_ad(fs->scratch + 400);
    if (root_ad.loc.part != fs->partition_number || root_ad.len == 0) return -1;
    if (udf_load_node(fs, root_ad.loc.lbn, &root) < 0) return -1;
    if (root.file_type != UDF_FILE_TYPE_DIRECTORY) return -1;
    fs->root_lbn = root.lbn;
    fs->root_len = root.size;

    memset(&sb, 0, sizeof(sb));
    strcpy(sb.fs_name, "udf");
    strncpy(sb.dev_name, dev ? dev : bdev->name, sizeof(sb.dev_name) - 1);
    strncpy(sb.mountpoint, target, sizeof(sb.mountpoint) - 1);
    udf_fill_inode(&root, &sb.root);
    sb.ops = &g_udf_ops;
    sb.fs_private = fs;
    if (vfs_add_superblock(&sb) < 0) return -1;
    g_udf_mount_count++;
    printf("[udf] mounted %s on %s blocks=%u part_start=%u\n",
           sb.dev_name, target, fs->partition_len, fs->partition_start);
    return 0;
}

int udf_mount(const char *dev, const char *target) {
    block_device_t *b;
    if (!dev || !target) return -1;
    b = block_find(dev[0] == '/' ? dev + 5 : dev);
    if (!b) return -1;
    return udf_mount_common(b, dev, target);
}

int udf_mount_block(block_device_t *bdev, const char *target) {
    if (!bdev) return -1;
    return udf_mount_common(bdev, bdev->name, target);
}
