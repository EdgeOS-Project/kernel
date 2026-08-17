/*
 * EdgeOS NTFS filesystem support.
 *
 * Copyright (c) EdgeOS Contributors.
 * Licensed under the Mozilla Public License, v. 2.0.
 */
#include "ntfs/ntfs.h"
#include "vfs/vfs.h"
#include "block/block.h"
#include "stdio.h"
#include "string.h"

#define NTFS_MAX_MOUNTS 4u
#define NTFS_MAX_RUNS 32u
#define NTFS_MAX_RECORD 4096u
#define NTFS_ATTR_STANDARD_INFORMATION 0x10u
#define NTFS_ATTR_FILE_NAME 0x30u
#define NTFS_ATTR_DATA 0x80u
#define NTFS_ATTR_INDEX_ROOT 0x90u
#define NTFS_ATTR_INDEX_ALLOCATION 0xA0u
#define NTFS_ATTR_END 0xFFFFFFFFu
#define NTFS_FILE_DIRECTORY 0x02u
#define NTFS_INDEX_ENTRY_LAST 0x02u

typedef struct {
    uint64_t vcn;
    int64_t lcn;
    uint64_t len;
} ntfs_run_t;

typedef struct {
    block_device_t *bdev;
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t bytes_per_cluster;
    uint32_t record_size;
    uint32_t index_block_size;
    uint64_t total_sectors;
    int64_t mft_lcn;
    ntfs_run_t mft_runs[NTFS_MAX_RUNS];
    uint32_t mft_run_count;
    uint8_t record[NTFS_MAX_RECORD];
    uint8_t index_block[4096];
    uint8_t scratch[4096];
} ntfs_fs_t;

typedef struct {
    uint64_t mft_ref;
    uint64_t size;
    uint16_t flags;
    char name[VFS_NAME_MAX];
} ntfs_dirent_t;

typedef struct {
    uint64_t mft_ref;
    uint64_t size;
    uint16_t flags;
} ntfs_node_t;

static ntfs_fs_t g_ntfs_mounts[NTFS_MAX_MOUNTS];
static uint32_t g_ntfs_mount_count;

static int ntfs_read_nonresident(ntfs_fs_t *fs, uint8_t *rec, uint8_t *attr,
                                 uint64_t off, void *buf, uint32_t len);

static uint16_t ntfs_le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t ntfs_le32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t ntfs_le64(const uint8_t *p) {
    return (uint64_t)ntfs_le32(p) | ((uint64_t)ntfs_le32(p + 4) << 32);
}

static int64_t ntfs_sign_extend(uint64_t v, uint32_t bytes) {
    uint64_t sign;
    if (bytes == 0 || bytes >= 8u) return (int64_t)v;
    sign = 1ull << (bytes * 8u - 1u);
    if (v & sign) v |= (~0ull) << (bytes * 8u);
    return (int64_t)v;
}

static int ntfs_read_sectors(ntfs_fs_t *fs, uint64_t lba, uint32_t count, void *out) {
    if (!fs || !fs->bdev || !out || count == 0) return -1;
    if (fs->bdev->sector_size != fs->bytes_per_sector) return -1;
    if (lba > 0xFFFFFFFFull) return -1;
    return block_read_sectors(fs->bdev, (uint32_t)lba, count, out);
}

static int ntfs_read_bytes(ntfs_fs_t *fs, uint64_t byte_off, void *buf, uint32_t len) {
    uint8_t *dst = (uint8_t *)buf;
    uint32_t done = 0;
    if (!fs || !buf) return -1;
    while (done < len) {
        uint64_t pos = byte_off + done;
        uint64_t lba = pos / fs->bytes_per_sector;
        uint32_t in_sector = (uint32_t)(pos % fs->bytes_per_sector);
        uint32_t chunk = fs->bytes_per_sector - in_sector;
        if (chunk > len - done) chunk = len - done;
        if (ntfs_read_sectors(fs, lba, 1, fs->scratch) < 0) return -1;
        memcpy(dst + done, fs->scratch + in_sector, chunk);
        done += chunk;
    }
    return (int)done;
}

static int ntfs_apply_fixup_sized(ntfs_fs_t *fs, uint8_t *rec, uint32_t bytes, const char *magic) {
    uint16_t usa_off;
    uint16_t usa_count;
    uint16_t usn;
    uint32_t sectors;

    if (!fs || !rec || !magic || bytes < fs->bytes_per_sector) return -1;
    if (memcmp(rec, magic, 4) != 0) return -1;
    usa_off = ntfs_le16(rec + 4);
    usa_count = ntfs_le16(rec + 6);
    sectors = bytes / fs->bytes_per_sector;
    if (usa_count != sectors + 1u || usa_off + usa_count * 2u > bytes) return -1;
    usn = ntfs_le16(rec + usa_off);
    for (uint32_t i = 0; i < sectors; ++i) {
        uint32_t fix_off = (i + 1u) * fs->bytes_per_sector - 2u;
        if (ntfs_le16(rec + fix_off) != usn) return -1;
        memcpy(rec + fix_off, rec + usa_off + 2u + i * 2u, 2u);
    }
    return 0;
}

static int ntfs_apply_fixup(ntfs_fs_t *fs, uint8_t *rec) {
    return ntfs_apply_fixup_sized(fs, rec, fs->record_size, "FILE");
}

static int ntfs_decode_runlist(const uint8_t *p, uint32_t max, ntfs_run_t *runs, uint32_t *count_io) {
    uint32_t off = 0;
    uint64_t vcn = 0;
    int64_t lcn = 0;
    uint32_t count = 0;

    if (!p || !runs || !count_io) return -1;
    while (off < max && p[off] != 0) {
        uint8_t h = p[off++];
        uint32_t len_bytes = h & 0x0Fu;
        uint32_t off_bytes = h >> 4;
        uint64_t run_len = 0;
        uint64_t run_delta = 0;
        if (len_bytes == 0 || len_bytes > 8u || off_bytes > 8u) return -1;
        if (off + len_bytes + off_bytes > max) return -1;
        for (uint32_t i = 0; i < len_bytes; ++i) run_len |= (uint64_t)p[off + i] << (i * 8u);
        off += len_bytes;
        for (uint32_t i = 0; i < off_bytes; ++i) run_delta |= (uint64_t)p[off + i] << (i * 8u);
        off += off_bytes;
        if (count >= *count_io || run_len == 0) return -1;
        lcn += ntfs_sign_extend(run_delta, off_bytes);
        runs[count].vcn = vcn;
        runs[count].lcn = lcn;
        runs[count].len = run_len;
        count++;
        vcn += run_len;
    }
    *count_io = count;
    return 0;
}

static int ntfs_read_mft_record(ntfs_fs_t *fs, uint64_t mft_ref, uint8_t *out) {
    uint64_t rec_byte = mft_ref * fs->record_size;
    uint64_t rec_cluster = rec_byte / fs->bytes_per_cluster;
    uint64_t in_cluster = rec_byte % fs->bytes_per_cluster;
    uint64_t abs_byte = 0;

    if (!fs || !out || fs->record_size > NTFS_MAX_RECORD) return -1;
    for (uint32_t i = 0; i < fs->mft_run_count; ++i) {
        ntfs_run_t *r = &fs->mft_runs[i];
        if (rec_cluster >= r->vcn && rec_cluster < r->vcn + r->len) {
            abs_byte = ((uint64_t)(r->lcn + (int64_t)(rec_cluster - r->vcn)) *
                        fs->bytes_per_cluster) + in_cluster;
            break;
        }
    }
    if (abs_byte == 0 && mft_ref != 0) return -1;
    if (fs->mft_run_count == 0 && mft_ref == 0) {
        abs_byte = (uint64_t)fs->mft_lcn * fs->bytes_per_cluster;
    }
    if (ntfs_read_bytes(fs, abs_byte, out, fs->record_size) < 0) return -1;
    return ntfs_apply_fixup(fs, out);
}

static uint8_t *ntfs_first_attr(ntfs_fs_t *fs, uint8_t *rec) {
    uint16_t off;
    if (!fs || !rec) return 0;
    off = ntfs_le16(rec + 20);
    if (off >= fs->record_size) return 0;
    return rec + off;
}

static uint8_t *ntfs_next_attr(ntfs_fs_t *fs, uint8_t *rec, uint8_t *attr) {
    uint32_t len;
    if (!fs || !rec || !attr) return 0;
    if (attr + 8 > rec + fs->record_size) return 0;
    if (ntfs_le32(attr) == NTFS_ATTR_END) return 0;
    len = ntfs_le32(attr + 4);
    if (len < 16u || attr + len > rec + fs->record_size) return 0;
    attr += len;
    if (attr + 8 > rec + fs->record_size) return 0;
    return attr;
}

static uint8_t *ntfs_find_attr(ntfs_fs_t *fs, uint8_t *rec, uint32_t type) {
    for (uint8_t *a = ntfs_first_attr(fs, rec); a; a = ntfs_next_attr(fs, rec, a)) {
        if (ntfs_le32(a) == NTFS_ATTR_END) break;
        if (ntfs_le32(a) == type) return a;
    }
    return 0;
}

static int ntfs_resident_value(ntfs_fs_t *fs, uint8_t *rec, uint8_t *attr, uint8_t **val, uint32_t *len) {
    uint32_t value_len;
    uint16_t value_off;
    if (!fs || !rec || !attr || !val || !len || attr[8] != 0) return -1;
    value_len = ntfs_le32(attr + 16);
    value_off = ntfs_le16(attr + 20);
    if (attr + value_off + value_len > rec + fs->record_size) return -1;
    *val = attr + value_off;
    *len = value_len;
    return 0;
}

static void ntfs_copy_name(const uint8_t *name_utf16, uint8_t name_len, char *out) {
    uint32_t pos = 0;
    if (!out) return;
    for (uint32_t i = 0; i < name_len && pos + 1u < VFS_NAME_MAX; ++i) {
        uint16_t ch = ntfs_le16(name_utf16 + i * 2u);
        out[pos++] = (ch < 0x80u) ? (char)ch : '?';
    }
    out[pos] = 0;
}

static int ntfs_name_eq(const char *a, const char *b) {
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

static int ntfs_parse_index_entry(const uint8_t *ie, uint32_t remain, ntfs_dirent_t *out) {
    uint16_t len;
    uint16_t stream_len;
    const uint8_t *fn;
    uint8_t name_len;
    uint8_t name_space;

    if (!ie || !out || remain < 16u) return -1;
    len = ntfs_le16(ie + 8);
    stream_len = ntfs_le16(ie + 10);
    if (len < 16u || len > remain) return -1;
    if (ntfs_le16(ie + 12) & NTFS_INDEX_ENTRY_LAST) return 1;
    if (stream_len < 66u || 16u + stream_len > len) return -1;
    fn = ie + 16;
    name_len = fn[64];
    name_space = fn[65];
    if (66u + (uint32_t)name_len * 2u > stream_len) return -1;
    if (name_space == 2u) return 1; /* DOS-only alias; prefer Win32 names. */
    memset(out, 0, sizeof(*out));
    out->mft_ref = ntfs_le64(ie) & 0x0000FFFFFFFFFFFFull;
    out->size = ntfs_le64(fn + 48);
    out->flags = (uint16_t)(ntfs_le32(fn + 56) & 0xFFFFu);
    ntfs_copy_name(fn + 66, name_len, out->name);
    return out->name[0] ? 0 : 1;
}

static int ntfs_scan_index_entries(const uint8_t *base, uint32_t entries_off, uint32_t total_size,
                                   uint32_t *idx_io, uint32_t want_idx, const char *want_name,
                                   ntfs_dirent_t *found) {
    uint32_t off;
    if (!base || !idx_io || entries_off >= total_size) return -1;
    off = entries_off;
    while (off + 16u <= total_size) {
        ntfs_dirent_t de;
        uint16_t len = ntfs_le16(base + off + 8);
        int rc;
        if (len == 0 || off + len > total_size) return -1;
        rc = ntfs_parse_index_entry(base + off, total_size - off, &de);
        if (rc < 0) return -1;
        if (rc == 0) {
            if (!want_name && de.name[0] == '$') {
                off += len;
                continue;
            }
            if (want_name) {
                if (ntfs_name_eq(de.name, want_name)) {
                    if (found) *found = de;
                    return 0;
                }
            } else if (*idx_io == want_idx) {
                if (found) *found = de;
                return 0;
            }
            (*idx_io)++;
        }
        off += len;
    }
    return -1;
}

static int ntfs_scan_index_allocation(ntfs_fs_t *fs, uint8_t *rec, uint8_t *attr, uint32_t *idx_io,
                                      uint32_t want_idx, const char *want_name, ntfs_dirent_t *found) {
    uint64_t data_size;
    uint32_t block_size;

    if (!fs || !rec || !attr || !idx_io || attr[8] == 0) return -1;
    data_size = ntfs_le64(attr + 48);
    block_size = fs->index_block_size ? fs->index_block_size : fs->bytes_per_cluster;
    if (block_size < fs->bytes_per_sector || block_size > sizeof(fs->index_block)) return -1;

    for (uint64_t pos = 0; pos + block_size <= data_size; pos += block_size) {
        uint32_t entries_off;
        uint32_t total_size;
        int rc;

        if (ntfs_read_nonresident(fs, rec, attr, pos, fs->index_block, block_size) != (int)block_size) {
            return -1;
        }
        if (ntfs_apply_fixup_sized(fs, fs->index_block, block_size, "INDX") < 0) return -1;
        /*
         * INDX records carry an index header at byte 24. Offsets in that
         * header are relative to the header itself, unlike INDEX_ROOT where
         * the first 16 bytes describe the indexed attribute and collation.
         */
        entries_off = 24u + ntfs_le32(fs->index_block + 24);
        total_size = 24u + ntfs_le32(fs->index_block + 28);
        if (entries_off >= block_size || total_size > block_size || entries_off >= total_size) {
            return -1;
        }
        rc = ntfs_scan_index_entries(fs->index_block, entries_off, total_size,
                                     idx_io, want_idx, want_name, found);
        if (rc == 0) return 0;
    }
    return -1;
}

static int ntfs_dir_iter(ntfs_fs_t *fs, const ntfs_node_t *dir, uint32_t want_idx,
                         const char *want_name, ntfs_dirent_t *found) {
    uint8_t *attr;
    uint8_t *alloc_attr;
    uint8_t *val;
    uint32_t val_len;
    uint32_t entries_off;
    uint32_t total_size;
    uint32_t idx = 0;
    int root_rc;

    if (!fs || !dir || !(dir->flags & NTFS_FILE_DIRECTORY)) return -1;
    if (ntfs_read_mft_record(fs, dir->mft_ref, fs->record) < 0) return -1;
    attr = ntfs_find_attr(fs, fs->record, NTFS_ATTR_INDEX_ROOT);
    if (!attr || ntfs_resident_value(fs, fs->record, attr, &val, &val_len) < 0) return -1;
    if (val_len < 32u) return -1;
    fs->index_block_size = ntfs_le32(val + 8);
    entries_off = 16u + ntfs_le32(val + 16);
    total_size = 16u + ntfs_le32(val + 20);
    if (entries_off > val_len || total_size > val_len || entries_off >= total_size) return -1;
    root_rc = ntfs_scan_index_entries(val, entries_off, total_size, &idx, want_idx, want_name, found);
    if (root_rc == 0) return 0;

    alloc_attr = ntfs_find_attr(fs, fs->record, NTFS_ATTR_INDEX_ALLOCATION);
    if (!alloc_attr) return -1;
    /*
     * NTFS directories commonly spill ordinary entries into non-resident INDX
     * records even when the resident root only contains a child pointer. Walk
     * those allocation blocks so Linux userspace sees normal directory content
     * from mkfs.ntfs-created volumes instead of an apparently empty mount.
     */
    return ntfs_scan_index_allocation(fs, fs->record, alloc_attr, &idx, want_idx, want_name, found);
}

static void ntfs_fill_inode(const ntfs_node_t *node, vfs_inode_t *out) {
    uint16_t kind;
    if (!node || !out) return;
    memset(out, 0, sizeof(*out));
    kind = (node->flags & NTFS_FILE_DIRECTORY) ? VFS_INODE_DIR : VFS_INODE_FILE;
    out->ino = (uint32_t)(node->mft_ref ? node->mft_ref : 5u);
    out->mode = kind | 0555u;
    out->uid = 0;
    out->gid = 0;
    out->size = (uint32_t)(node->size > 0xFFFFFFFFull ? 0xFFFFFFFFu : node->size);
    out->fs_private[0] = (uint32_t)node->mft_ref;
    out->fs_private[1] = (uint32_t)(node->size & 0xFFFFFFFFu);
    out->fs_private[2] = (uint32_t)(node->size >> 32);
    out->fs_private[3] = node->flags;
}

static void ntfs_node_from_inode(const vfs_inode_t *inode, ntfs_node_t *node) {
    if (!inode || !node) return;
    node->mft_ref = inode->fs_private[0];
    node->size = ((uint64_t)inode->fs_private[2] << 32) | inode->fs_private[1];
    node->flags = (uint16_t)inode->fs_private[3];
}

static int ntfs_load_node(ntfs_fs_t *fs, uint64_t mft_ref, ntfs_node_t *node) {
    uint16_t flags;
    uint64_t size = 0;
    uint8_t *attr;
    if (!fs || !node) return -1;
    if (ntfs_read_mft_record(fs, mft_ref, fs->record) < 0) return -1;
    flags = ntfs_le16(fs->record + 22);
    attr = ntfs_find_attr(fs, fs->record, NTFS_ATTR_DATA);
    if (attr) {
        if (attr[8] == 0) {
            size = ntfs_le32(attr + 16);
        } else {
            size = ntfs_le64(attr + 48);
        }
    }
    node->mft_ref = mft_ref;
    node->size = size;
    node->flags = (flags & NTFS_FILE_DIRECTORY) ? NTFS_FILE_DIRECTORY : 0;
    return 0;
}

static int ntfs_lookup(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    ntfs_fs_t *fs = sb ? (ntfs_fs_t *)sb->fs_private : 0;
    ntfs_node_t dnode;
    ntfs_node_t node;
    ntfs_dirent_t de;
    if (!fs || !dir || !name || !out) return -1;
    if (strcmp(name, ".") == 0) {
        *out = *dir;
        return 0;
    }
    ntfs_node_from_inode(dir, &dnode);
    if (ntfs_dir_iter(fs, &dnode, 0, name, &de) < 0) return -1;
    if (ntfs_load_node(fs, de.mft_ref, &node) < 0) {
        node.mft_ref = de.mft_ref;
        node.size = de.size;
        node.flags = (de.flags & NTFS_FILE_DIRECTORY) ? NTFS_FILE_DIRECTORY : 0;
    }
    ntfs_fill_inode(&node, out);
    return 0;
}

static int ntfs_read_nonresident(ntfs_fs_t *fs, uint8_t *rec, uint8_t *attr,
                                 uint64_t off, void *buf, uint32_t len) {
    uint8_t *dst = (uint8_t *)buf;
    uint16_t run_off;
    uint32_t attr_len;
    ntfs_run_t runs[NTFS_MAX_RUNS];
    uint32_t run_count = NTFS_MAX_RUNS;
    uint32_t done = 0;
    uint64_t size;

    if (!fs || !rec || !attr || !buf) return -1;
    attr_len = ntfs_le32(attr + 4);
    run_off = ntfs_le16(attr + 32);
    size = ntfs_le64(attr + 48);
    if (off >= size) return 0;
    if ((uint64_t)len > size - off) len = (uint32_t)(size - off);
    if (run_off >= attr_len) return -1;
    if (ntfs_decode_runlist(attr + run_off, attr_len - run_off, runs, &run_count) < 0) return -1;
    while (done < len) {
        uint64_t file_pos = off + done;
        uint64_t file_cluster = file_pos / fs->bytes_per_cluster;
        uint32_t in_cluster = (uint32_t)(file_pos % fs->bytes_per_cluster);
        uint32_t chunk = fs->bytes_per_cluster - in_cluster;
        uint64_t abs_byte = 0;
        if (chunk > len - done) chunk = len - done;
        for (uint32_t i = 0; i < run_count; ++i) {
            if (file_cluster >= runs[i].vcn && file_cluster < runs[i].vcn + runs[i].len) {
                if (runs[i].lcn < 0) return -1;
                abs_byte = ((uint64_t)(runs[i].lcn + (int64_t)(file_cluster - runs[i].vcn)) *
                            fs->bytes_per_cluster) + in_cluster;
                break;
            }
        }
        if (!abs_byte) return -1;
        if (ntfs_read_bytes(fs, abs_byte, dst + done, chunk) < 0) return -1;
        done += chunk;
    }
    return (int)done;
}

static int ntfs_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    ntfs_fs_t *fs = sb ? (ntfs_fs_t *)sb->fs_private : 0;
    ntfs_node_t node;
    uint8_t *attr;
    uint8_t *val;
    uint32_t val_len;

    if (!fs || !inode || !buf) return -1;
    if ((inode->mode & 0xF000u) != VFS_INODE_FILE) return -1;
    ntfs_node_from_inode(inode, &node);
    if (ntfs_read_mft_record(fs, node.mft_ref, fs->record) < 0) return -1;
    attr = ntfs_find_attr(fs, fs->record, NTFS_ATTR_DATA);
    if (!attr) return -1;
    if (attr[8] == 0) {
        if (ntfs_resident_value(fs, fs->record, attr, &val, &val_len) < 0) return -1;
        if (off >= val_len) return 0;
        if (len > val_len - off) len = val_len - off;
        memcpy(buf, val + off, len);
        return (int)len;
    }
    return ntfs_read_nonresident(fs, fs->record, attr, off, buf, len);
}

static int ntfs_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx,
                        char *name_out, vfs_inode_t *inode_out) {
    ntfs_fs_t *fs = sb ? (ntfs_fs_t *)sb->fs_private : 0;
    ntfs_node_t dnode;
    ntfs_node_t node;
    ntfs_dirent_t de;
    if (!fs || !dir || !name_out || !inode_out) return -1;
    ntfs_node_from_inode(dir, &dnode);
    if (ntfs_dir_iter(fs, &dnode, idx, 0, &de) < 0) return -1;
    strncpy(name_out, de.name, VFS_NAME_MAX - 1);
    name_out[VFS_NAME_MAX - 1] = 0;
    if (ntfs_load_node(fs, de.mft_ref, &node) < 0) {
        node.mft_ref = de.mft_ref;
        node.size = de.size;
        node.flags = (de.flags & NTFS_FILE_DIRECTORY) ? NTFS_FILE_DIRECTORY : 0;
    }
    ntfs_fill_inode(&node, inode_out);
    return 0;
}

static int ntfs_statfs(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) {
    ntfs_fs_t *fs = sb ? (ntfs_fs_t *)sb->fs_private : 0;
    uint64_t total;
    if (!fs || !total_kb || !used_kb) return -1;
    total = (fs->total_sectors * fs->bytes_per_sector) / 1024u;
    if (total > 0xFFFFFFFFull) total = 0xFFFFFFFFull;
    *total_kb = (uint32_t)total;
    /*
     * EdgeOS does not parse the NTFS $Bitmap yet. Report a conservative used
     * value instead of fake free space; Linux userspace gets a stable capacity
     * while write support remains explicitly unavailable.
     */
    *used_kb = *total_kb;
    return 0;
}

static filesystem_ops_t g_ntfs_ops = {
    .lookup = ntfs_lookup,
    .read = ntfs_read,
    .readdir = ntfs_readdir,
    .statfs = ntfs_statfs,
};

static int ntfs_init_mft_runs(ntfs_fs_t *fs) {
    uint8_t *attr;
    uint16_t run_off;
    uint32_t attr_len;
    uint32_t count = NTFS_MAX_RUNS;

    if (!fs) return -1;
    fs->mft_run_count = 0;
    if (ntfs_read_bytes(fs, (uint64_t)fs->mft_lcn * fs->bytes_per_cluster,
                        fs->record, fs->record_size) < 0) return -1;
    if (ntfs_apply_fixup(fs, fs->record) < 0) return -1;
    attr = ntfs_find_attr(fs, fs->record, NTFS_ATTR_DATA);
    if (!attr || attr[8] == 0) return -1;
    attr_len = ntfs_le32(attr + 4);
    run_off = ntfs_le16(attr + 32);
    if (run_off >= attr_len) return -1;
    if (ntfs_decode_runlist(attr + run_off, attr_len - run_off, fs->mft_runs, &count) < 0) return -1;
    fs->mft_run_count = count;
    return count ? 0 : -1;
}

static int ntfs_mount_common(block_device_t *bdev, const char *dev, const char *target) {
    ntfs_fs_t *fs;
    vfs_superblock_t sb;
    ntfs_node_t root;
    int8_t clusters_per_record;

    if (!bdev || !target) return -1;
    if (g_ntfs_mount_count >= NTFS_MAX_MOUNTS) return -1;
    fs = &g_ntfs_mounts[g_ntfs_mount_count];
    memset(fs, 0, sizeof(*fs));
    fs->bdev = bdev;
    fs->bytes_per_sector = bdev->sector_size;
    if (fs->bytes_per_sector > sizeof(fs->scratch)) return -1;
    if (ntfs_read_sectors(fs, 0, 1, fs->scratch) < 0) return -1;
    if (memcmp(fs->scratch + 3, "NTFS    ", 8) != 0 ||
        fs->scratch[510] != 0x55u || fs->scratch[511] != 0xAAu) {
        printf("[ntfs] invalid boot sector on %s\n", dev ? dev : bdev->name);
        return -1;
    }
    if (ntfs_le16(fs->scratch + 11) != fs->bytes_per_sector) return -1;
    fs->total_sectors = ntfs_le64(fs->scratch + 40);
    fs->sectors_per_cluster = fs->scratch[13];
    if (!fs->sectors_per_cluster) return -1;
    fs->bytes_per_cluster = fs->bytes_per_sector * fs->sectors_per_cluster;
    fs->mft_lcn = (int64_t)ntfs_le64(fs->scratch + 48);
    clusters_per_record = (int8_t)fs->scratch[64];
    if (clusters_per_record < 0) {
        fs->record_size = 1u << (uint8_t)(-clusters_per_record);
    } else {
        fs->record_size = (uint32_t)clusters_per_record * fs->bytes_per_cluster;
    }
    if (fs->record_size < 512u || fs->record_size > NTFS_MAX_RECORD) return -1;
    if (ntfs_init_mft_runs(fs) < 0) return -1;
    if (ntfs_load_node(fs, 5u, &root) < 0) return -1;
    root.flags = NTFS_FILE_DIRECTORY;

    memset(&sb, 0, sizeof(sb));
    strcpy(sb.fs_name, "ntfs");
    strncpy(sb.dev_name, dev ? dev : bdev->name, sizeof(sb.dev_name) - 1);
    strncpy(sb.mountpoint, target, sizeof(sb.mountpoint) - 1);
    ntfs_fill_inode(&root, &sb.root);
    sb.ops = &g_ntfs_ops;
    sb.fs_private = fs;
    if (vfs_add_superblock(&sb) < 0) return -1;
    g_ntfs_mount_count++;
    printf("[ntfs] mounted %s on %s mft_lcn=%lld record=%u\n",
           sb.dev_name, target, (long long)fs->mft_lcn, fs->record_size);
    return 0;
}

int ntfs_mount(const char *dev, const char *target) {
    block_device_t *b;
    const char *name;
    if (!dev || !target) return -1;
    name = (strncmp(dev, "/dev/", 5) == 0) ? dev + 5 : dev;
    b = block_find(name);
    if (!b) return -1;
    return ntfs_mount_common(b, dev, target);
}

int ntfs_mount_block(block_device_t *bdev, const char *target) {
    if (!bdev) return -1;
    return ntfs_mount_common(bdev, bdev->name, target);
}
