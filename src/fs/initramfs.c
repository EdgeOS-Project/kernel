// SPDX-License-Identifier: MPL-2.0
/*
 * Linux initramfs unpacking support for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * Implements the externally documented Linux initramfs "newc" and "crc" cpio
 * wire formats without copying Linux implementation code.  Unsupported inode
 * kinds are rejected rather than represented as regular files.
 */

#include "fs/initramfs.h"
#include "fs/tmpfs.h"
#include "kernel/file_metadata.h"
#ifdef CONFIG_INITRAMFS_GZIP
#include "lib/gzip.h"
#endif
#include "stdio.h"
#include "string.h"
#include "vfs/vfs.h"

#include <stdint.h>

#define INITRAMFS_STRINGIFY_VALUE(value) #value
#define INITRAMFS_STRINGIFY(value) INITRAMFS_STRINGIFY_VALUE(value)
#define INITRAMFS_MOUNT_OPTIONS \
    "nr_inodes=" INITRAMFS_STRINGIFY(CONFIG_INITRAMFS_MAX_INODES)

#define CPIO_NEWC_HEADER_LEN 110u
#define CPIO_S_IFMT  0170000u
#define CPIO_S_IFCHR 0020000u
#define CPIO_S_IFBLK 0060000u
#define CPIO_S_IFREG 0100000u
#define CPIO_S_IFDIR 0040000u
#define CPIO_S_IFLNK 0120000u
#define CPIO_S_IFIFO 0010000u
#define CPIO_S_IFSOCK 0140000u
#define INITRAMFS_MAX_SKIPPED 8u

typedef struct {
    const uint8_t *data;
    uint32_t size;
} initramfs_blob_t;

static char g_initramfs_raw_name[VFS_PATH_MAX];
static char g_initramfs_path[VFS_PATH_MAX];
static char g_initramfs_link_target[VFS_PATH_MAX];
static char g_initramfs_parent_path[VFS_PATH_MAX];
static char g_initramfs_hardlink_source[VFS_PATH_MAX];
static char g_initramfs_hardlink_path[VFS_PATH_MAX];
static volatile uint32_t g_initramfs_unpack_lock;

static uint32_t align4(uint32_t v) {
    return (v + 3u) & ~3u;
}

static int cpio_is_magic(const uint8_t *p, uint32_t size) {
    if (!p || size < CPIO_NEWC_HEADER_LEN) return 0;
    return memcmp(p, "070701", 6) == 0 || memcmp(p, "070702", 6) == 0;
}

static int initramfs_find_cpio_offset(const uint8_t *data, uint32_t size, uint32_t *off_out) {
    uint32_t off = 0;
    if (!data || !off_out) return 0;
    while (off < size && data[off] == 0) off++;
    if (!cpio_is_magic(data + off, size - off)) return 0;
    *off_out = off;
    return 1;
}

static int hex_digit(uint8_t c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F') return (int)(c - 'A') + 10;
    return -1;
}

static int cpio_hex32(const uint8_t *p, uint32_t *out) {
    uint32_t v = 0;
    if (!p || !out) return -1;
    for (uint32_t i = 0; i < 8; ++i) {
        int d = hex_digit(p[i]);
        if (d < 0) return -1;
        v = (v << 4) | (uint32_t)d;
    }
    *out = v;
    return 0;
}

static int cpio_crc_valid(const uint8_t *header, const uint8_t *data,
                          uint32_t size) {
    uint32_t expected;
    uint32_t actual = 0;

    if (memcmp(header, "070702", 6) != 0) return 1;
    if (cpio_hex32(header + 102, &expected) < 0) return 0;
    for (uint32_t i = 0; i < size; ++i) actual += data[i];
    return actual == expected;
}

static int initramfs_clean_path(const char *name, char *out, uint32_t out_len) {
    uint32_t oi = 0;
    uint32_t comp_len = 0;
    if (!name || !out || out_len < 2) return -1;
    while (*name == '/') name++;
    out[oi++] = '/';
    out[oi] = 0;
    while (*name) {
        const char *start;
        while (*name == '/') name++;
        if (!*name) break;
        start = name;
        comp_len = 0;
        while (name[comp_len] && name[comp_len] != '/') comp_len++;
        if (comp_len == 1 && start[0] == '.') {
            name += comp_len;
            continue;
        }
        if (comp_len == 2 && start[0] == '.' && start[1] == '.') return -1;
        if (comp_len >= VFS_NAME_MAX) return -1;
        if (oi > 1) {
            if (oi + 1 >= out_len) return -1;
            out[oi++] = '/';
        }
        for (uint32_t i = 0; i < comp_len; ++i) {
            if (oi + 1 >= out_len) return -1;
            out[oi++] = start[i];
        }
        out[oi] = 0;
        name += comp_len;
    }
    return 0;
}

static int initramfs_ensure_parent_dirs(const char *path) {
    uint32_t len;
    if (!path || path[0] != '/') return -1;
    len = (uint32_t)strlen(path);
    if (len >= VFS_PATH_MAX) return -1;
    strcpy(g_initramfs_parent_path, path);
    for (uint32_t i = 1; g_initramfs_parent_path[i]; ++i) {
        if (g_initramfs_parent_path[i] != '/') continue;
        g_initramfs_parent_path[i] = 0;
        (void)vfs_mkdir(g_initramfs_parent_path);
        g_initramfs_parent_path[i] = '/';
    }
    return 0;
}

/*
 * Concatenated initramfs archives are overlays.  Reuse regular files and
 * directories when their type already matches, but replace every other
 * backed inode so a later archive can change both contents and inode type.
 * Synthetic early /dev entries have no superblock and are intentionally left
 * in place; vfs_mknod() can materialize a real device inode over them.
 */
static int initramfs_prepare_destination(const char *path,
                                         uint16_t desired_kind,
                                         int reuse_matching) {
    vfs_inode_t existing;
    vfs_superblock_t *superblock = 0;
    uint16_t existing_kind;

    if (!path || !path[0]) return -1;
    if (vfs_resolve_nofollow(path, &existing, &superblock) < 0) return 0;
    existing_kind = (uint16_t)(existing.mode & CPIO_S_IFMT);
    if (reuse_matching && existing_kind == desired_kind) return 1;
    if (!superblock) {
        if (desired_kind == VFS_INODE_CHR ||
            desired_kind == VFS_INODE_BLK)
            return 0;
        return -1;
    }
    if (existing_kind == VFS_INODE_DIR)
        return vfs_rmdir(path) < 0 ? -1 : 0;
    return vfs_unlink(path) < 0 ? -1 : 0;
}

static void initramfs_metadata_apply(const char *path, uint32_t mode,
                                     uint32_t uid, uint32_t gid,
                                     uint32_t mtime) {
    if (!path || !path[0]) return;
    if ((mode & CPIO_S_IFMT) == CPIO_S_IFLNK) {
        (void)vfs_lchown(path, uid, gid);
        return;
    }
    (void)vfs_chown(path, uid, gid);
    (void)vfs_chmod(path, (uint16_t)(mode & 07777u));
    (void)vfs_utimens(path, mtime, mtime, 1, 1);
}

static int initramfs_hardlink_entry_matches(
    const uint8_t *header, uint32_t inode, uint32_t device_major,
    uint32_t device_minor, uint32_t *filesize_out,
    uint32_t *namesize_out) {
    uint32_t candidate_inode;
    uint32_t candidate_nlink;
    uint32_t candidate_device_major;
    uint32_t candidate_device_minor;
    uint32_t filesize;
    uint32_t namesize;

    if (!header ||
        cpio_hex32(header + 6, &candidate_inode) < 0 ||
        cpio_hex32(header + 38, &candidate_nlink) < 0 ||
        cpio_hex32(header + 54, &filesize) < 0 ||
        cpio_hex32(header + 62, &candidate_device_major) < 0 ||
        cpio_hex32(header + 70, &candidate_device_minor) < 0 ||
        cpio_hex32(header + 94, &namesize) < 0)
        return -1;
    if (filesize_out) *filesize_out = filesize;
    if (namesize_out) *namesize_out = namesize;
    return candidate_nlink > 1 &&
           candidate_inode == inode &&
           candidate_device_major == device_major &&
           candidate_device_minor == device_minor;
}

static int initramfs_find_hardlink_source(
    const initramfs_blob_t *blob, uint32_t inode, uint32_t device_major,
    uint32_t device_minor, uint32_t *source_offset_out) {
    uint32_t off = 0;
    uint32_t source_offset = UINT32_MAX;
    int source_has_data = 0;

    if (!blob || !source_offset_out) return -1;
    while (off + CPIO_NEWC_HEADER_LEN <= blob->size) {
        const uint8_t *header = blob->data + off;
        uint32_t filesize;
        uint32_t namesize;
        uint32_t name_off;
        uint32_t data_off;
        uint32_t next_off;
        int matches;

        if (!cpio_is_magic(header, blob->size - off)) return -1;
        matches = initramfs_hardlink_entry_matches(
            header, inode, device_major, device_minor,
            &filesize, &namesize);
        if (matches < 0 || namesize == 0 || namesize >= VFS_PATH_MAX)
            return -1;
        name_off = off + CPIO_NEWC_HEADER_LEN;
        if (name_off + namesize > blob->size) return -1;
        memcpy(g_initramfs_raw_name, blob->data + name_off, namesize);
        g_initramfs_raw_name[namesize - 1] = 0;
        data_off = align4(name_off + namesize);
        if (data_off > blob->size ||
            filesize > blob->size - data_off)
            return -1;
        next_off = align4(data_off + filesize);
        if (next_off < data_off || next_off > blob->size) return -1;
        if (strcmp(g_initramfs_raw_name, "TRAILER!!!") == 0) break;

        if (matches &&
            (!source_has_data || source_offset == UINT32_MAX) &&
            initramfs_clean_path(g_initramfs_raw_name,
                                 g_initramfs_hardlink_source,
                                 VFS_PATH_MAX) == 0) {
            source_offset = off;
            if (filesize != 0) source_has_data = 1;
        }
        off = next_off;
    }
    if (source_offset == UINT32_MAX) return -1;
    *source_offset_out = source_offset;
    return 0;
}

static int initramfs_create_hardlink_group(
    const initramfs_blob_t *blob, uint32_t inode, uint32_t device_major,
    uint32_t device_minor, uint32_t source_offset) {
    uint32_t off = 0;

    if (!blob || !g_initramfs_hardlink_source[0]) return -1;
    while (off + CPIO_NEWC_HEADER_LEN <= blob->size) {
        const uint8_t *header = blob->data + off;
        uint32_t filesize;
        uint32_t namesize;
        uint32_t name_off;
        uint32_t data_off;
        uint32_t next_off;
        int matches;

        if (!cpio_is_magic(header, blob->size - off)) return -1;
        matches = initramfs_hardlink_entry_matches(
            header, inode, device_major, device_minor,
            &filesize, &namesize);
        if (matches < 0 || namesize == 0 || namesize >= VFS_PATH_MAX)
            return -1;
        name_off = off + CPIO_NEWC_HEADER_LEN;
        if (name_off + namesize > blob->size) return -1;
        memcpy(g_initramfs_raw_name, blob->data + name_off, namesize);
        g_initramfs_raw_name[namesize - 1] = 0;
        data_off = align4(name_off + namesize);
        if (data_off > blob->size ||
            filesize > blob->size - data_off)
            return -1;
        next_off = align4(data_off + filesize);
        if (next_off < data_off || next_off > blob->size) return -1;
        if (strcmp(g_initramfs_raw_name, "TRAILER!!!") == 0) break;

        if (matches && off != source_offset) {
            if (initramfs_clean_path(g_initramfs_raw_name,
                                     g_initramfs_hardlink_path,
                                     VFS_PATH_MAX) < 0 ||
                initramfs_ensure_parent_dirs(
                    g_initramfs_hardlink_path) < 0 ||
                initramfs_prepare_destination(
                    g_initramfs_hardlink_path, VFS_INODE_FILE, 0) < 0 ||
                vfs_link(g_initramfs_hardlink_source,
                         g_initramfs_hardlink_path, 0) < 0) {
                printf("[initramfs] failed creating hardlink %s -> %s\n",
                       g_initramfs_hardlink_path,
                       g_initramfs_hardlink_source);
                return -1;
            }
        }
        off = next_off;
    }
    return 0;
}

static int initramfs_unpack_one(const initramfs_blob_t *blob, uint32_t *consumed_out) {
    uint32_t off = 0;
    uint32_t entries = 0;
    uint32_t skipped = 0;
    if (!blob || !blob->data || !cpio_is_magic(blob->data, blob->size)) return -1;
    if (consumed_out) *consumed_out = 0;

    while (off + CPIO_NEWC_HEADER_LEN <= blob->size) {
        const uint8_t *h = blob->data + off;
        uint32_t inode;
        uint32_t mode;
        uint32_t uid;
        uint32_t gid;
        uint32_t nlink;
        uint32_t mtime;
        uint32_t filesize;
        uint32_t namesize;
        uint32_t device_major;
        uint32_t device_minor;
        uint32_t rdev_major;
        uint32_t rdev_minor;
        uint32_t name_off;
        uint32_t data_off;
        uint32_t next_off;
        char *raw_name = g_initramfs_raw_name;
        char *path = g_initramfs_path;

        if (!cpio_is_magic(h, blob->size - off)) return -1;
        if (cpio_hex32(h + 6, &inode) < 0 ||
            cpio_hex32(h + 14, &mode) < 0 ||
            cpio_hex32(h + 22, &uid) < 0 ||
            cpio_hex32(h + 30, &gid) < 0 ||
            cpio_hex32(h + 38, &nlink) < 0 ||
            cpio_hex32(h + 46, &mtime) < 0 ||
            cpio_hex32(h + 54, &filesize) < 0 ||
            cpio_hex32(h + 62, &device_major) < 0 ||
            cpio_hex32(h + 70, &device_minor) < 0 ||
            cpio_hex32(h + 78, &rdev_major) < 0 ||
            cpio_hex32(h + 86, &rdev_minor) < 0 ||
            cpio_hex32(h + 94, &namesize) < 0) {
            return -1;
        }
        if (namesize == 0 || namesize >= VFS_PATH_MAX) return -1;
        name_off = off + CPIO_NEWC_HEADER_LEN;
        if (name_off + namesize > blob->size) return -1;
        memcpy(raw_name, blob->data + name_off, namesize);
        raw_name[namesize - 1] = 0;
        data_off = align4(name_off + namesize);
        if (data_off > blob->size || filesize > blob->size - data_off) return -1;
        next_off = align4(data_off + filesize);
        if (next_off < data_off || next_off > blob->size) return -1;
        if (!cpio_crc_valid(h, blob->data + data_off, filesize)) {
            printf("[initramfs] checksum mismatch for %s\n", raw_name);
            return -1;
        }

        if (strcmp(raw_name, "TRAILER!!!") == 0) {
            if (consumed_out) *consumed_out = next_off;
            printf("[initramfs] unpacked %u entries, skipped %u unsupported entries\n", entries, skipped);
            return (int)entries;
        }
        if (initramfs_clean_path(raw_name, path, VFS_PATH_MAX) < 0) {
            skipped++;
            off = next_off;
            continue;
        }
        if (initramfs_ensure_parent_dirs(path) < 0) {
            printf("[initramfs] failed creating parent directories for %s\n", path);
            return -1;
        }

        switch (mode & CPIO_S_IFMT) {
        case CPIO_S_IFDIR:
            if (strcmp(path, "/") != 0) {
                int prepared = initramfs_prepare_destination(
                    path, VFS_INODE_DIR, 1);
                if (prepared < 0 ||
                    (prepared == 0 &&
                     vfs_mkdir_mode(
                         path, (uint16_t)(mode & 07777u)) < 0)) {
                    printf("[initramfs] failed creating directory %s\n", path);
                    return -1;
                }
            }
            entries++;
            break;
        case CPIO_S_IFREG: {
            uint32_t hardlink_source_offset = off;

            if (nlink > 1 &&
                initramfs_find_hardlink_source(
                    blob, inode, device_major, device_minor,
                    &hardlink_source_offset) < 0)
                return -1;
            if (hardlink_source_offset != off) {
                entries++;
                break;
            }
            if (nlink > 1)
                path = g_initramfs_hardlink_source;
            if (initramfs_ensure_parent_dirs(path) < 0 ||
                initramfs_prepare_destination(
                    path, VFS_INODE_FILE, 1) < 0 ||
                vfs_write_file(path,
                               (const char *)(blob->data + data_off),
                               filesize) != (int)filesize) {
                printf("[initramfs] failed writing regular file %s size=%u\n", path, filesize);
                return -1;
            }
            if (nlink > 1 &&
                initramfs_create_hardlink_group(
                    blob, inode, device_major, device_minor,
                    hardlink_source_offset) < 0)
                return -1;
            initramfs_metadata_apply(path, mode, uid, gid, mtime);
            entries++;
            break;
        }
        case CPIO_S_IFLNK: {
            if (filesize == 0 || filesize >= VFS_PATH_MAX) return -1;
            memcpy(g_initramfs_link_target, blob->data + data_off, filesize);
            g_initramfs_link_target[filesize] = 0;
            if (initramfs_prepare_destination(
                    path, VFS_INODE_LNK, 0) < 0 ||
                vfs_symlink(g_initramfs_link_target, path) < 0) {
                printf("[initramfs] failed creating symlink %s -> %s\n",
                       path, g_initramfs_link_target);
                return -1;
            }
            initramfs_metadata_apply(path, mode, uid, gid, mtime);
            entries++;
            break;
        }
        case CPIO_S_IFIFO:
            if (initramfs_prepare_destination(
                    path, VFS_INODE_FIFO, 0) < 0 ||
                vfs_create_special_node(
                    path,
                    (uint16_t)(VFS_INODE_FIFO | (mode & 07777u))) < 0) {
                printf("[initramfs] failed creating fifo %s\n", path);
                return -1;
            }
            initramfs_metadata_apply(path, mode, uid, gid, mtime);
            entries++;
            break;
        case CPIO_S_IFSOCK:
            if (initramfs_prepare_destination(
                    path, VFS_INODE_SOCK, 0) < 0 ||
                vfs_create_special_node(
                    path,
                    (uint16_t)(VFS_INODE_SOCK | (mode & 07777u))) < 0) {
                printf("[initramfs] failed creating socket node %s\n", path);
                return -1;
            }
            initramfs_metadata_apply(path, mode, uid, gid, mtime);
            entries++;
            break;
        case CPIO_S_IFCHR:
        case CPIO_S_IFBLK: {
            uint16_t kind = (mode & CPIO_S_IFMT) == CPIO_S_IFCHR ?
                VFS_INODE_CHR : VFS_INODE_BLK;
            uint64_t rdev = kernel_file_device_encode(rdev_major, rdev_minor);

            if (initramfs_prepare_destination(path, kind, 0) < 0 ||
                vfs_mknod(path,
                           (uint16_t)(kind | (mode & 07777u)),
                           rdev) < 0) {
                printf("[initramfs] failed creating device node %s\n", path);
                return -1;
            }
            initramfs_metadata_apply(path, mode, uid, gid, mtime);
            entries++;
            break;
        }
        default:
            if (skipped < INITRAMFS_MAX_SKIPPED) {
                printf("[initramfs] skipping unsupported entry %s mode=0%o\n", path, mode);
            }
            skipped++;
            break;
        }

        off = next_off;
    }
    if (entries > 0) {
        if (consumed_out) *consumed_out = off;
        printf("[initramfs] unpacked %u entries, skipped %u unsupported entries (no trailer)\n", entries, skipped);
        return (int)entries;
    }
    return -1;
}

static int initramfs_apply_directory_metadata(
    const initramfs_blob_t *blob) {
    uint32_t off = 0;

    if (!blob || !blob->data) return -1;
    while (off < blob->size) {
        uint32_t relative = 0;

        while (off < blob->size && blob->data[off] == 0) off++;
        if (off >= blob->size) break;
        if (!initramfs_find_cpio_offset(
                blob->data + off, blob->size - off, &relative))
            return -1;
        off += relative;

        while (off + CPIO_NEWC_HEADER_LEN <= blob->size) {
            const uint8_t *header = blob->data + off;
            uint32_t mode;
            uint32_t uid;
            uint32_t gid;
            uint32_t mtime;
            uint32_t filesize;
            uint32_t namesize;
            uint32_t name_off;
            uint32_t data_off;
            uint32_t next_off;

            if (!cpio_is_magic(header, blob->size - off) ||
                cpio_hex32(header + 14, &mode) < 0 ||
                cpio_hex32(header + 22, &uid) < 0 ||
                cpio_hex32(header + 30, &gid) < 0 ||
                cpio_hex32(header + 46, &mtime) < 0 ||
                cpio_hex32(header + 54, &filesize) < 0 ||
                cpio_hex32(header + 94, &namesize) < 0 ||
                namesize == 0 || namesize >= VFS_PATH_MAX)
                return -1;

            name_off = off + CPIO_NEWC_HEADER_LEN;
            if (name_off + namesize > blob->size) return -1;
            memcpy(g_initramfs_raw_name, blob->data + name_off, namesize);
            g_initramfs_raw_name[namesize - 1] = 0;
            data_off = align4(name_off + namesize);
            if (data_off > blob->size ||
                filesize > blob->size - data_off)
                return -1;
            next_off = align4(data_off + filesize);
            if (next_off < data_off || next_off > blob->size) return -1;

            if (strcmp(g_initramfs_raw_name, "TRAILER!!!") == 0) {
                off = next_off;
                break;
            }
            if ((mode & CPIO_S_IFMT) == CPIO_S_IFDIR &&
                initramfs_clean_path(g_initramfs_raw_name,
                                     g_initramfs_path,
                                     VFS_PATH_MAX) == 0) {
                initramfs_metadata_apply(
                    g_initramfs_path, mode, uid, gid, mtime);
            }
            off = next_off;
        }
    }
    return 0;
}

static int initramfs_unpack_archives(const initramfs_blob_t *blob) {
    uint32_t off = 0;
    uint32_t archives = 0;
    uint32_t total_entries = 0;
    if (!blob || !blob->data) return -1;

    while (off < blob->size) {
        initramfs_blob_t one;
        uint32_t rel = 0;
        uint32_t consumed = 0;
        int rc;

        while (off < blob->size && blob->data[off] == 0) off++;
        if (off >= blob->size) break;
        if (!initramfs_find_cpio_offset(blob->data + off, blob->size - off, &rel)) break;
        off += rel;

        one.data = blob->data + off;
        one.size = blob->size - off;
        rc = initramfs_unpack_one(&one, &consumed);
        if (rc < 0 || consumed == 0) return -1;
        total_entries += (uint32_t)rc;
        archives++;
        off += align4(consumed);
    }

    if (archives == 0) return -1;
    if (initramfs_apply_directory_metadata(blob) < 0) return -1;
    if (archives > 1) {
        printf("[initramfs] unpacked %u concatenated archive(s), total entries=%u\n",
               archives, total_entries);
    }
    return (int)total_entries;
}

int initramfs_buffer_has_archive(const void *data, uint64_t size) {
    uint32_t offset = 0;

    if (!data || size == 0 || size > UINT32_MAX) return 0;
    if (initramfs_find_cpio_offset(
            (const uint8_t *)data, (uint32_t)size, &offset))
        return 1;
#ifdef CONFIG_INITRAMFS_GZIP
    return edge_gzip_is_archive(data, size);
#else
    return 0;
#endif
}

int initramfs_mount_root(void) {
    return tmpfs_mount_type_options(
        "initramfs", "/", "tmpfs", INITRAMFS_MOUNT_OPTIONS);
}

int initramfs_unpack_memory(const void *data, uint64_t size) {
    initramfs_blob_t blob;
    void *decoded = 0;
    uint64_t decoded_size = 0;
    int rc;

    if (!data || size == 0 || size > UINT32_MAX) return -1;
    while (__sync_lock_test_and_set(&g_initramfs_unpack_lock, 1u))
        __asm__ __volatile__("" ::: "memory");
    blob.data = (const uint8_t *)data;
    blob.size = (uint32_t)size;
    if (!initramfs_find_cpio_offset(
            blob.data, blob.size, &(uint32_t){ 0 })) {
#ifdef CONFIG_INITRAMFS_GZIP
        if (edge_gzip_decompress(
                data, size, CONFIG_INITRAMFS_MAX_BYTES,
                &decoded, &decoded_size) < 0 ||
            decoded_size > UINT32_MAX ||
            !initramfs_find_cpio_offset(
                (const uint8_t *)decoded, (uint32_t)decoded_size,
                &(uint32_t){ 0 })) {
            edge_gzip_release(decoded);
            __sync_lock_release(&g_initramfs_unpack_lock);
            return -1;
        }
        printf("[initramfs] decompressed gzip archive %u -> %u bytes\n",
               (uint32_t)size, (uint32_t)decoded_size);
        blob.data = (const uint8_t *)decoded;
        blob.size = (uint32_t)decoded_size;
#else
        __sync_lock_release(&g_initramfs_unpack_lock);
        return -1;
#endif
    }
    printf("[initramfs] unpacking cpio archive size=%u bytes\n", blob.size);
    rc = initramfs_unpack_archives(&blob);
    if (rc < 0) {
        printf("[initramfs] unpack failed\n");
#ifdef CONFIG_INITRAMFS_GZIP
        edge_gzip_release(decoded);
#endif
        __sync_lock_release(&g_initramfs_unpack_lock);
        return -1;
    }
#ifdef CONFIG_INITRAMFS_GZIP
    edge_gzip_release(decoded);
#endif
    __sync_lock_release(&g_initramfs_unpack_lock);
    return rc;
}
