/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS declarations of the public FUSE 7.31 wire ABI.
 * Only protocol data structures are declared here; policy lives in fuse.c.
 */

#ifndef EDGEOS_FS_FUSE_KERNEL_H
#define EDGEOS_FS_FUSE_KERNEL_H

#include <stdint.h>

#define FUSE_KERNEL_VERSION 7u
#define FUSE_KERNEL_MINOR_VERSION 31u

enum fuse_opcode {
    FUSE_LOOKUP = 1, FUSE_FORGET = 2, FUSE_GETATTR = 3,
    FUSE_SETATTR = 4, FUSE_READLINK = 5, FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8, FUSE_MKDIR = 9, FUSE_UNLINK = 10,
    FUSE_RMDIR = 11, FUSE_RENAME = 12, FUSE_LINK = 13,
    FUSE_OPEN = 14, FUSE_READ = 15, FUSE_WRITE = 16,
    FUSE_STATFS = 17, FUSE_RELEASE = 18, FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21, FUSE_GETXATTR = 22, FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24, FUSE_FLUSH = 25, FUSE_INIT = 26,
    FUSE_OPENDIR = 27, FUSE_READDIR = 28, FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30, FUSE_ACCESS = 34, FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36, FUSE_DESTROY = 38, FUSE_FALLOCATE = 43,
    FUSE_READDIRPLUS = 44, FUSE_RENAME2 = 45, FUSE_LSEEK = 46,
    FUSE_COPY_FILE_RANGE = 47
};

enum fuse_notify_code {
    FUSE_NOTIFY_POLL = 1,
    FUSE_NOTIFY_INVAL_INODE = 2,
    FUSE_NOTIFY_INVAL_ENTRY = 3,
    FUSE_NOTIFY_STORE = 4,
    FUSE_NOTIFY_RETRIEVE = 5,
    FUSE_NOTIFY_DELETE = 6
};

#define FUSE_ASYNC_READ       (1u << 0)
#define FUSE_POSIX_LOCKS      (1u << 1)
#define FUSE_ATOMIC_O_TRUNC   (1u << 3)
#define FUSE_EXPORT_SUPPORT   (1u << 4)
#define FUSE_BIG_WRITES       (1u << 5)
#define FUSE_DONT_MASK        (1u << 6)
#define FUSE_FLOCK_LOCKS      (1u << 10)
#define FUSE_AUTO_INVAL_DATA  (1u << 12)
#define FUSE_DO_READDIRPLUS   (1u << 13)
#define FUSE_READDIRPLUS_AUTO (1u << 14)
#define FUSE_ASYNC_DIO        (1u << 15)
#define FUSE_MAX_PAGES        (1u << 22)

#define FUSE_GETATTR_FH 1u
#define FUSE_SET_ATTR_MODE  (1u << 0)
#define FUSE_SET_ATTR_UID   (1u << 1)
#define FUSE_SET_ATTR_GID   (1u << 2)
#define FUSE_SET_ATTR_SIZE  (1u << 3)
#define FUSE_SET_ATTR_ATIME (1u << 4)
#define FUSE_SET_ATTR_MTIME (1u << 5)
#define FUSE_SET_ATTR_FH    (1u << 6)

struct fuse_in_header {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t padding;
};

struct fuse_out_header {
    uint32_t len;
    int32_t error;
    uint64_t unique;
};

struct fuse_attr {
    uint64_t ino, size, blocks, atime, mtime, ctime;
    uint32_t atimensec, mtimensec, ctimensec;
    uint32_t mode, nlink, uid, gid, rdev, blksize, flags;
};

struct fuse_entry_out {
    uint64_t nodeid, generation, entry_valid, attr_valid;
    uint32_t entry_valid_nsec, attr_valid_nsec;
    struct fuse_attr attr;
};

struct fuse_attr_out {
    uint64_t attr_valid;
    uint32_t attr_valid_nsec, dummy;
    struct fuse_attr attr;
};

struct fuse_init_in {
    uint32_t major, minor, max_readahead, flags;
};

struct fuse_init_out {
    uint32_t major, minor, max_readahead, flags;
    uint16_t max_background, congestion_threshold;
    uint32_t max_write, time_gran;
    uint16_t max_pages, map_alignment;
    uint32_t flags2, unused[7];
};

struct fuse_getattr_in { uint32_t getattr_flags, dummy; uint64_t fh; };
struct fuse_setattr_in {
    uint32_t valid, padding;
    uint64_t fh, size, lock_owner, atime, mtime, ctime;
    uint32_t atimensec, mtimensec, ctimensec, mode, unused4, uid, gid, unused5;
};
struct fuse_mknod_in { uint32_t mode, rdev, umask, padding; };
struct fuse_mkdir_in { uint32_t mode, umask; };
struct fuse_rename_in { uint64_t newdir; };
struct fuse_rename2_in { uint64_t newdir; uint32_t flags, padding; };
struct fuse_link_in { uint64_t oldnodeid; };
struct fuse_open_in { uint32_t flags, open_flags; };
struct fuse_open_out { uint64_t fh; uint32_t open_flags, padding; };
struct fuse_release_in { uint64_t fh; uint32_t flags, release_flags; uint64_t lock_owner; };
struct fuse_flush_in { uint64_t fh; uint32_t unused, padding; uint64_t lock_owner; };
struct fuse_read_in {
    uint64_t fh, offset;
    uint32_t size, read_flags;
    uint64_t lock_owner;
    uint32_t flags, padding;
};
struct fuse_write_in {
    uint64_t fh, offset;
    uint32_t size, write_flags;
    uint64_t lock_owner;
    uint32_t flags, padding;
};
struct fuse_write_out { uint32_t size, padding; };
struct fuse_fsync_in { uint64_t fh; uint32_t fsync_flags, padding; };
struct fuse_setxattr_in { uint32_t size, flags, setxattr_flags, padding; };
struct fuse_getxattr_in { uint32_t size, padding; };
struct fuse_getxattr_out { uint32_t size, padding; };
struct fuse_access_in { uint32_t mask, padding; };
struct fuse_create_in { uint32_t flags, mode, umask, open_flags; };
struct fuse_fallocate_in { uint64_t fh, offset, length; uint32_t mode, padding; };

struct fuse_kstatfs {
    uint64_t blocks, bfree, bavail, files, ffree;
    uint32_t bsize, namelen, frsize, padding, spare[6];
};
struct fuse_statfs_out { struct fuse_kstatfs st; };

struct fuse_dirent {
    uint64_t ino, off;
    uint32_t namelen, type;
    char name[];
};

struct fuse_notify_inval_inode_out {
    uint64_t ino;
    int64_t off;
    int64_t len;
};

struct fuse_notify_inval_entry_out {
    uint64_t parent;
    uint32_t namelen;
    uint32_t flags;
};

struct fuse_notify_delete_out {
    uint64_t parent;
    uint64_t child;
    uint32_t namelen;
    uint32_t padding;
};

#define FUSE_DIRENT_ALIGN(x) (((x) + 7u) & ~7u)
#define FUSE_DIRENT_SIZE(n) FUSE_DIRENT_ALIGN(sizeof(struct fuse_dirent) + (n))

#endif
