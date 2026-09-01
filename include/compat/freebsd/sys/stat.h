/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_COMPAT_FREEBSD_SYS_STAT_H
#define EDGEOS_COMPAT_FREEBSD_SYS_STAT_H

#include <sys/types.h>

#define S_IRWXU 0000700
#define S_IRUSR 0000400
#define S_IWUSR 0000200
#define S_IXUSR 0000100
#define S_IRWXG 0000070
#define S_IRGRP 0000040
#define S_IWGRP 0000020
#define S_IXGRP 0000010
#define S_IRWXO 0000007
#define S_IROTH 0000004
#define S_IWOTH 0000002
#define S_IXOTH 0000001

#define S_IFREG 0100000
#define S_IFCHR 0020000

struct stat {
    uint64_t st_dev;
    uint64_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    uint64_t st_rdev;
    off_t st_size;
    int64_t st_blocks;
    int32_t st_blksize;
};

#endif
