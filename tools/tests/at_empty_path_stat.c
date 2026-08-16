/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    struct stat st;
    union {
        struct statx stx;
        unsigned char abi[256];
    } stx_buf;
    struct statx *stx = &stx_buf.stx;
    int fd;
    long rc;
    int failed = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    fd = open("/bin/busybox", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("open_rc:-1 errno:%d\n", errno);
        return 1;
    }

    memset(&st, 0, sizeof(st));
    errno = 0;
    rc = syscall(SYS_newfstatat, fd, "", &st, AT_EMPTY_PATH);
    printf("newfstatat_empty_rc:%ld errno:%d mode:%o size:%lld\n",
           rc, errno, (unsigned)(st.st_mode & 0170000),
           (long long)st.st_size);
    if (rc != 0 || (st.st_mode & S_IFMT) != S_IFREG || st.st_size <= 0) failed = 1;

    memset(&stx_buf, 0, sizeof(stx_buf));
    errno = 0;
    rc = syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, stx);
    printf("statx_empty_rc:%ld errno:%d mode:%o size:%lld mask:%x sizeof_statx:%zu\n",
           rc, errno, (unsigned)(stx->stx_mode & 0170000),
           (long long)stx->stx_size, stx->stx_mask, sizeof(*stx));
    if (rc != 0 || (stx->stx_mode & S_IFMT) != S_IFREG || stx->stx_size <= 0) failed = 1;

    close(fd);
    printf("AT_EMPTY_PATH_STAT_%s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
