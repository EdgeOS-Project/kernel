/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int write_all(int fd, const char *s) {
    size_t len = strlen(s);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, s + off, len - off);
        if (n < 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

int main(void) {
    const char *tmp = "/usr/lib/.apk.e30fa1e096050138dacf1740229ff224a251e515acb35b43";
    const char *dst = "/usr/lib/edgeos-apk-extract-probe.so.1.0.0";
    const char *ltmp = "/usr/lib/.apk.symlink-e30fa1e096050138dacf1740229ff224a251e515acb35b43";
    const char *ldst = "/usr/lib/edgeos-apk-extract-probe.so.1";
    struct stat st;
    int fd;
    int failed = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    unlink(tmp);
    unlink(dst);
    unlink(ltmp);
    unlink(ldst);

    fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    printf("apk_probe_open_fd:%d errno:%d\n", fd, errno);
    if (fd < 0) return 1;

    if (write_all(fd, "edgeos apk extraction probe\n") < 0) {
        printf("apk_probe_write_failed errno:%d\n", errno);
        failed = 1;
    }

    errno = 0;
    if (fchown(fd, 0, 0) < 0) {
        printf("apk_probe_fchown_failed errno:%d\n", errno);
        failed = 1;
    } else {
        printf("apk_probe_fchown_ok\n");
    }

    if (close(fd) < 0) {
        printf("apk_probe_close_failed errno:%d\n", errno);
        failed = 1;
    }

    errno = 0;
    if (rename(tmp, dst) < 0) {
        printf("apk_probe_rename_failed errno:%d\n", errno);
        failed = 1;
    } else {
        printf("apk_probe_rename_ok\n");
    }

    memset(&st, 0, sizeof(st));
    errno = 0;
    if (stat(dst, &st) < 0) {
        printf("apk_probe_stat_failed errno:%d\n", errno);
        failed = 1;
    } else {
        printf("apk_probe_stat_ok mode:%o uid:%lu gid:%lu size:%lld\n",
               (unsigned)(st.st_mode & 07777),
               (unsigned long)st.st_uid,
               (unsigned long)st.st_gid,
               (long long)st.st_size);
        if (st.st_uid != 0 || st.st_gid != 0 || st.st_size <= 0) failed = 1;
    }

    unlink(dst);
    errno = 0;
    if (symlink("edgeos-apk-extract-probe.so.1.0.0", ltmp) < 0) {
        printf("apk_probe_symlink_create_failed errno:%d\n", errno);
        failed = 1;
    } else {
        printf("apk_probe_symlink_create_ok\n");
    }

    errno = 0;
    if (lchown(ltmp, 0, 0) < 0) {
        printf("apk_probe_lchown_failed errno:%d\n", errno);
        failed = 1;
    } else {
        printf("apk_probe_lchown_ok\n");
    }

    errno = 0;
    if (syscall(SYS_fchownat, AT_FDCWD, ltmp, 0, 0, AT_SYMLINK_NOFOLLOW) < 0) {
        printf("apk_probe_fchownat_nofollow_failed errno:%d\n", errno);
        failed = 1;
    } else {
        printf("apk_probe_fchownat_nofollow_ok\n");
    }

    errno = 0;
    if (rename(ltmp, ldst) < 0) {
        printf("apk_probe_symlink_rename_failed errno:%d\n", errno);
        failed = 1;
    } else {
        printf("apk_probe_symlink_rename_ok\n");
    }

    memset(&st, 0, sizeof(st));
    errno = 0;
    if (lstat(ldst, &st) < 0) {
        printf("apk_probe_lstat_symlink_failed errno:%d\n", errno);
        failed = 1;
    } else {
        printf("apk_probe_lstat_symlink_ok mode:%o uid:%lu gid:%lu size:%lld\n",
               (unsigned)(st.st_mode & 0177777),
               (unsigned long)st.st_uid,
               (unsigned long)st.st_gid,
               (long long)st.st_size);
        if ((st.st_mode & S_IFMT) != S_IFLNK || st.st_uid != 0 || st.st_gid != 0) failed = 1;
    }

    unlink(ldst);
    printf("APK_EXTRACT_PROBE_%s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
