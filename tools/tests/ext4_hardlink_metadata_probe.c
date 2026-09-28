/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Exercise the metadata sequence used by apk when committing package files.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void fail_errno(const char *operation) {
    fprintf(stderr, "%s: %s\n", operation, strerror(errno));
    ++failures;
}

static void expect_links(const char *phase, const char *left,
                         const char *right, int fd, nlink_t expected) {
    struct stat left_stat;
    struct stat right_stat;
    struct stat fd_stat;
    struct statx left_statx;

    memset(&left_stat, 0, sizeof(left_stat));
    memset(&right_stat, 0, sizeof(right_stat));
    memset(&fd_stat, 0, sizeof(fd_stat));
    memset(&left_statx, 0, sizeof(left_statx));
    if (left && stat(left, &left_stat) < 0) {
        fail_errno("stat(left)");
        return;
    }
    if (right && stat(right, &right_stat) < 0) {
        fail_errno("stat(right)");
        return;
    }
    if (fstat(fd, &fd_stat) < 0) {
        fail_errno("fstat");
        return;
    }
    if (left && statx(AT_FDCWD, left, 0, STATX_BASIC_STATS, &left_statx) < 0) {
        fail_errno("statx");
        return;
    }
    if ((left && left_stat.st_nlink != expected) ||
        (right && right_stat.st_nlink != expected) ||
        fd_stat.st_nlink != expected ||
        (left && left_statx.stx_nlink != expected)) {
        fprintf(stderr,
                "%s: expected links=%lu, got stat=%lu peer=%lu fstat=%lu statx=%u\n",
                phase, (unsigned long)expected,
                left ? (unsigned long)left_stat.st_nlink : 0ul,
                right ? (unsigned long)right_stat.st_nlink : 0ul,
                (unsigned long)fd_stat.st_nlink,
                left ? left_statx.stx_nlink : 0u);
        ++failures;
    }
    if (left && right && left_stat.st_ino != right_stat.st_ino) {
        fprintf(stderr, "%s: hard links have different inode numbers\n", phase);
        ++failures;
    }
    printf("%s inode=%lu links=%lu\n", phase,
           (unsigned long)fd_stat.st_ino,
           (unsigned long)fd_stat.st_nlink);
}

int main(int argc, char **argv) {
    const char *parent = argc > 1 ? argv[1] : "/tmp";
    char directory[512];
    char temporary_a[640];
    char temporary_b[640];
    char final_a[640];
    char final_b[640];
    const char payload[] = "EdgeOS hard-link metadata probe\n";
    const char attribute[] = "package-metadata";
    char attribute_readback[sizeof(attribute)];
    struct timespec times[2];
    int fd = -1;

    if (snprintf(directory, sizeof(directory), "%s/edgeos-hardlink-XXXXXX",
                 parent) >= (int)sizeof(directory) || !mkdtemp(directory)) {
        fail_errno("mkdtemp");
        return 1;
    }
    snprintf(temporary_a, sizeof(temporary_a), "%s/.apk.A", directory);
    snprintf(temporary_b, sizeof(temporary_b), "%s/.apk.B", directory);
    snprintf(final_a, sizeof(final_a), "%s/final-A", directory);
    snprintf(final_b, sizeof(final_b), "%s/final-B", directory);

    fd = open(temporary_a, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0) fail_errno("open");
    if (fd >= 0 && write(fd, payload, sizeof(payload) - 1) !=
                       (ssize_t)(sizeof(payload) - 1))
        fail_errno("write");
    if (fd < 0) goto cleanup;
    expect_links("created", temporary_a, NULL, fd, 1);

    if (link(temporary_a, temporary_b) < 0) fail_errno("link");
    expect_links("linked", temporary_a, temporary_b, fd, 2);

    if (fchmod(fd, 0640) < 0) fail_errno("fchmod");
    if (fchown(fd, getuid(), getgid()) < 0) fail_errno("fchown");
    times[0].tv_sec = 1577934245;
    times[0].tv_nsec = 123456789;
    times[1].tv_sec = 1577934246;
    times[1].tv_nsec = 987654321;
    if (futimens(fd, times) < 0) fail_errno("futimens");
    if (fsetxattr(fd, "user.edgeos.package", attribute,
                  sizeof(attribute) - 1, 0) < 0)
        fail_errno("fsetxattr");
    memset(attribute_readback, 0, sizeof(attribute_readback));
    if (getxattr(temporary_b, "user.edgeos.package", attribute_readback,
                 sizeof(attribute_readback)) != (ssize_t)(sizeof(attribute) - 1) ||
        memcmp(attribute, attribute_readback, sizeof(attribute) - 1) != 0) {
        fprintf(stderr, "getxattr: hard-link attribute did not round-trip\n");
        ++failures;
    }
    expect_links("metadata", temporary_a, temporary_b, fd, 2);

    if (rename(temporary_a, final_a) < 0) fail_errno("rename(first)");
    if (rename(temporary_b, final_b) < 0) fail_errno("rename(second)");
    expect_links("renamed", final_a, final_b, fd, 2);

    if (unlink(final_b) < 0) fail_errno("unlink(peer)");
    expect_links("single-link", final_a, NULL, fd, 1);
    if (unlink(final_a) < 0) fail_errno("unlink(last)");
    expect_links("open-unlinked", NULL, NULL, fd, 0);

cleanup:
    if (fd >= 0 && close(fd) < 0) fail_errno("close");
    unlink(temporary_a);
    unlink(temporary_b);
    unlink(final_a);
    unlink(final_b);
    if (rmdir(directory) < 0) fail_errno("rmdir");
    if (failures) {
        fprintf(stderr, "EXT4_HARDLINK_METADATA_PROBE_FAIL failures=%d\n",
                failures);
        return 1;
    }
    puts("EXT4_HARDLINK_METADATA_PROBE_PASS");
    return 0;
}
