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
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_execveat
#define SYS_execveat 322
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static int run_execveat(int dirfd, const char *path, int flags, const char *label) {
    char *const argv[] = { "busybox", "true", NULL };
    char *const envp[] = { "PATH=/bin:/sbin:/usr/bin:/usr/sbin", NULL };
    long rc;

    rc = syscall(SYS_execveat, dirfd, path, argv, envp, flags);
    printf("%s_execveat_rc:%ld errno:%d\n", label, rc, errno);
    return 111;
}

int main(int argc, char **argv) {
    int fd;
    int dirfd;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc != 2) {
        printf("usage:%s empty|relative\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "empty") == 0) {
        fd = open("/bin/busybox", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            printf("open_busybox_rc:-1 errno:%d\n", errno);
            return 1;
        }
        return run_execveat(fd, "", AT_EMPTY_PATH, "empty_path");
    }

    if (strcmp(argv[1], "relative") == 0) {
        dirfd = open("/bin", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dirfd < 0) {
            printf("open_bindir_rc:-1 errno:%d\n", errno);
            return 1;
        }
        return run_execveat(dirfd, "busybox", 0, "relative_path");
    }

    printf("unknown_mode:%s\n", argv[1]);
    return 2;
}
