/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif

#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ 1032
#endif

int main(void) {
    int p[2];
    int size_r;
    int size_w;
    int rc;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (pipe(p) < 0) {
        printf("pipe_errno:%d\n", errno);
        return 1;
    }

    errno = 0;
    size_r = fcntl(p[0], F_GETPIPE_SZ);
    printf("getpipe_read:%d errno:%d\n", size_r, errno);
    if (size_r < 4096) return 1;

    errno = 0;
    size_w = fcntl(p[1], F_GETPIPE_SZ);
    printf("getpipe_write:%d errno:%d\n", size_w, errno);
    if (size_w != size_r) return 1;

    errno = 0;
    rc = fcntl(p[0], F_SETPIPE_SZ, size_r);
    printf("setpipe_same:%d errno:%d\n", rc, errno);
    if (rc != size_r) return 1;

    errno = 0;
    rc = fcntl(p[1], F_SETPIPE_SZ, 4096);
    printf("setpipe_smaller:%d errno:%d\n", rc, errno);
    if (rc != size_r) return 1;

    errno = 0;
    rc = fcntl(p[0], F_SETPIPE_SZ, 0);
    printf("setpipe_zero:%d errno:%d\n", rc, errno);
    if (rc != -1 || errno != EINVAL) return 1;

    errno = 0;
    rc = fcntl(p[0], F_SETPIPE_SZ, size_r + 4096);
    printf("setpipe_grow:%d errno:%d\n", rc, errno);
    if (rc != -1 || errno != EPERM) return 1;

    errno = 0;
    rc = fcntl(STDOUT_FILENO, F_GETPIPE_SZ);
    printf("getpipe_stdout:%d errno:%d\n", rc, errno);
    if (rc != -1 || errno != EBADF) return 1;

    close(p[0]);
    close(p[1]);

    printf("PIPE_FCNTL_PROBE_PASS\n");
    return 0;
}
