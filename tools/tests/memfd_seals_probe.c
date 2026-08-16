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
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif

static int xmemfd_create(const char *name, unsigned int flags) {
    return (int)syscall(SYS_memfd_create, name, flags);
}

int main(void) {
    int fd;
    int seals;
    int rc;
    char buf[8];
    char *map;

    setvbuf(stdout, NULL, _IONBF, 0);

    fd = xmemfd_create("edgeos-memfd-probe", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    printf("memfd_fd:%d errno:%d\n", fd, errno);
    if (fd < 0) return 1;

    if (write(fd, "abc", 3) != 3) {
        printf("memfd_write_errno:%d\n", errno);
        return 1;
    }
    if (ftruncate(fd, 4096) < 0) {
        printf("memfd_ftruncate_errno:%d\n", errno);
        return 1;
    }

    map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("memfd_mmap:%p errno:%d\n", (void *)map, errno);
    if (map == MAP_FAILED) return 1;
    map[0] = 'z';
    memset(buf, 0, sizeof(buf));
    if (pread(fd, buf, 1, 0) != 1 || buf[0] != 'z') {
        printf("memfd_shared_visible:%c errno:%d\n", buf[0], errno);
        return 1;
    }

    errno = 0;
    rc = fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE);
    printf("seal_write_busy:%d errno:%d\n", rc, errno);
    if (rc != -1 || errno != EBUSY) return 1;
    if (munmap(map, 4096) < 0) return 1;

    errno = 0;
    rc = fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE);
    printf("seal_future_write:%d errno:%d\n", rc, errno);
    if (rc < 0) return 1;
    errno = 0;
    rc = (int)write(fd, "y", 1);
    printf("seal_future_write_write:%d errno:%d\n", rc, errno);
    if (rc != -1 || errno != EPERM) return 1;

    errno = 0;
    rc = fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
    printf("seal_add:%d errno:%d\n", rc, errno);
    if (rc < 0) return 1;

    seals = fcntl(fd, F_GET_SEALS);
    printf("seal_get:0x%x errno:%d\n", seals, errno);
    if ((seals & (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) !=
        (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) return 1;

    errno = 0;
    rc = ftruncate(fd, 8192);
    printf("seal_grow:%d errno:%d\n", rc, errno);
    if (rc != -1 || errno != EPERM) return 1;

    errno = 0;
    rc = ftruncate(fd, 1024);
    printf("seal_shrink:%d errno:%d\n", rc, errno);
    if (rc != -1 || errno != EPERM) return 1;

    errno = 0;
    rc = (int)write(fd, "x", 1);
    printf("seal_write:%d errno:%d\n", rc, errno);
    if (rc != -1 || errno != EPERM) return 1;

    close(fd);
    printf("MEMFD_SEALS_PROBE_PASS\n");
    return 0;
}
