/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux sparse memfd mapping ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef SYS_memfd_create
#if defined(__aarch64__)
#define SYS_memfd_create 279
#elif defined(__x86_64__)
#define SYS_memfd_create 319
#else
#error "memfd_sparse_mmap_abi_probe requires a Linux 64-bit architecture"
#endif
#endif

#define PAGE_SIZE 4096UL
#define INITIAL_SIZE (64UL * 1024UL * 1024UL)
#define REMAPPED_SIZE (80UL * 1024UL * 1024UL)

static int check(int condition, const char *name) {
    if (condition) return 0;
    printf("FAIL %s errno=%d\n", name, errno);
    return 1;
}

int main(void) {
    unsigned char vector;
    unsigned char value;
    unsigned char *mapping;
    unsigned char *remapped;
    void *collision;
    pid_t child;
    int status = 0;
    int failures = 0;
    int fd;

    setvbuf(stdout, NULL, _IONBF, 0);
    fd = (int)syscall(SYS_memfd_create, "edgeos-sparse-memfd", MFD_CLOEXEC);
    failures += check(fd >= 0, "memfd_create");
    if (fd < 0) return 1;
    failures += check(ftruncate(fd, (off_t)INITIAL_SIZE) == 0,
                      "ftruncate initial");
    mapping = mmap(NULL, INITIAL_SIZE, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    failures += check(mapping != MAP_FAILED, "mmap sparse 64 MiB");
    if (mapping == MAP_FAILED) return 1;

    vector = 0xff;
    failures += check(mincore(mapping, PAGE_SIZE, &vector) == 0,
                      "mincore first lazy page");
    failures += check((vector & 1u) == 0, "first page initially nonresident");
    vector = 0xff;
    failures += check(mincore(mapping + INITIAL_SIZE - PAGE_SIZE,
                              PAGE_SIZE, &vector) == 0,
                      "mincore last lazy page");
    failures += check((vector & 1u) == 0, "last page initially nonresident");

    mapping[0] = 0x5a;
    mapping[INITIAL_SIZE - 1] = 0xa5;
    failures += check(pread(fd, &value, 1, 0) == 1 && value == 0x5a,
                      "faulted write visible through pread");
    failures += check(pread(fd, &value, 1, INITIAL_SIZE - 1) == 1 &&
                      value == 0xa5, "last faulted write visible");

    mapping[PAGE_SIZE] = 0;
    failures += check(pread(fd, mapping + PAGE_SIZE, 1, 0) == 1 &&
                      mapping[PAGE_SIZE] == 0x5a,
                      "kernel copy_to_user resolves lazy page");
    failures += check(pwrite(fd, mapping + 2 * PAGE_SIZE, 1,
                             4 * PAGE_SIZE) == 1,
                      "kernel copy_from_user resolves lazy page");
    value = 0xff;
    failures += check(pread(fd, &value, 1, 4 * PAGE_SIZE) == 1 && value == 0,
                      "lazy zero page copied through pwrite");

    failures += check(mprotect(mapping + 3 * PAGE_SIZE, PAGE_SIZE,
                               PROT_READ) == 0,
                      "mprotect lazy page");
    vector = 0xff;
    failures += check(mincore(mapping + 3 * PAGE_SIZE,
                              PAGE_SIZE, &vector) == 0 &&
                      (vector & 1u) == 0,
                      "mprotect preserves laziness");
    value = mapping[3 * PAGE_SIZE];
    failures += check(value == 0, "read fault after mprotect");
    failures += check(mprotect(mapping + 3 * PAGE_SIZE, PAGE_SIZE,
                               PROT_READ | PROT_WRITE) == 0,
                      "mprotect restore write");

    errno = 0;
    collision = mmap(mapping + 5 * PAGE_SIZE, PAGE_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                     -1, 0);
    failures += check(collision == MAP_FAILED && errno == EEXIST,
                      "MAP_FIXED_NOREPLACE sees lazy VMA");
    failures += check(msync(mapping, INITIAL_SIZE, MS_SYNC) == 0,
                      "msync sparse range");

    child = fork();
    failures += check(child >= 0, "fork");
    if (child == 0) {
        if (mapping[0] != 0x5a || mapping[INITIAL_SIZE - 1] != 0xa5)
            _exit(2);
        mapping[6 * PAGE_SIZE] = 0x6c;
        _exit(0);
    }
    if (child > 0) {
        failures += check(waitpid(child, &status, 0) == child,
                          "waitpid child");
        failures += check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                          "child shared mapping");
        failures += check(mapping[6 * PAGE_SIZE] == 0x6c,
                          "child fault visible to parent");
    }

    failures += check(ftruncate(fd, (off_t)REMAPPED_SIZE) == 0,
                      "ftruncate remap size");
    remapped = mremap(mapping, INITIAL_SIZE, REMAPPED_SIZE, MREMAP_MAYMOVE);
    failures += check(remapped != MAP_FAILED, "mremap sparse mapping");
    if (remapped != MAP_FAILED) {
        remapped[REMAPPED_SIZE - 1] = 0x7e;
        value = 0;
        failures += check(pread(fd, &value, 1, REMAPPED_SIZE - 1) == 1 &&
                          value == 0x7e, "mremap extension fault");
        failures += check(munmap(remapped, REMAPPED_SIZE) == 0,
                          "munmap remapped range");
    } else {
        (void)munmap(mapping, INITIAL_SIZE);
    }
    close(fd);

    if (failures) {
        printf("MEMFD_SPARSE_MMAP_ABI_PROBE_FAIL failures=%d\n", failures);
        return 1;
    }
    printf("MEMFD_SPARSE_MMAP_ABI_PROBE_PASS\n");
    return 0;
}
