/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux mmap hint ABI regression test.
 * Copyright (c) EdgeOS Contributors.
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

static long raw_mmap_with_fd(uint64_t descriptor) {
#if defined(__x86_64__)
    register uint64_t r10 __asm__("r10") = MAP_PRIVATE;
    register uint64_t r8 __asm__("r8") = descriptor;
    register uint64_t r9 __asm__("r9") = 0;
    register uint64_t rax __asm__("rax") = SYS_mmap;
    register uint64_t rdi __asm__("rdi") = 0;
    register uint64_t rsi __asm__("rsi") = 4096;
    register uint64_t rdx __asm__("rdx") = PROT_READ;

    __asm__ volatile("syscall"
                     : "+a"(rax)
                     : "D"(rdi), "S"(rsi), "d"(rdx), "r"(r10),
                       "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return (long)rax;
#elif defined(__aarch64__)
    register uint64_t x0 __asm__("x0") = 0;
    register uint64_t x1 __asm__("x1") = 4096;
    register uint64_t x2 __asm__("x2") = PROT_READ;
    register uint64_t x3 __asm__("x3") = MAP_PRIVATE;
    register uint64_t x4 __asm__("x4") = descriptor;
    register uint64_t x5 __asm__("x5") = 0;
    register uint64_t x8 __asm__("x8") = SYS_mmap;

    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5),
                       "r"(x8)
                     : "memory");
    return (long)x0;
#else
#error "raw mmap regression requires x86_64 or AArch64"
#endif
}

static int expect_low_hint_fallback(void) {
    const size_t length = 0xf0000;
    void *const hint = (void *)(uintptr_t)0x10000;
    void *mapping;

    errno = 0;
    mapping = mmap(hint, length, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        fprintf(stderr, "mmap low hint failed: %s\n", strerror(errno));
        return 1;
    }
    if ((uintptr_t)mapping < (uintptr_t)getpagesize()) {
        fprintf(stderr, "mmap returned invalid address %p\n", mapping);
        munmap(mapping, length);
        return 1;
    }
    if (munmap(mapping, length) != 0) {
        fprintf(stderr, "munmap failed: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

static int expect_noreplace_collision(void) {
    const size_t length = (size_t)getpagesize();
    void *mapping;
    void *collision;

    mapping = mmap(NULL, length, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        fprintf(stderr, "initial mmap failed: %s\n", strerror(errno));
        return 1;
    }
    errno = 0;
    collision = mmap(mapping, length, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                     -1, 0);
    if (collision != MAP_FAILED || errno != EEXIST) {
        fprintf(stderr,
                "MAP_FIXED_NOREPLACE collision returned %p errno=%d\n",
                collision, errno);
        if (collision != MAP_FAILED) munmap(collision, length);
        munmap(mapping, length);
        return 1;
    }
    if (munmap(mapping, length) != 0) {
        fprintf(stderr, "final munmap failed: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

static int expect_int_descriptor_conversion(void) {
    int descriptor = open("/dev/zero", O_RDONLY);
    uint64_t dirty_descriptor;
    long result;

    if (descriptor < 0) {
        fprintf(stderr, "open /dev/zero failed: %s\n", strerror(errno));
        return 1;
    }
    dirty_descriptor = (UINT64_C(0x29) << 32) | (uint32_t)descriptor;
    result = raw_mmap_with_fd(dirty_descriptor);
    if (result < 0) {
        fprintf(stderr,
                "mmap rejected int fd with upper bits set: errno=%ld\n",
                -result);
        close(descriptor);
        return 1;
    }
    if (munmap((void *)(uintptr_t)result, 4096) != 0) {
        fprintf(stderr, "dirty-fd munmap failed: %s\n", strerror(errno));
        close(descriptor);
        return 1;
    }
    close(descriptor);
    return 0;
}

static int expect_large_sparse_reservation(void) {
    const size_t length = (UINT64_C(4) << 30) + UINT64_C(0xf0000);
    void *mapping;

    if (sizeof(size_t) < sizeof(uint64_t)) return 0;
    mapping = mmap(NULL, length, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        fprintf(stderr, "large sparse mmap failed: %s\n", strerror(errno));
        return 1;
    }
    if (munmap(mapping, length) != 0) {
        fprintf(stderr, "large sparse munmap failed: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

int main(void) {
    if (expect_low_hint_fallback() != 0) return 1;
    if (expect_noreplace_collision() != 0) return 1;
    if (expect_int_descriptor_conversion() != 0) return 1;
    if (expect_large_sparse_reservation() != 0) return 1;
    puts("mmap hint ABI: PASS");
    return 0;
}
