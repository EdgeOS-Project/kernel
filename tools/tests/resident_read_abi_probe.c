/* SPDX-License-Identifier: MPL-2.0 */
/* Read immutable file bytes through mappings and retained descriptions. */
#include <stdint.h>
#if defined(__x86_64__)
#define TEST_DEVICE "/dev/sda"
#define SYS_clock_gettime 228
#define SYS_mremap 25
#define SYS_read 0
#define SYS_write 1
#define SYS_openat 257
#define SYS_close 3
#define SYS_exit 60
#define SYS_lseek 8
#define SYS_pread 17
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_mount 165
#define SYS_umount2 166
#else
#define TEST_DEVICE "/dev/vda"
#define SYS_clock_gettime 113
#define SYS_mremap 216
#define SYS_read 63
#define SYS_write 64
#define SYS_openat 56
#define SYS_close 57
#define SYS_exit 93
#define SYS_lseek 62
#define SYS_pread 67
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_mount 40
#define SYS_umount2 39
#endif
static long raw_syscall6(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4,
                         long argument5) {
    long result;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = argument3;
    register long r8 __asm__("r8") = argument4;
    register long r9 __asm__("r9") = argument5;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    register long x3 __asm__("x3") = argument3;
    register long x4 __asm__("x4") = argument4;
    register long x5 __asm__("x5") = argument5;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    return raw_syscall6(number, argument0, argument1, argument2, argument3,
                        0, 0);
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall6(number, argument0, 0, 0, 0, 0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
}

static void putdec(long value) {
    char buffer[24];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        putstr("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    if (!magnitude) {
        putstr("0");
        return;
    }
    while (magnitude && position) {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    }
    (void)raw_syscall3(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned)position));
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": result=");
    putdec(actual);
    putstr(" expected=");
    putdec(expected);
    putstr("\n");
    return 1;
}



#define FILE_BYTES (4u * 4096u + 37u)
static unsigned char buffer[FILE_BYTES + 4096u];
static unsigned char pattern(unsigned long offset) {
    return (unsigned char)((offset * 17u + offset / 97u) % 251u);
}
static int read_range(long fd, unsigned long offset, unsigned long length) {
    unsigned long done = 0;
    while (done < length) {
        long count = raw_syscall4(SYS_pread, fd, (long)buffer,
                                  length - done, offset + done);
        if (count <= 0 || (unsigned long)count > length - done) {
            putstr("range failure offset="); putdec(offset + done);
            putstr(" result="); putdec(count); putstr("\n"); return 1;
        }
        for (long i = 0; i < count; ++i)
            if (buffer[i] != pattern(offset + done + (unsigned long)i)) {
                putstr("byte mismatch\n"); return 1;
            }
        done += (unsigned long)count;
    }
    return 0;
}
static long sparse_mappings[2048];
static uint64_t monotonic_us(void) {
    int64_t time[2] = {0, 0};
    if (raw_syscall3(SYS_clock_gettime, 1, (long)time, 0) < 0) return 0;
    return (uint64_t)time[0] * 1000000u + (uint64_t)time[1] / 1000u;
}
static int stress_gaps(long fd) {
    for (unsigned i = 0; i < 2048; ++i) {
        sparse_mappings[i] = raw_syscall6(SYS_mmap, 0, 4096, 1, 2, fd, 0);
        if ((unsigned long)sparse_mappings[i] >= (unsigned long)-4095)
            return expect_result("sparse map", sparse_mappings[i], 0);
    }
    long arena = raw_syscall6(SYS_mmap, 0, 512u * 4096u, 3, 0x22, -1, 0);
    if ((unsigned long)arena >= (unsigned long)-4095) return 1;
    uint64_t begin = monotonic_us();
    for (unsigned page = 0; page < 512; ++page)
        ((volatile unsigned char *)arena)[page * 4096u] = (unsigned char)page;
    uint64_t elapsed = monotonic_us() - begin;
    putstr("anonymous fault batch us="); putdec((long)elapsed); putstr("\n");
    int failures = 0;
    for (unsigned page = 0; page < 512; ++page)
        if (((volatile unsigned char *)arena)[page * 4096u] != (unsigned char)page)
            ++failures;
    long target = arena + 200u * 4096u;
    long moved = raw_syscall6(SYS_mremap, sparse_mappings[0], 4096, 4096,
                              3, target, 0);
    failures += expect_result("fixed mremap", moved, target);
    if (moved == target)
        failures += expect_result("moved file byte",
            ((volatile unsigned char *)target)[11], pattern(11));
    else
        raw_syscall3(SYS_munmap, sparse_mappings[0], 4096, 0);
    raw_syscall3(SYS_munmap, arena, 512u * 4096u, 0);
    for (unsigned i = 1; i < 2048; ++i)
        raw_syscall3(SYS_munmap, sparse_mappings[i], 4096, 0);
    return failures;
}
static int run_probe(void) {
#ifndef NATIVE_ORACLE
    long result = raw_syscall6(SYS_mount, (long)"devtmpfs", (long)"/dev",
                               (long)"devtmpfs", 0, 0, 0);
    if (result < 0) return expect_result("devtmpfs", result, 0);
    result = raw_syscall6(SYS_mount, (long)TEST_DEVICE, (long)"/mnt",
                          (long)"squashfs", 1, 0, 0);
    if (result < 0) return expect_result("squashfs", result, 0);
#define TEST_FILE "/mnt/pattern"
#else
#define TEST_FILE "/home/edgeos/edgeos-acceptance/r585-resident-read/pattern"
#endif
    long fd = raw_syscall4(SYS_openat, -100, (long)TEST_FILE, 0, 0);
    if (fd < 0) return expect_result("open", fd, 3);
    int failures = stress_gaps(fd);
    long private_map = raw_syscall6(SYS_mmap, 0, 3u * 4096u, 3, 2, fd, 0);
    long remap_target = raw_syscall6(SYS_mmap, 0, 4u * 4096u, 3, 0x22, -1, 0);
    if ((unsigned long)private_map >= (unsigned long)-4095 ||
        (unsigned long)remap_target >= (unsigned long)-4095) return 1;
    ((volatile unsigned char *)private_map)[11] = 0xa7;
    failures += expect_result("clean source byte",
        ((volatile unsigned char *)private_map)[4107], pattern(4107));
    long moved_private = raw_syscall6(SYS_mremap, private_map, 3u * 4096u,
                                      4u * 4096u, 3, remap_target, 0);
    failures += expect_result("private growth remap", moved_private, remap_target);
    if (moved_private == remap_target) {
        failures += expect_result("moved private byte",
            ((volatile unsigned char *)remap_target)[11], 0xa7);
        for (unsigned page = 1; page < 4; ++page)
            failures += expect_result("moved file offset",
                ((volatile unsigned char *)remap_target)[page * 4096u + 11u],
                pattern(page * 4096u + 11u));
        ((volatile unsigned char *)remap_target)[4107] = 0xb8;
    } else {
        raw_syscall3(SYS_munmap, private_map, 3u * 4096u, 0);
    }
    raw_syscall3(SYS_munmap, remap_target, 4u * 4096u, 0);
    failures += read_range(fd, 0, FILE_BYTES);

    failures += read_range(fd, 8197, 513);
    long mapping = raw_syscall6(SYS_mmap, 0, FILE_BYTES, 3, 2, fd, 0);
    if ((unsigned long)mapping >= (unsigned long)-4095)
        return expect_result("mmap", mapping, 0);
    volatile unsigned char *bytes = (volatile unsigned char *)mapping;
    for (unsigned long offset = 0; offset < FILE_BYTES; ++offset)
        if (bytes[offset] != pattern(offset)) { ++failures; break; }
    /* Warm a negative file-mapping lookup, then replace part of that gap. */
    long arena = raw_syscall6(SYS_mmap, 0, 64u * 4096u, 3, 0x22, -1, 0);
    if ((unsigned long)arena >= (unsigned long)-4095)
        return expect_result("anonymous arena", arena, 0);
    for (unsigned long page = 0; page < 64; ++page)
        ((volatile unsigned char *)arena)[page * 4096u] = (unsigned char)page;
    for (unsigned long round = 0; round < 8; ++round) {
        long target = arena + (long)(round + 8) * 4096;
        long fixed = raw_syscall6(SYS_mmap, target, 4096, 1, 0x12, fd, 4096);
        failures += expect_result("fixed file mapping", fixed, target);
        if (fixed == target)
            failures += expect_result("fixed file byte",
                ((volatile unsigned char *)target)[11], pattern(4107));
        failures += expect_result("fixed unmap",
            raw_syscall3(SYS_munmap, target, 4096, 0), 0);
        fixed = raw_syscall6(SYS_mmap, target, 4096, 3, 0x32, -1, 0);
        failures += expect_result("fixed anonymous mapping", fixed, target);
        if (fixed == target) {
            failures += expect_result("anonymous zero",
                ((volatile unsigned char *)target)[11], 0);
            ((volatile unsigned char *)target)[11] = 0x44;
        }
    }
    failures += expect_result("arena unmap",
        raw_syscall3(SYS_munmap, arena, 64u * 4096u, 0), 0);
    failures += read_range(fd, 3, FILE_BYTES - 3);
    bytes[4097] ^= 0x5a;
    failures += read_range(fd, 4093, 11);
    failures += expect_result("partial EOF",
        raw_syscall4(SYS_pread, fd, (long)buffer, 4096, FILE_BYTES - 7), 7);
    failures += expect_result("EOF",
        raw_syscall4(SYS_pread, fd, (long)buffer, 7, FILE_BYTES), 0);
    failures += expect_result("zero count",
        raw_syscall4(SYS_pread, fd, (long)buffer, 0, 0), 0);
    failures += expect_result("negative offset",
        raw_syscall4(SYS_pread, fd, (long)buffer, 1, -1), -22);
    failures += expect_result("pread position",
        raw_syscall3(SYS_lseek, fd, 0, 1), 0);
    failures += expect_result("read",
        raw_syscall3(SYS_read, fd, (long)buffer, 19), 19);
    failures += expect_result("read position",
        raw_syscall3(SYS_lseek, fd, 0, 1), 19);
#ifndef NATIVE_ORACLE
    failures += expect_result("lazy unmount",
        raw_syscall3(SYS_umount2, (long)"/mnt", 2, 0), 0);
    failures += read_range(fd, 8191, 8193);
#endif
    raw_syscall3(SYS_munmap, mapping, FILE_BYTES, 0);
    raw_syscall1(SYS_close, fd);
    return failures;
}
static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    int result = run_probe();
    putstr(result ? "RESIDENT_READ_FAIL\n" : "RESIDENT_READ_PASS\n");
    raw_syscall1(SYS_exit, result ? 1 : 0);
    for (;;) {}
}
#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ __volatile__("andq $-16, %rsp\ncall probe_entry\n");
}
#else
void _start(void) { probe_entry(); }
#endif
