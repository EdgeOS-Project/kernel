/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 basic file, pipe and socket ABI probe. */

#include <stdint.h>

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_exit 60
#define X32_read 0
#define X32_open 2
#define X32_close 3
#define X32_stat 4
#define X32_fstat 5
#define X32_lseek 8
#define X32_pread64 17
#define X32_pwrite64 18
#define X32_pipe 22
#define X32_socketpair 53
#define X32_rename 82
#define X32_mkdir 83
#define X32_rmdir 84
#define X32_unlink 87
#define X32_getcwd 79
#define O_RDWR 2
#define O_CREAT 0100
#define O_EXCL 0200
#define SEEK_SET 0
#define AF_UNIX 1
#define SOCK_STREAM 1

static char path[] = "/x32-basic-io";
static char renamed[] = "/x32-basic-io-renamed";
static char data[] = "x32-uapi";
static char buffer[32];
static char cwd[16];
static uint8_t stat_buffer[144];
static int pipe_descriptors[2];
static int socket_descriptors[2];

static long raw(long number, long a0, long a1, long a2,
                long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a0),
                     "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static long x32(long number, long a0, long a1, long a2,
                long a3, long a4, long a5) {
    return raw((long)(X32_BIT | (uint64_t)number),
               a0, a1, a2, a3, a4, a5);
}

static unsigned long length(const char *text) {
    unsigned long result = 0;
    while (text[result]) ++result;
    return result;
}

static void text(const char *value) {
    raw(SYS_write, 1, (long)value, (long)length(value), 0, 0, 0);
}

static void number(long value) {
    char digits[24];
    unsigned long magnitude;
    unsigned long count = 0;
    if (value < 0) {
        text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1; left < right;
         ++left, --right) {
        char temporary = digits[left];
        digits[left] = digits[right];
        digits[right] = temporary;
    }
    raw(SYS_write, 1, (long)digits, (long)count, 0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    text("FAIL "); text(name); text(" expected="); number(expected);
    text(" actual="); number(actual); text("\n");
    return 1;
}

static int same(const char *left, const char *right, unsigned long count) {
    for (unsigned long index = 0; index < count; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

START_ATTRIBUTES void _start(void) {
    long descriptor;
    int failures = 0;

    failures += expect("getcwd", x32(X32_getcwd, (long)cwd,
                                      sizeof(cwd), 0, 0, 0, 0), 2);
    failures += expect("cwd-root", cwd[0], '/');
    descriptor = x32(X32_open, (long)path, O_RDWR | O_CREAT | O_EXCL,
                     0600, 0, 0, 0);
    if (descriptor < 0) {
        failures += expect("open", descriptor, 0);
    } else {
        failures += expect("write", x32(SYS_write, descriptor, (long)data,
                                         8, 0, 0, 0), 8);
        failures += expect("seek", x32(X32_lseek, descriptor, 0,
                                        SEEK_SET, 0, 0, 0), 0);
        failures += expect("read", x32(X32_read, descriptor, (long)buffer,
                                        8, 0, 0, 0), 8);
        failures += expect("read-data", same(buffer, data, 8), 1);
        failures += expect("pwrite", x32(X32_pwrite64, descriptor,
                                          (long)data, 8, 0, 0, 0), 8);
        failures += expect("pread", x32(X32_pread64, descriptor,
                                         (long)buffer, 8, 0, 0, 0), 8);
        failures += expect("fstat", x32(X32_fstat, descriptor,
                                         (long)stat_buffer, 0, 0, 0, 0), 0);
        failures += expect("close", x32(X32_close, descriptor,
                                         0, 0, 0, 0, 0), 0);
    }
    failures += expect("stat", x32(X32_stat, (long)path,
                                    (long)stat_buffer, 0, 0, 0, 0), 0);
    failures += expect("rename", x32(X32_rename, (long)path,
                                      (long)renamed, 0, 0, 0, 0), 0);
    failures += expect("unlink", x32(X32_unlink, (long)renamed,
                                      0, 0, 0, 0, 0), 0);
    failures += expect("mkdir", x32(X32_mkdir, (long)path, 0700,
                                     0, 0, 0, 0), 0);
    failures += expect("rmdir", x32(X32_rmdir, (long)path,
                                     0, 0, 0, 0, 0), 0);

    failures += expect("pipe", x32(X32_pipe, (long)pipe_descriptors,
                                    0, 0, 0, 0, 0), 0);
    failures += expect("pipe-write", x32(SYS_write, pipe_descriptors[1],
                                           (long)data, 8, 0, 0, 0), 8);
    failures += expect("pipe-read", x32(X32_read, pipe_descriptors[0],
                                         (long)buffer, 8, 0, 0, 0), 8);
    x32(X32_close, pipe_descriptors[0], 0, 0, 0, 0, 0);
    x32(X32_close, pipe_descriptors[1], 0, 0, 0, 0, 0);

    failures += expect("socketpair", x32(
        X32_socketpair, AF_UNIX, SOCK_STREAM, 0,
        (long)socket_descriptors, 0, 0), 0);
    if (!failures) {
        failures += expect("socket-write", x32(
            SYS_write, socket_descriptors[0], (long)data, 8, 0, 0, 0), 8);
        failures += expect("socket-read", x32(
            X32_read, socket_descriptors[1], (long)buffer, 8, 0, 0, 0), 8);
    }
    x32(X32_close, socket_descriptors[0], 0, 0, 0, 0, 0);
    x32(X32_close, socket_descriptors[1], 0, 0, 0, 0, 0);

    if (failures) {
        text("X32_BASIC_IO_ABI_PROBE_FAIL count="); number(failures); text("\n");
        raw(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    text("X32_BASIC_IO_ABI_PROBE_PASS\n");
    raw(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
