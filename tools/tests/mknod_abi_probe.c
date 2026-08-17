/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS mknod and mknodat Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_mkdir 83
#define SYS_umask 95
#define SYS_setuid 105
#define SYS_setgid 106
#define SYS_capget 125
#define SYS_capset 126
#define SYS_mknod 133
#define SYS_openat 257
#define SYS_mknodat 259
#define SYS_unlinkat 263
#define SYS_fchmodat 268
#define SYS_statx 332
#elif defined(__aarch64__)
#define SYS_mknodat 33
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_fchmodat 53
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_capget 90
#define SYS_capset 91
#define SYS_setgid 144
#define SYS_setuid 146
#define SYS_umask 166
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_statx 291
#else
#error "mknod_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define AT_REMOVEDIR 0x200
#define AT_SYMLINK_NOFOLLOW 0x100
#define O_RDONLY 0
#define O_DIRECTORY 0x10000
#define O_CLOEXEC 0x80000
#define S_IFMT 0xf000
#define S_IFIFO 0x1000
#define S_IFCHR 0x2000
#define S_IFDIR 0x4000
#define S_IFBLK 0x6000
#define S_IFREG 0x8000
#define S_IFLNK 0xa000
#define S_IFSOCK 0xc000
#define EFAULT 14
#define EBADF 9
#define EEXIST 17
#define ENOENT 2
#define ENOTDIR 20
#define EPERM 1
#define EINVAL 22
#define CAP_MKNOD 27
#define SIGCHLD 17
#define LINUX_CAPABILITY_VERSION_3 0x20080522u
#define STATX_BASIC_STATS 0x000007ffu

struct cap_header {
    uint32_t version;
    int32_t pid;
};

struct cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

struct statx_timestamp {
    int64_t seconds;
    uint32_t nanoseconds;
    int32_t reserved;
};

struct statx_result {
    uint32_t mask;
    uint32_t block_size;
    uint64_t attributes;
    uint32_t links;
    uint32_t uid;
    uint32_t gid;
    uint16_t mode;
    uint16_t reserved0;
    uint64_t inode;
    uint64_t size;
    uint64_t blocks;
    uint64_t attributes_mask;
    struct statx_timestamp access_time;
    struct statx_timestamp birth_time;
    struct statx_timestamp change_time;
    struct statx_timestamp modification_time;
    uint32_t rdev_major;
    uint32_t rdev_minor;
    uint32_t dev_major;
    uint32_t dev_minor;
    uint64_t mount_id;
    uint8_t tail[104];
};

_Static_assert(sizeof(struct statx_result) == 256,
               "Linux statx size mismatch");

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#endif
}

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void copy_bytes(void *destination, const void *source,
                       unsigned long length) {
    unsigned char *out = destination;
    const unsigned char *in = source;
    while (length--) *out++ = *in++;
}

static void zero_bytes(void *destination, unsigned long length) {
    unsigned char *out = destination;
    while (length--) *out++ = 0;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char buffer[32];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned long)position),
                       0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static int append_text(char *destination, unsigned long capacity,
                       const char *source) {
    unsigned long used = string_length(destination);
    unsigned long added = string_length(source);
    if (used + added + 1u > capacity) return -1;
    copy_bytes(destination + used, source, added + 1u);
    return 0;
}

static int append_number(char *destination, unsigned long capacity,
                         unsigned long value) {
    char digits[24];
    int position = (int)sizeof(digits);
    do {
        digits[--position] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    digits[sizeof(digits) - 1u] = 0;
    return append_text(destination, capacity, &digits[position]);
}

static long create_directory(const char *path) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_mkdir, (long)path, 0777, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_mkdirat, AT_FDCWD, (long)path, 0777, 0, 0, 0);
#endif
}

static long create_node(long directory, const char *path,
                        long mode, unsigned long device) {
    return raw_syscall6(SYS_mknodat, directory, (long)path, mode,
                        (long)device, 0, 0);
}

static long stat_node(long directory, const char *path,
                      struct statx_result *result) {
    zero_bytes(result, sizeof(*result));
    return raw_syscall6(SYS_statx, directory, (long)path,
                        AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS,
                        (long)result, 0);
}

static int expect_node(const char *name, long directory, const char *path,
                       uint16_t type, uint16_t permissions,
                       uint32_t rdev_major, uint32_t rdev_minor) {
    struct statx_result result;
    long status = stat_node(directory, path, &result);
    if (status < 0) return expect_result(name, status, 0);
    if ((result.mode & S_IFMT) == type &&
        (result.mode & 07777u) == permissions &&
        result.rdev_major == rdev_major &&
        result.rdev_minor == rdev_minor)
        return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" mode=");
    print_number(result.mode);
    print_text(" rdev=");
    print_number(result.rdev_major);
    print_text(":");
    print_number(result.rdev_minor);
    print_text("\n");
    return 1;
}

static int set_capabilities(struct cap_header *header,
                            struct cap_data data[2]) {
    return (int)raw_syscall6(SYS_capset, (long)header, (long)data,
                             0, 0, 0, 0);
}

static int test_capability(long directory) {
    struct cap_header header = {LINUX_CAPABILITY_VERSION_3, 0};
    struct cap_data saved[2];
    struct cap_data dropped[2];
    unsigned int word = CAP_MKNOD / 32u;
    uint32_t bit = 1u << (CAP_MKNOD % 32u);
    long status;
    int failures = 0;

    zero_bytes(saved, sizeof(saved));
    status = raw_syscall6(SYS_capget, (long)&header, (long)saved,
                          0, 0, 0, 0);
    failures += expect_result("capget", status, 0);
    if (status < 0) return failures;
    if (!(saved[word].effective & bit) || !(saved[word].permitted & bit)) {
        print_text("FAIL CAP_MKNOD unavailable\n");
        return failures + 1;
    }
    copy_bytes(dropped, saved, sizeof(dropped));
    dropped[word].effective &= ~bit;
    failures += expect_result("drop CAP_MKNOD",
                              set_capabilities(&header, dropped), 0);
    failures += expect_result("existing before capability",
                              create_node(directory, "character",
                                          S_IFCHR | 0600, 0x103u),
                              -EEXIST);
    failures += expect_result("CAP_MKNOD required",
                              create_node(directory, "denied-character",
                                          S_IFCHR | 0600, 0x103u),
                              -EPERM);
    failures += expect_result("restore CAP_MKNOD",
                              set_capabilities(&header, saved), 0);
    return failures;
}

static int test_sticky_directory_creation(long directory) {
    int status = -1;
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    long waited;
    int failures = 0;

    if (child < 0)
        return expect_result("clone sticky child", child, 0);
    if (child == 0) {
        long result;
        if (raw_syscall6(SYS_setgid, 65534, 0, 0, 0, 0, 0) < 0 ||
            raw_syscall6(SYS_setuid, 65534, 0, 0, 0, 0, 0) < 0)
            raw_syscall6(SYS_exit, 2, 0, 0, 0, 0, 0);
        result = create_node(directory, "unprivileged",
                             S_IFREG | 0600, 0);
        raw_syscall6(SYS_exit, result == 0 ? 0 : 3, 0, 0, 0, 0, 0);
        for (;;) { }
    }
    waited = raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0);
    failures += expect_result("wait sticky child", waited, child);
    failures += expect_result("sticky creation child status", status, 0);
    failures += expect_node("sticky creation metadata", directory,
                            "unprivileged", S_IFREG, 0600, 0, 0);
    return failures;
}

static void remove_node(long directory, const char *path) {
    (void)raw_syscall6(SYS_unlinkat, directory, (long)path, 0, 0, 0, 0);
}

static int run_probe(void) {
    char directory[64] = "/tmp/edge-mknod-";
    char absolute[96];
    long directory_fd;
    long regular_fd;
    int failures = 0;

    if (append_number(directory, sizeof(directory),
                      (unsigned long)raw_syscall6(
                          SYS_getpid, 0, 0, 0, 0, 0, 0)) < 0)
        return 1;
    copy_bytes(absolute, directory, string_length(directory) + 1u);
    if (append_text(absolute, sizeof(absolute), "/absolute") < 0)
        return 1;
    failures += expect_result("mkdir", create_directory(directory), 0);
    directory_fd = raw_syscall6(SYS_openat, AT_FDCWD, (long)directory,
                                O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                                0, 0, 0);
    if (directory_fd < 0) {
        failures += expect_result("open directory", directory_fd, 0);
        return failures;
    }
    failures += expect_result("sticky directory mode", raw_syscall6(
        SYS_fchmodat, AT_FDCWD, (long)directory, 01777, 0, 0, 0), 0);

    (void)raw_syscall6(SYS_umask, 0027, 0, 0, 0, 0, 0);
    failures += expect_result("invalid mode before null path",
                              create_node(directory_fd, 0,
                                          S_IFLNK | 0600, 0), -EINVAL);
    failures += expect_result("null path",
                              create_node(directory_fd, 0,
                                          S_IFREG | 0600, 0), -EFAULT);
    failures += expect_result("empty path before lookup",
                              create_node(directory_fd, "", S_IFREG, 0),
                              -ENOENT);
    failures += expect_result("directory type rejected",
                              create_node(directory_fd, "bad-dir",
                                          S_IFDIR | 0700, 0), -EPERM);
    failures += expect_result("invalid type rejected",
                              create_node(-9, "bad-kind",
                                          S_IFLNK | 0700, 0), -EINVAL);
    failures += expect_result("bad relative dirfd",
                              create_node(-9, "relative", S_IFREG | 0600, 0),
                              -EBADF);
    failures += expect_result("absolute ignores dirfd",
                              create_node(-9, absolute, S_IFREG | 0604, 0), 0);
    failures += expect_node("absolute metadata", AT_FDCWD, absolute,
                            S_IFREG, 0600, 0, 0);

    failures += expect_result("regular", create_node(
        directory_fd, "regular", S_IFREG | 0666, 0x103u), 0);
    failures += expect_node("regular metadata", directory_fd, "regular",
                            S_IFREG, 0640, 0, 0);
    failures += expect_result("zero type and mode", create_node(
        directory_fd, "zero", 0, 0), 0);
    failures += expect_node("zero metadata", directory_fd, "zero",
                            S_IFREG, 0, 0, 0);
    failures += expect_result("fifo", create_node(
        directory_fd, "fifo", S_IFIFO | 0666, 0xffffffffu), 0);
    failures += expect_node("fifo metadata", directory_fd, "fifo",
                            S_IFIFO, 0640, 0, 0);
    failures += expect_result("socket", create_node(
        directory_fd, "socket", S_IFSOCK | 0677, 0xffffffffu), 0);
    failures += expect_node("socket metadata", directory_fd, "socket",
                            S_IFSOCK, 0650, 0, 0);
    failures += expect_result("character", create_node(
        directory_fd, "character", S_IFCHR | 0666, 0x100000103ull), 0);
    failures += expect_node("character metadata", directory_fd, "character",
                            S_IFCHR, 0640, 1, 3);
    failures += expect_result("block", create_node(
        directory_fd, "block", S_IFBLK | 0600, 0x807u), 0);
    failures += expect_node("block metadata", directory_fd, "block",
                            S_IFBLK, 0600, 8, 7);
    failures += expect_result("existing", create_node(
        directory_fd, "regular", S_IFREG | 0600, 0), -EEXIST);
    failures += expect_result("missing trailing slash", create_node(
        directory_fd, "trailing/", S_IFREG | 0600, 0), -ENOENT);

    regular_fd = raw_syscall6(SYS_openat, directory_fd, (long)"regular",
                              O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (regular_fd < 0) {
        failures += expect_result("open regular", regular_fd, 0);
    } else {
        failures += expect_result("non-directory dirfd", create_node(
            regular_fd, "child", S_IFREG | 0600, 0), -ENOTDIR);
        (void)raw_syscall6(SYS_close, regular_fd, 0, 0, 0, 0, 0);
    }

#if defined(__x86_64__)
    {
        char legacy[96];
        copy_bytes(legacy, directory, string_length(directory) + 1u);
        (void)append_text(legacy, sizeof(legacy), "/legacy");
        failures += expect_result("legacy mknod", raw_syscall6(
            SYS_mknod, (long)legacy, S_IFREG | 0666, 0, 0, 0, 0), 0);
        failures += expect_node("legacy metadata", AT_FDCWD, legacy,
                                S_IFREG, 0640, 0, 0);
        remove_node(AT_FDCWD, legacy);
    }
#endif

    failures += test_capability(directory_fd);
    failures += test_sticky_directory_creation(directory_fd);

    remove_node(directory_fd, "unprivileged");
    remove_node(directory_fd, "denied-character");
    remove_node(directory_fd, "block");
    remove_node(directory_fd, "character");
    remove_node(directory_fd, "socket");
    remove_node(directory_fd, "fifo");
    remove_node(directory_fd, "zero");
    remove_node(directory_fd, "regular");
    remove_node(AT_FDCWD, absolute);
    (void)raw_syscall6(SYS_close, directory_fd, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)directory,
                       AT_REMOVEDIR, 0, 0, 0);

    if (!failures) print_text("MKNOD_ABI_PROBE_PASS\n");
    else {
        print_text("MKNOD_ABI_PROBE_FAIL failures=");
        print_number(failures);
        print_text("\n");
    }
    return failures ? 1 : 0;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    raw_syscall6(SYS_exit, run_probe(), 0, 0, 0, 0, 0);
    for (;;) { }
}
