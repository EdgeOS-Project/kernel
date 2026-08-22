/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux mount namespace ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_write 1
#define SYS_chdir 80
#define SYS_pivot_root 155
#define SYS_mount 165
#define SYS_umount2 166
#define SYS_statfs 137
#define SYS_exit 60
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_symlinkat 266
#define SYS_unshare 272
#define SYS_statx 332
#define SYS_mount_setattr 442
#elif defined(__aarch64__)
#define SYS_mkdirat 34
#define SYS_symlinkat 36
#define SYS_umount2 39
#define SYS_mount 40
#define SYS_statfs 43
#define SYS_pivot_root 41
#define SYS_chdir 49
#define SYS_close 57
#define SYS_openat 56
#define SYS_write 64
#define SYS_exit 93
#define SYS_unshare 97
#define SYS_statx 291
#define SYS_mount_setattr 442
#else
#error "mount_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD -100
#define AT_EMPTY_PATH 0x1000u
#define AT_RECURSIVE 0x8000u
#define E2BIG 7
#define EBUSY 16
#define EEXIST 17
#define EFAULT 14
#define EINVAL 22
#define ENOTDIR 20
#define EROFS 30

#define MS_RDONLY 0x1u
#define MS_REMOUNT 0x20u
#define MS_BIND 0x1000u
#define MS_REC 0x4000u
#define MS_PRIVATE 0x40000u
#define MS_SLAVE 0x80000u
#define MS_SHARED 0x100000u
#define MNT_DETACH 0x2u
#define UMOUNT_NOFOLLOW 0x8u
#define CLONE_NEWNS 0x00020000u
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100u
#define O_DIRECTORY 0x10000u
#define O_PATH 0x200000u
#define STATX_MNT_ID 0x00001000u
#define ST_RDONLY 0x1u
#define ST_NOSUID 0x2u
#define ST_NODEV 0x4u
#define ST_NOEXEC 0x8u

#define MOUNT_ATTR_NOSUID 0x2u
#define MOUNT_ATTR_NODEV 0x4u
#define MOUNT_ATTR_NOEXEC 0x8u
#define MOUNT_ATTR_RDONLY 0x1u

struct mount_attr {
    uint64_t attr_set;
    uint64_t attr_clear;
    uint64_t propagation;
    uint64_t user_namespace_fd;
};

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

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char digits[24];
    unsigned long magnitude;
    int position = (int)sizeof(digits);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&digits[position],
                       (long)(sizeof(digits) - (unsigned long)position),
                       0, 0, 0);
}

static void format_procfd_path(char *path, unsigned long capacity,
                               unsigned long descriptor) {
    static const char prefix[] = "/proc/self/fd/";
    char digits[24];
    unsigned long length = sizeof(prefix) - 1u;
    unsigned long count = 0;

    if (!path || capacity <= length) return;
    for (unsigned long index = 0; index < length; ++index)
        path[index] = prefix[index];
    do {
        digits[count++] = (char)('0' + descriptor % 10u);
        descriptor /= 10u;
    } while (descriptor && count < sizeof(digits));
    if (length + count >= capacity) {
        path[0] = 0;
        return;
    }
    while (count) path[length++] = digits[--count];
    path[length] = 0;
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

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int ensure_directory(const char *path) {
    long result = raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)path, 0755, 0, 0, 0);
    return result == 0 || result == -EEXIST ? 0 : 1;
}

static int ensure_symlink(const char *target, const char *path) {
    long result = raw_syscall6(
        SYS_symlinkat, (long)target, AT_FDCWD, (long)path, 0, 0, 0);
    return result == 0 || result == -EEXIST ? 0 : 1;
}

static long mount_call(const char *source, const char *target,
                       const char *filesystem, unsigned long flags,
                       const char *data) {
    return raw_syscall6(SYS_mount, (long)source, (long)target,
                        (long)filesystem, (long)flags, (long)data, 0);
}

static long umount_call(const char *target, unsigned long flags) {
    return raw_syscall6(SYS_umount2, (long)target, (long)flags,
                        0, 0, 0, 0);
}

static long mount_setattr_call(long descriptor, const char *target,
                               unsigned long flags,
                               const struct mount_attr *attributes,
                               unsigned long size) {
    return raw_syscall6(
        SYS_mount_setattr, descriptor, (long)target, (long)flags,
        (long)attributes, (long)size, 0);
}

static long statfs_flags(const char *path, uint64_t *flags) {
    uint64_t result[15] = {0};
    long status = raw_syscall6(
        SYS_statfs, (long)path, (long)result, 0, 0, 0, 0);
    *flags = status == 0 ? result[10] : 0;
    return status;
}

static long statx_mount_id(long descriptor, uint64_t *mount_id) {
    uint64_t result[32];
    long status = raw_syscall6(
        SYS_statx, descriptor, (long)"", AT_EMPTY_PATH,
        STATX_MNT_ID, (long)result, 0);
    uint32_t mask = (uint32_t)result[0];
    if (status == 0 && (mask & STATX_MNT_ID))
        *mount_id = result[18];
    else
        *mount_id = 0;
    return status;
}

static int run_pivot_root_test(void) {
    static const char base[] = "/tmp/edge-mount-abi-pivot";
    static const char host_incoming[] =
        "/tmp/edge-mount-abi-incoming";
    static const char incoming[] =
        "/tmp/edge-mount-abi-pivot/tmp/edge-mount-abi-incoming";
    static const char source[] = "/tmp/edge-mount-abi-source";
    uint64_t root_mount_id = 0;
    uint64_t bind_mount_id = 0;
    long root_descriptor;
    long bind_descriptor;
    long descriptor;
    int failures = 0;

    failures += expect_result("unshare mount namespace",
        raw_syscall6(SYS_unshare, CLONE_NEWNS, 0, 0, 0, 0, 0), 0);
    if (failures) return failures;
    failures += expect_result("slave root propagation",
        mount_call(0, "/", 0, MS_REC | MS_SLAVE, 0), 0);
    failures += expect_true("create pivot mountpoint",
                            ensure_directory(base) == 0);
    failures += expect_true("create incoming directory",
                            ensure_directory(host_incoming) == 0);
    if (failures) return failures;
    failures += expect_result("recursive root bind",
        mount_call("/", base, "none", MS_BIND | MS_REC, 0), 0);
    failures += expect_result("incoming bind",
        mount_call(source, incoming, 0, MS_BIND, 0), 0);
    if (failures) return failures;
    root_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)"/",
        O_PATH | O_DIRECTORY, 0, 0, 0);
    bind_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)base,
        O_PATH | O_DIRECTORY, 0, 0, 0);
    failures += expect_true("open root mount", root_descriptor >= 0);
    failures += expect_true("open recursive bind mount", bind_descriptor >= 0);
    if (root_descriptor >= 0)
        failures += expect_result("statx root mount id",
            statx_mount_id(root_descriptor, &root_mount_id), 0);
    if (bind_descriptor >= 0)
        failures += expect_result("statx recursive bind mount id",
            statx_mount_id(bind_descriptor, &bind_mount_id), 0);
    failures += expect_true(
        "recursive bind has distinct mount id",
        root_mount_id != 0 && bind_mount_id != 0 &&
        root_mount_id != bind_mount_id);
    if (root_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, root_descriptor, 0, 0, 0, 0, 0);
    if (bind_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, bind_descriptor, 0, 0, 0, 0, 0);
    if (failures) return failures;
    failures += expect_result("pivot chdir",
        raw_syscall6(SYS_chdir, (long)base, 0, 0, 0, 0, 0), 0);
    failures += expect_result("pivot root",
        raw_syscall6(SYS_pivot_root, (long)".", (long)".",
                     0, 0, 0, 0), 0);
    failures += expect_result("detach old root",
        umount_call(".", MNT_DETACH), 0);
    if (failures) return failures;
    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)host_incoming,
        O_RDONLY | O_DIRECTORY, 0, 0, 0);
    failures += expect_true("incoming bind remains visible", descriptor >= 0);
    if (descriptor >= 0)
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    failures += expect_result("shared new root propagation",
        mount_call(0, "/", 0, MS_REC | MS_SHARED, 0), 0);
    failures += expect_result("slave incoming propagation",
        mount_call(0, host_incoming, 0, MS_SLAVE, 0), 0);
    return failures;
}

static int run_tests(void) {
    static const char tmpfs_target[] = "/tmp/edge-mount-abi-tmpfs";
    static const char tmpfs_link[] = "/tmp/edge-mount-abi-tmpfs-link";
    static const char dev_target[] = "/tmp/edge-mount-abi-dev";
    static const char bind_source[] = "/tmp/edge-mount-abi-source";
    static const char bind_source_child[] =
        "/tmp/edge-mount-abi-source/child";
    static const char bind_target[] = "/tmp/edge-mount-abi-bind";
    static const char bind_child[] = "/tmp/edge-mount-abi-bind/child";
    static const char bind_source_file[] =
        "/tmp/edge-mount-abi-source/existing";
    static const char bind_target_file[] =
        "/tmp/edge-mount-abi-bind/existing";
    static const char bind_target_new_file[] =
        "/tmp/edge-mount-abi-bind/blocked-file";
    static const char bind_target_new_directory[] =
        "/tmp/edge-mount-abi-bind/blocked-directory";
    struct mount_attr attributes = {0};
    struct {
        struct mount_attr attributes;
        uint64_t extra;
    } extended_attributes = {{0}, 1};
    uint64_t flags = 0;
    long bind_descriptor = -1;
    long file_descriptor;
    char procfd_path[48] = {0};
    int failures = 0;

    failures += ensure_directory(tmpfs_target);
    failures += ensure_directory(dev_target);
    failures += ensure_directory(bind_source);
    failures += ensure_directory(bind_source_child);
    failures += ensure_directory(bind_target);
    file_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)bind_source_file,
        O_CREAT | O_WRONLY, 0644, 0, 0);
    failures += expect_true("create bind source file", file_descriptor >= 0);
    if (file_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, file_descriptor, 0, 0, 0, 0, 0);
    failures += ensure_symlink(tmpfs_target, tmpfs_link);
    failures += expect_result("null target",
        mount_call("tmpfs", 0, "tmpfs", 0, 0), -EFAULT);
    failures += expect_result("unknown mount flag",
        mount_call("tmpfs", tmpfs_target, "tmpfs", 1ul << 63, 0),
        -EINVAL);
    failures += expect_result("duplicate proc mount",
        mount_call("proc", "/proc", "proc", 0, 0), -EBUSY);
    failures += expect_result("duplicate sysfs mount",
        mount_call("sysfs", "/sys", "sysfs", 0, 0), -EBUSY);
    failures += expect_result("tmpfs mount",
        mount_call("tmpfs", tmpfs_target, "tmpfs", 0, "mode=0755"), 0);
    failures += expect_result("private propagation",
        mount_call(0, tmpfs_target, 0, MS_PRIVATE, 0), 0);
    failures += expect_result("containing mount propagation",
        mount_call(0, bind_source_child, 0, MS_PRIVATE, 0), 0);
    failures += expect_result("nofollow symlink umount",
        umount_call(tmpfs_link, UMOUNT_NOFOLLOW), -EINVAL);
    failures += expect_result("tmpfs umount",
        umount_call(tmpfs_target, 0), 0);
    failures += expect_result("file bind over directory",
        mount_call("/dev/null", bind_target, 0, MS_BIND, 0), -ENOTDIR);
    failures += expect_result("bind mount",
        mount_call(bind_source, bind_target, 0, MS_BIND, 0), 0);
    attributes.attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC;
    failures += expect_result("set bind mount attributes",
        mount_setattr_call(AT_FDCWD, bind_target, 0, &attributes,
                           sizeof(attributes)), 0);
    failures += expect_result("statfs bind attributes",
        statfs_flags(bind_target, &flags), 0);
    failures += expect_true("bind attributes visible",
        (flags & (ST_NOSUID | ST_NOEXEC)) == (ST_NOSUID | ST_NOEXEC));
    failures += expect_result("short mount attribute structure",
        mount_setattr_call(AT_FDCWD, bind_target, 0, &attributes,
                           sizeof(attributes) - 1u), -EINVAL);
    extended_attributes.attributes = attributes;
    failures += expect_result("nonzero mount attribute extension",
        mount_setattr_call(AT_FDCWD, bind_target, 0,
                           &extended_attributes.attributes,
                           sizeof(extended_attributes)), -E2BIG);
    attributes.attr_set = 1ull << 63;
    failures += expect_result("unknown mount attribute",
        mount_setattr_call(AT_FDCWD, bind_target, 0, &attributes,
                           sizeof(attributes)), -EINVAL);
    failures += expect_result("nested tmpfs mount",
        mount_call("tmpfs", bind_child, "tmpfs", 0, "mode=0755"), 0);
    attributes.attr_set = MOUNT_ATTR_NODEV;
    attributes.attr_clear = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC;
    failures += expect_result("recursive mount attributes",
        mount_setattr_call(AT_FDCWD, bind_target, AT_RECURSIVE,
                           &attributes, sizeof(attributes)), 0);
    failures += expect_result("statfs nested attributes",
        statfs_flags(bind_child, &flags), 0);
    failures += expect_true("recursive attributes visible",
        (flags & ST_NODEV) == ST_NODEV);
    bind_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)bind_target,
        O_PATH | O_DIRECTORY, 0, 0, 0);
    failures += expect_true("open bind mount", bind_descriptor >= 0);
    attributes.attr_set = 0;
    attributes.attr_clear = MOUNT_ATTR_NODEV;
    if (bind_descriptor >= 0) {
        failures += expect_result("descriptor mount attributes",
            mount_setattr_call(bind_descriptor, "", AT_EMPTY_PATH,
                               &attributes, sizeof(attributes)), 0);
        format_procfd_path(procfd_path, sizeof(procfd_path),
                           (unsigned long)bind_descriptor);
        attributes.attr_set = MOUNT_ATTR_RDONLY;
        failures += expect_result("procfd mount attributes",
            mount_setattr_call(AT_FDCWD, procfd_path, AT_RECURSIVE,
                               &attributes, sizeof(attributes)), 0);
        (void)raw_syscall6(
            SYS_close, bind_descriptor, 0, 0, 0, 0, 0);
    }
    failures += expect_result("recursive bind read-only remount",
        mount_call(bind_source, bind_target, 0,
                   MS_REMOUNT | MS_BIND | MS_REC | MS_RDONLY, 0), 0);
    failures += expect_result("statfs read-only bind",
        statfs_flags(bind_target, &flags), 0);
    failures += expect_true("read-only bind visible",
        (flags & ST_RDONLY) == ST_RDONLY);
    failures += expect_result("statfs recursive read-only child",
        statfs_flags(bind_child, &flags), 0);
    failures += expect_true("recursive read-only child visible",
        (flags & ST_RDONLY) == ST_RDONLY);
    failures += expect_result("read-only existing file open",
        raw_syscall6(SYS_openat, AT_FDCWD, (long)bind_target_file,
                     O_WRONLY, 0, 0, 0), -EROFS);
    failures += expect_result("read-only file create",
        raw_syscall6(SYS_openat, AT_FDCWD, (long)bind_target_new_file,
                     O_CREAT | O_WRONLY, 0644, 0, 0), -EROFS);
    failures += expect_result("read-only directory create",
        raw_syscall6(SYS_mkdirat, AT_FDCWD,
                     (long)bind_target_new_directory, 0755, 0, 0, 0),
        -EROFS);
    failures += expect_result("nested tmpfs lazy umount",
        umount_call(bind_child, MNT_DETACH), 0);
    failures += expect_result("bind lazy umount",
        umount_call(bind_target, MNT_DETACH), 0);
    failures += expect_result("devtmpfs mount",
        mount_call("dev", dev_target, "devtmpfs", 0, 0), 0);
    failures += expect_result("devtmpfs umount",
        umount_call(dev_target, 0), 0);
    failures += expect_result("invalid umount flag",
        umount_call(dev_target, 0x10u), -EINVAL);
    if (!failures) failures += run_pivot_root_test();

    if (!failures) print_text("MOUNT_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
