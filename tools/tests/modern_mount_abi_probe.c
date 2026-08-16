/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent open_tree and move_mount runtime probe. */

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mount 165
#define SYS_umount2 166
#define SYS_exit 60
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_unlinkat 263
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_close 57
#define SYS_mount 40
#define SYS_umount2 39
#define SYS_exit 93
#define SYS_openat 56
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "modern_mount_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_open_tree 428
#define SYS_move_mount 429

#define AT_FDCWD (-100)
#define AT_REMOVEDIR 0x200
#define O_WRONLY 0x1
#define O_CREAT 0x40
#define O_TRUNC 0x200
#define O_CLOEXEC 0x80000
#define OPEN_TREE_CLONE 0x1
#define MOVE_MOUNT_F_EMPTY_PATH 0x4
#define EINVAL 22
#define ENOENT 2

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

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int expect_descriptor(const char *name, long descriptor) {
    if (descriptor < 0) return expect_result(name, descriptor, 0);
    return expect_result(
        name, raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
}

static void remove_directory(const char *path) {
    (void)raw_syscall6(
        SYS_unlinkat, AT_FDCWD, (long)path, AT_REMOVEDIR, 0, 0, 0);
}

static int run_tests(void) {
    static const char source[] = "/tmp/edgeos-modern-mount-source";
    static const char target[] = "/tmp/edgeos-modern-mount-target";
    static const char source_marker[] =
        "/tmp/edgeos-modern-mount-source/marker";
    static const char target_marker[] =
        "/tmp/edgeos-modern-mount-target/marker";
    static const char empty[] = "";
    long descriptor;
    long marker;
    int failures = 0;

    (void)raw_syscall6(SYS_umount2, (long)target, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_umount2, (long)source, 0, 0, 0, 0, 0);
    remove_directory(target);
    remove_directory(source);
    failures += expect_result(
        "mkdir source",
        raw_syscall6(SYS_mkdirat, AT_FDCWD, (long)source, 0700, 0, 0, 0),
        0);
    failures += expect_result(
        "mkdir target",
        raw_syscall6(SYS_mkdirat, AT_FDCWD, (long)target, 0700, 0, 0, 0),
        0);
    failures += expect_result(
        "mount tmpfs",
        raw_syscall6(SYS_mount, (long)"none", (long)source,
                     (long)"tmpfs", 0, (long)"size=1m", 0),
        0);
    marker = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)source_marker,
        O_WRONLY | O_CREAT | O_TRUNC, 0600, 0, 0);
    failures += expect_descriptor("create marker", marker);

    descriptor = raw_syscall6(
        SYS_open_tree, AT_FDCWD, (long)source, O_CLOEXEC, 0, 0, 0);
    if (descriptor < 0) {
        failures += expect_result("open_tree attached mount", descriptor, 0);
    } else {
        failures += expect_descriptor(
            "open_tree clone",
            raw_syscall6(SYS_open_tree, AT_FDCWD, (long)source,
                         OPEN_TREE_CLONE | O_CLOEXEC, 0, 0, 0));
        failures += expect_result(
            "move_mount descriptor source",
            raw_syscall6(SYS_move_mount, descriptor, (long)empty,
                         AT_FDCWD, (long)target,
                         MOVE_MOUNT_F_EMPTY_PATH, 0),
            0);
        marker = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)target_marker, 0, 0, 0, 0);
        failures += expect_descriptor("moved marker", marker);
        failures += expect_result(
            "source mount removed",
            raw_syscall6(SYS_openat, AT_FDCWD, (long)source_marker,
                         0, 0, 0, 0),
            -ENOENT);
        failures += expect_result(
            "move_mount invalid flags",
            raw_syscall6(SYS_move_mount, descriptor, (long)empty,
                         AT_FDCWD, (long)source, 0x80000000u, 0),
            -EINVAL);
        failures += expect_result(
            "close mount descriptor",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    failures += expect_result(
        "unmount moved tree",
        raw_syscall6(SYS_umount2, (long)target, 0, 0, 0, 0, 0), 0);
    remove_directory(target);
    remove_directory(source);
    if (!failures) print_text("MODERN_MOUNT_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

START_ATTRIBUTES void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
