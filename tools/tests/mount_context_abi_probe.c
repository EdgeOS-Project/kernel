/* SPDX-License-Identifier: MPL-2.0 */
/* Linux descriptor-based mount API runtime probe. */

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
#error "mount_context_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_open_tree 428
#define SYS_move_mount 429
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#define SYS_fspick 433
#define SYS_open_tree_attr 467

#define AT_FDCWD (-100)
#define AT_REMOVEDIR 0x200
#define O_CLOEXEC 0x80000
#define OPEN_TREE_CLONE 0x1
#define FSOPEN_CLOEXEC 0x1
#define FSMOUNT_CLOEXEC 0x1
#define FSPICK_CLOEXEC 0x1
#define FSPICK_NO_AUTOMOUNT 0x2
#define FSPICK_EMPTY_PATH 0x8
#define FSCONFIG_SET_FLAG 0
#define FSCONFIG_SET_STRING 1
#define FSCONFIG_CMD_CREATE 6
#define FSCONFIG_CMD_RECONFIGURE 7
#define MOVE_MOUNT_F_EMPTY_PATH 0x4
#define MOUNT_ATTR_NOSUID 0x2
#define MOUNT_ATTR_NOEXEC 0x8
#define EINVAL 22
#define ENODEV 19

struct mount_attr {
    unsigned long attr_set;
    unsigned long attr_clear;
    unsigned long propagation;
    unsigned long userns_fd;
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

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char digits[24];
    unsigned long magnitude;
    unsigned long position = sizeof(digits);

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude && position);
    (void)raw_syscall6(SYS_write, 1, (long)&digits[position],
                       sizeof(digits) - position, 0, 0, 0);
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

static int expect_open(const char *name, const char *path) {
    long descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    if (descriptor < 0) return expect_result(name, descriptor, 0);
    return expect_result(
        name, raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
}

static void remove_directory(const char *path) {
    (void)raw_syscall6(
        SYS_unlinkat, AT_FDCWD, (long)path, AT_REMOVEDIR, 0, 0, 0);
}

static int move_descriptor(long descriptor, const char *target) {
    return (int)raw_syscall6(
        SYS_move_mount, descriptor, (long)"", AT_FDCWD,
        (long)target, MOVE_MOUNT_F_EMPTY_PATH, 0);
}

static int run_tests(void) {
    static const char target[] = "/tmp/edgeos-fsctx-target";
    static const char clone[] = "/tmp/edgeos-fsctx-clone";
    static const char attr_clone[] = "/tmp/edgeos-fsctx-attr-clone";
    static const char marker[] = "/tmp/edgeos-fsctx-target/marker";
    static const char clone_marker[] = "/tmp/edgeos-fsctx-clone/marker";
    static const char attr_marker[] =
        "/tmp/edgeos-fsctx-attr-clone/marker";
    struct mount_attr attributes = {MOUNT_ATTR_NOSUID, 0, 0, 0};
    long context;
    long mount;
    long tree;
    long file;
    int failures = 0;

    (void)raw_syscall6(SYS_umount2, (long)attr_clone, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_umount2, (long)clone, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_umount2, (long)target, 0, 0, 0, 0, 0);
    remove_directory(attr_clone);
    remove_directory(clone);
    remove_directory(target);
    failures += expect_result(
        "mkdir target",
        raw_syscall6(SYS_mkdirat, AT_FDCWD, (long)target, 0700, 0, 0, 0),
        0);
    failures += expect_result(
        "mkdir clone",
        raw_syscall6(SYS_mkdirat, AT_FDCWD, (long)clone, 0700, 0, 0, 0),
        0);
    failures += expect_result(
        "mkdir attr clone",
        raw_syscall6(
            SYS_mkdirat, AT_FDCWD, (long)attr_clone, 0700, 0, 0, 0),
        0);

    failures += expect_result(
        "unknown filesystem",
        raw_syscall6(SYS_fsopen, (long)"edgeos-missing", 0, 0, 0, 0, 0),
        -ENODEV);
    context = raw_syscall6(
        SYS_fsopen, (long)"tmpfs", FSOPEN_CLOEXEC, 0, 0, 0, 0);
    if (context < 0) {
        failures += expect_result("fsopen tmpfs", context, 0);
        goto cleanup;
    }
    failures += expect_result(
        "fsconfig size",
        raw_syscall6(SYS_fsconfig, context, FSCONFIG_SET_STRING,
                     (long)"size", (long)"4m", 0, 0),
        0);
    failures += expect_result(
        "fsconfig noexec",
        raw_syscall6(SYS_fsconfig, context, FSCONFIG_SET_FLAG,
                     (long)"noexec", 0, 0, 0),
        -EINVAL);
    failures += expect_result(
        "fsconfig create",
        raw_syscall6(SYS_fsconfig, context, FSCONFIG_CMD_CREATE,
                     0, 0, 0, 0),
        0);
    mount = raw_syscall6(
        SYS_fsmount, context, FSMOUNT_CLOEXEC,
        MOUNT_ATTR_NOSUID, 0, 0, 0);
    if (mount < 0) {
        failures += expect_result("fsmount", mount, 0);
        (void)raw_syscall6(SYS_close, context, 0, 0, 0, 0, 0);
        goto cleanup;
    }
    failures += expect_result(
        "move detached mount", move_descriptor(mount, target), 0);
    file = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)marker, 0x41, 0600, 0, 0);
    if (file < 0) failures += expect_result("create marker", file, 0);
    else failures += expect_result(
        "close marker", raw_syscall6(SYS_close, file, 0, 0, 0, 0, 0), 0);

    tree = raw_syscall6(
        SYS_open_tree, AT_FDCWD, (long)target,
        OPEN_TREE_CLONE | O_CLOEXEC, 0, 0, 0);
    if (tree < 0) failures += expect_result("open_tree clone", tree, 0);
    else {
        failures += expect_result(
            "attach tree clone", move_descriptor(tree, clone), 0);
        failures += expect_open("clone marker", clone_marker);
        (void)raw_syscall6(SYS_close, tree, 0, 0, 0, 0, 0);
    }

    tree = raw_syscall6(
        SYS_open_tree_attr, AT_FDCWD, (long)target,
        OPEN_TREE_CLONE | O_CLOEXEC, (long)&attributes,
        sizeof(attributes), 0);
    if (tree < 0)
        failures += expect_result("open_tree_attr clone", tree, 0);
    else {
        failures += expect_result(
            "attach attributed clone",
            move_descriptor(tree, attr_clone), 0);
        failures += expect_open("attributed clone marker", attr_marker);
        (void)raw_syscall6(SYS_close, tree, 0, 0, 0, 0, 0);
    }

    tree = raw_syscall6(
        SYS_fspick, AT_FDCWD, (long)target, FSPICK_CLOEXEC, 0, 0, 0);
    if (tree < 0) failures += expect_result("fspick", tree, 0);
    else {
        failures += expect_result(
            "fspick reconfigure flag",
            raw_syscall6(SYS_fsconfig, tree, FSCONFIG_SET_FLAG,
                         (long)"noatime", 0, 0, 0),
            -EINVAL);
        failures += expect_result(
            "fspick reconfigure",
            raw_syscall6(SYS_fsconfig, tree, FSCONFIG_CMD_RECONFIGURE,
                         0, 0, 0, 0),
            0);
        (void)raw_syscall6(SYS_close, tree, 0, 0, 0, 0, 0);
    }
    tree = raw_syscall6(
        SYS_open_tree, AT_FDCWD, (long)target, O_CLOEXEC, 0, 0, 0);
    if (tree < 0) {
        failures += expect_result("open_tree for fspick", tree, 0);
    } else {
        long picked = raw_syscall6(
            SYS_fspick, tree, (long)"",
            FSPICK_CLOEXEC | FSPICK_EMPTY_PATH | FSPICK_NO_AUTOMOUNT,
            0, 0, 0);
        if (picked < 0)
            failures += expect_result("fspick mount descriptor", picked, 0);
        else
            (void)raw_syscall6(SYS_close, picked, 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, tree, 0, 0, 0, 0, 0);
    }
    (void)raw_syscall6(SYS_close, mount, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, context, 0, 0, 0, 0, 0);

cleanup:
    (void)raw_syscall6(SYS_umount2, (long)attr_clone, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_umount2, (long)clone, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_umount2, (long)target, 0, 0, 0, 0, 0);
    remove_directory(attr_clone);
    remove_directory(clone);
    remove_directory(target);
    if (!failures) print_text("MOUNT_CONTEXT_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

START_ATTRIBUTES void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
