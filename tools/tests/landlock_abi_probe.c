/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux Landlock ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_ftruncate 77
#define SYS_prctl 157
#define SYS_exit 60
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_unlinkat 263
#define SYS_renameat 264
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_ftruncate 46
#define SYS_prctl 167
#define SYS_exit 93
#define SYS_openat 56
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_renameat 38
#else
#error "landlock_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446

#define AT_FDCWD (-100)
#define O_RDONLY 0u
#define O_WRONLY 1u
#define O_CREAT 0100u
#define O_TRUNC 01000u
#define O_DIRECTORY 00200000u
#define O_CLOEXEC 02000000u
#define O_PATH 010000000u
#define PR_SET_NO_NEW_PRIVS 38
#define LANDLOCK_CREATE_RULESET_VERSION (1u << 0)
#define LANDLOCK_RULE_PATH_BENEATH 1u
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#define EACCES 13
#define EXDEV 18
#define EBADFD 77
#define EINVAL 22
#define ENOMSG 42

struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
};

struct landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));

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

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
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

static int expect_at_least(const char *name, long actual, long minimum) {
    return expect_true(name, actual >= minimum);
}

static long open_file(const char *path, uint32_t flags) {
    return raw_syscall6(SYS_openat, AT_FDCWD, (long)path, flags, 0644, 0, 0);
}

static int prepare_file(const char *path) {
    static const char contents[] = "edgeos-landlock\n";
    long descriptor = open_file(path, O_WRONLY | O_CREAT | O_TRUNC);
    if (descriptor < 0) return 1;
    if (raw_syscall6(SYS_write, descriptor, (long)contents,
                     sizeof(contents) - 1u, 0, 0, 0) !=
        (long)(sizeof(contents) - 1u)) {
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
        return 1;
    }
    return raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0) < 0;
}

static int run_tests(void) {
    static const char allowed_dir[] = "/tmp/landlock-allowed";
    static const char allowed_dir_two[] = "/tmp/landlock-allowed-two";
    static const char denied_dir[] = "/tmp/landlock-denied";
    static const char allowed_file[] = "/tmp/landlock-allowed/file";
    static const char renamed_file[] = "/tmp/landlock-allowed/renamed";
    static const char moved_file[] = "/tmp/landlock-allowed-two/moved";
    static const char denied_moved_file[] = "/tmp/landlock-denied/moved";
    static const char denied_file[] = "/tmp/landlock-denied/file";
    struct landlock_ruleset_attr ruleset = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_MAKE_REG |
                             LANDLOCK_ACCESS_FS_REFER |
                             LANDLOCK_ACCESS_FS_TRUNCATE,
    };
    struct landlock_ruleset_attr empty = {0};
    struct landlock_path_beneath_attr path_rule;
    char byte;
    long allowed_parent;
    long allowed_parent_two;
    long denied_preopen;
    long denied_preopen_write;
    long descriptor;
    long wrong_ruleset;
    long ruleset_fd;
    int failures = 0;

    (void)raw_syscall6(SYS_mkdirat, AT_FDCWD, (long)"/tmp", 0755, 0, 0, 0);
    (void)raw_syscall6(SYS_mkdirat, AT_FDCWD, (long)allowed_dir, 0755, 0, 0, 0);
    (void)raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)allowed_dir_two, 0755, 0, 0, 0);
    (void)raw_syscall6(SYS_mkdirat, AT_FDCWD, (long)denied_dir, 0755, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)renamed_file, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)moved_file, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_unlinkat, AT_FDCWD, (long)denied_moved_file, 0, 0, 0, 0);
    failures += prepare_file(allowed_file);
    failures += prepare_file(denied_file);

    failures += expect_at_least(
        "version",
        raw_syscall6(SYS_landlock_create_ruleset, 0, 0,
                     LANDLOCK_CREATE_RULESET_VERSION, 0, 0, 0),
        3);
    failures += expect(
        "unknown create flag",
        raw_syscall6(SYS_landlock_create_ruleset, 0, 0, 4, 0, 0, 0),
        -EINVAL);
    failures += expect(
        "empty ruleset",
        raw_syscall6(SYS_landlock_create_ruleset, (long)&empty,
                     sizeof(empty), 0, 0, 0, 0),
        -ENOMSG);

    denied_preopen = open_file(denied_file, O_RDONLY);
    failures += expect_true("preopen denied file", denied_preopen >= 0);
    denied_preopen_write = open_file(denied_file, O_WRONLY);
    failures += expect_true(
        "preopen denied writable file", denied_preopen_write >= 0);
    allowed_parent = open_file(allowed_dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    failures += expect_true("open allowed parent", allowed_parent >= 0);
    allowed_parent_two = open_file(
        allowed_dir_two, O_PATH | O_DIRECTORY | O_CLOEXEC);
    failures += expect_true(
        "open second allowed parent", allowed_parent_two >= 0);
    wrong_ruleset = open_file("/dev/null", O_RDONLY);
    failures += expect_true("open wrong ruleset descriptor", wrong_ruleset >= 0);
    if (allowed_parent < 0 || allowed_parent_two < 0 || denied_preopen < 0 ||
        denied_preopen_write < 0 || wrong_ruleset < 0)
        return failures + 1;

    ruleset_fd = raw_syscall6(
        SYS_landlock_create_ruleset, (long)&ruleset,
        sizeof(ruleset), 0, 0, 0, 0);
    failures += expect_true("create ruleset", ruleset_fd >= 0);
    if (ruleset_fd < 0) return failures + 1;
    path_rule.allowed_access = ruleset.handled_access_fs &
        ~(LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_REFER);
    path_rule.parent_fd = (int32_t)allowed_parent;
    failures += expect(
        "wrong ruleset descriptor",
        raw_syscall6(SYS_landlock_add_rule, wrong_ruleset,
                     LANDLOCK_RULE_PATH_BENEATH, (long)&path_rule, 0, 0, 0),
        -EBADFD);
    failures += expect(
        "add path rule",
        raw_syscall6(SYS_landlock_add_rule, ruleset_fd,
                     LANDLOCK_RULE_PATH_BENEATH, (long)&path_rule, 0, 0, 0),
        0);
    path_rule.parent_fd = (int32_t)allowed_parent_two;
    failures += expect(
        "add second path rule",
        raw_syscall6(SYS_landlock_add_rule, ruleset_fd,
                     LANDLOCK_RULE_PATH_BENEATH, (long)&path_rule, 0, 0, 0),
        0);
    failures += expect(
        "set no new privileges",
        raw_syscall6(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0),
        0);
    failures += expect(
        "restrict self",
        raw_syscall6(SYS_landlock_restrict_self, ruleset_fd, 0, 0, 0, 0, 0),
        0);

    failures += expect(
        "same-parent rename",
        raw_syscall6(SYS_renameat, AT_FDCWD, (long)allowed_file,
                     AT_FDCWD, (long)renamed_file, 0, 0),
        0);
    failures += expect(
        "same-parent rename back",
        raw_syscall6(SYS_renameat, AT_FDCWD, (long)renamed_file,
                     AT_FDCWD, (long)allowed_file, 0, 0),
        0);
    failures += expect(
        "cross-parent rename without refer",
        raw_syscall6(SYS_renameat, AT_FDCWD, (long)allowed_file,
                     AT_FDCWD, (long)moved_file, 0, 0),
        -EXDEV);
    failures += expect(
        "missing make access precedes refer",
        raw_syscall6(SYS_renameat, AT_FDCWD, (long)allowed_file,
                     AT_FDCWD, (long)denied_moved_file, 0, 0),
        -EACCES);

    descriptor = open_file(allowed_file, O_RDONLY);
    failures += expect_true("allowed file", descriptor >= 0);
    if (descriptor >= 0)
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    failures += expect("denied file", open_file(denied_file, O_RDONLY),
                       -EACCES);
    descriptor = open_file(allowed_dir, O_RDONLY | O_DIRECTORY);
    failures += expect_true("allowed directory", descriptor >= 0);
    if (descriptor >= 0)
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    failures += expect(
        "denied directory", open_file(denied_dir, O_RDONLY | O_DIRECTORY),
        -EACCES);
    failures += expect(
        "preopened descriptor remains readable",
        raw_syscall6(SYS_read, denied_preopen, (long)&byte, 1, 0, 0, 0),
        1);
    failures += expect(
        "preopened descriptor retains truncate access",
        raw_syscall6(SYS_ftruncate, denied_preopen_write, 0, 0, 0, 0, 0),
        0);
    descriptor = open_file(allowed_file, O_WRONLY);
    failures += expect_true("open allowed writable file", descriptor >= 0);
    if (descriptor >= 0) {
        failures += expect(
            "new descriptor cannot truncate",
            raw_syscall6(SYS_ftruncate, descriptor, 0, 0, 0, 0, 0),
            -EACCES);
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    }
    return failures;
}

void _start(void) {
    int failures = run_tests();
    print_text(failures ? "LANDLOCK_ABI_PROBE_FAIL\n" :
                          "LANDLOCK_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
