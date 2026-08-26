/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux quota control ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define ENTRY_ALIGNMENT __attribute__((force_align_arg_pointer))
#define SYS_close 3
#define SYS_write 1
#define SYS_exit 60
#define SYS_openat 257
#define SYS_quotactl 179
#define SYS_quotactl_fd 443
#elif defined(__aarch64__)
#define ENTRY_ALIGNMENT
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_openat 56
#define SYS_quotactl 60
#define SYS_quotactl_fd 443
#else
#error "quota_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define O_RDONLY 0u
#define O_DIRECTORY 00200000u
#define Q_SYNC 0x800001u
#define Q_QUOTAON 0x800002u
#define Q_QUOTAOFF 0x800003u
#define Q_GETFMT 0x800004u
#define Q_GETINFO 0x800005u
#define Q_SETINFO 0x800006u
#define Q_GETQUOTA 0x800007u
#define Q_SETQUOTA 0x800008u
#define Q_GETNEXTQUOTA 0x800009u
#define QCMD(command, type) (((command) << 8) | (type))
#define USRQUOTA 0u
#define QFMT_SHMEM 5u
#define QIF_BLIMITS (1u << 0)
#define QIF_SPACE (1u << 1)
#define QIF_ILIMITS (1u << 2)
#define QIF_INODES (1u << 3)
#define IIF_BGRACE (1u << 0)
#define IIF_IGRACE (1u << 1)
#define EBADF 9
#define EINVAL 22
#define ENOSYS 38
#define ESRCH 3

struct if_dqblk {
    uint64_t block_hard_limit;
    uint64_t block_soft_limit;
    uint64_t current_space;
    uint64_t inode_hard_limit;
    uint64_t inode_soft_limit;
    uint64_t current_inodes;
    uint64_t block_time;
    uint64_t inode_time;
    uint32_t valid;
};

struct if_nextdqblk {
    uint64_t block_hard_limit;
    uint64_t block_soft_limit;
    uint64_t current_space;
    uint64_t inode_hard_limit;
    uint64_t inode_soft_limit;
    uint64_t current_inodes;
    uint64_t block_time;
    uint64_t inode_time;
    uint32_t valid;
    uint32_t id;
};

struct if_dqinfo {
    uint64_t block_grace;
    uint64_t inode_grace;
    uint32_t flags;
    uint32_t valid;
};

_Static_assert(sizeof(struct if_dqblk) == 72,
               "if_dqblk probe layout mismatch");
_Static_assert(sizeof(struct if_nextdqblk) == 72,
               "if_nextdqblk probe layout mismatch");
_Static_assert(sizeof(struct if_dqinfo) == 24,
               "if_dqinfo probe layout mismatch");

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

static long raw_syscall5(long number, long a0, long a1, long a2,
                         long a3, long a4) {
    return raw_syscall6(number, a0, a1, a2, a3, a4, 0);
}

static long raw_syscall4(long number, long a0, long a1, long a2,
                         long a3) {
    return raw_syscall5(number, a0, a1, a2, a3, 0);
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

static void print_long(long value) {
    char digits[32];
    unsigned long magnitude;
    unsigned long count = 0;
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    while (count) {
        char digit = digits[--count];
        (void)raw_syscall6(SYS_write, 1, (long)&digit, 1, 0, 0, 0);
    }
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_long(actual);
    print_text(" expected=");
    print_long(expected);
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

static void clear_bytes(void *destination, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = 0;
}

static int run_tests(void) {
    static const char root_path[] = "/";
    static const char quota_path[] = "/quota.user";
    struct if_dqblk set;
    struct if_dqblk get;
    struct if_nextdqblk next;
    struct if_dqinfo information;
    uint32_t format = 0;
    long descriptor;
    long enable_result;
    int failures = 0;

    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)root_path,
        O_RDONLY | O_DIRECTORY, 0, 0, 0);
    failures += expect_true("open root", descriptor >= 0);
    if (descriptor < 0) return failures + 1;
    failures += expect(
        "invalid descriptor precedence",
        raw_syscall5(SYS_quotactl_fd, -1,
                     QCMD(Q_GETFMT, 3), 0, (long)&format, 0),
        -EBADF);
    failures += expect(
        "invalid type",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_GETFMT, 3), 0, (long)&format, 0),
        -EINVAL);
    enable_result = raw_syscall5(
        SYS_quotactl_fd, descriptor, QCMD(Q_QUOTAON, USRQUOTA),
        QFMT_SHMEM, (long)quota_path, 0);
    if (enable_result == -ENOSYS) {
        failures += expect("unsupported root quota backend",
            raw_syscall5(SYS_quotactl_fd, descriptor,
                         QCMD(Q_GETFMT, USRQUOTA), 0,
                         (long)&format, 0), -ENOSYS);
        failures += expect("close", raw_syscall6(
            SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
        return failures;
    }
    failures += expect("enable", enable_result, 0);
    failures += expect(
        "format",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_GETFMT, USRQUOTA), 0, (long)&format, 0),
        0);
    failures += expect_true("format value", format == QFMT_SHMEM);

    clear_bytes(&set, sizeof(set));
    set.block_hard_limit = 8192;
    set.block_soft_limit = 4096;
    set.current_space = 1024;
    set.inode_hard_limit = 32;
    set.inode_soft_limit = 24;
    set.current_inodes = 2;
    set.valid = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES;
    failures += expect(
        "set quota",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_SETQUOTA, USRQUOTA), 0, (long)&set, 0),
        0);
    clear_bytes(&get, sizeof(get));
    failures += expect(
        "get quota",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_GETQUOTA, USRQUOTA), 0, (long)&get, 0),
        0);
    failures += expect_true(
        "quota values",
        get.block_hard_limit == 8192 && get.current_space == 1024 &&
        get.inode_hard_limit == 32 && get.current_inodes == 2);
    clear_bytes(&next, sizeof(next));
    failures += expect(
        "get next quota",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_GETNEXTQUOTA, USRQUOTA), 0,
                     (long)&next, 0),
        0);
    failures += expect_true(
        "next quota values", next.id == 0 &&
        next.block_hard_limit == 8192);

    clear_bytes(&information, sizeof(information));
    information.block_grace = 600;
    information.inode_grace = 300;
    information.valid = IIF_BGRACE | IIF_IGRACE;
    failures += expect(
        "set info",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_SETINFO, USRQUOTA), 0,
                     (long)&information, 0),
        0);
    clear_bytes(&information, sizeof(information));
    failures += expect(
        "get info",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_GETINFO, USRQUOTA), 0,
                     (long)&information, 0),
        0);
    failures += expect_true(
        "info values", information.block_grace == 600 &&
        information.inode_grace == 300);
    failures += expect(
        "sync",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_SYNC, USRQUOTA), 0, 0, 0),
        0);
    failures += expect(
        "disable",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_QUOTAOFF, USRQUOTA), 0, 0, 0),
        0);
    failures += expect(
        "disabled get",
        raw_syscall5(SYS_quotactl_fd, descriptor,
                     QCMD(Q_GETQUOTA, USRQUOTA), 0, (long)&get, 0),
        -ESRCH);
    failures += expect(
        "global sync",
        raw_syscall4(SYS_quotactl, QCMD(Q_SYNC, USRQUOTA), 0, 0, 0),
        0);
    failures += expect("close", raw_syscall6(
        SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    return failures;
}

ENTRY_ALIGNMENT void _start(void) {
    int failures = run_tests();
    print_text(failures ? "QUOTA_ABI_PROBE_FAIL\n" :
                          "QUOTA_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
