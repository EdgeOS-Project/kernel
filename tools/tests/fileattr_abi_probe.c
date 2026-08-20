/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux file_getattr and file_setattr ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_ftruncate 77
#define SYS_exit 60
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_renameat 264
#define SYS_statx 332
#elif defined(__aarch64__)
#define SYS_unlinkat 35
#define SYS_renameat 38
#define SYS_ftruncate 46
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_statx 291
#else
#error "fileattr_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_file_getattr 468
#define SYS_file_setattr 469

#define AT_FDCWD (-100)
#define AT_EMPTY_PATH 0x1000u
#define O_WRONLY 1u
#define O_RDWR 2u
#define O_CREAT 64u
#define O_EXCL 128u
#define O_APPEND 1024u

#define E2BIG 7
#define EFAULT 14
#define EPERM 1
#define EINVAL 22
#define EOPNOTSUPP 95

#define FS_XFLAG_IMMUTABLE 0x00000008u
#define FS_XFLAG_APPEND 0x00000010u
#define FS_XFLAG_SYNC 0x00000020u
#define FS_XFLAG_NOATIME 0x00000040u
#define FS_XFLAG_NODUMP 0x00000080u
#define STATX_BASIC_STATS 0x000007ffu
#define STATX_ATTR_IMMUTABLE 0x00000010ull
#define STATX_ATTR_APPEND 0x00000020ull
#define STATX_ATTR_NODUMP 0x00000040ull

struct file_attr {
    uint64_t fa_xflags;
    uint32_t fa_extsize;
    uint32_t fa_nextents;
    uint32_t fa_projid;
    uint32_t fa_cowextsize;
};

struct extended_file_attr {
    struct file_attr current;
    uint64_t extension;
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

_Static_assert(sizeof(struct file_attr) == 24,
               "Linux file_attr ABI size");
_Static_assert(sizeof(struct statx_result) == 256,
               "Linux statx ABI size");

static const char g_path[] = "/tmp/edgeos-fileattr-abi-probe";
static const char g_renamed[] = "/tmp/edgeos-fileattr-abi-renamed";

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

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = (unsigned char)value;
    return destination;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count,
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

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static long file_getattr(long directory, const char *path,
                         void *attributes, unsigned long size,
                         unsigned int flags) {
    return raw_syscall6(SYS_file_getattr, directory, (long)path,
                        (long)attributes, (long)size, flags, 0);
}

static long file_setattr(long directory, const char *path,
                         const void *attributes, unsigned long size,
                         unsigned int flags) {
    return raw_syscall6(SYS_file_setattr, directory, (long)path,
                        (long)attributes, (long)size, flags, 0);
}

static long set_xflags(uint64_t flags) {
    struct file_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.fa_xflags = flags;
    return file_setattr(AT_FDCWD, g_path, &attributes,
                        sizeof(attributes), 0);
}

static long stat_attributes(struct statx_result *metadata) {
    memset(metadata, 0, sizeof(*metadata));
    return raw_syscall6(SYS_statx, AT_FDCWD, (long)g_path, 0,
                        STATX_BASIC_STATS, (long)metadata, 0);
}

static int test_validation(void) {
    struct extended_file_attr extended;
    int failures = 0;
    memset(&extended, 0, sizeof(extended));
    failures += expect_result(
        "get invalid flags before size",
        file_getattr(AT_FDCWD, g_path, &extended, 1, 0x80000000u),
        -EINVAL);
    failures += expect_result(
        "get oversize", file_getattr(AT_FDCWD, g_path, &extended,
                                      4097, 0), -E2BIG);
    failures += expect_result(
        "get undersize", file_getattr(AT_FDCWD, g_path, &extended,
                                       23, 0), -EINVAL);
    failures += expect_result(
        "get null output", file_getattr(AT_FDCWD, g_path, 0,
                                         sizeof(struct file_attr), 0),
        -EFAULT);
    failures += expect_result(
        "set null input", file_setattr(AT_FDCWD, g_path, 0,
                                        sizeof(struct file_attr), 0),
        -EFAULT);
    extended.extension = 1;
    failures += expect_result(
        "set nonzero extension",
        file_setattr(AT_FDCWD, g_path, &extended, sizeof(extended), 0),
        -E2BIG);
    extended.extension = 0;
    extended.current.fa_xflags = 1ull << 40;
    failures += expect_result(
        "set unknown xflag",
        file_setattr(AT_FDCWD, g_path, &extended.current,
                     sizeof(extended.current), 0), -EINVAL);
    return failures;
}

static int test_attributes(long descriptor) {
    struct extended_file_attr attributes;
    struct statx_result metadata;
    static const char byte = 'B';
    long append_descriptor;
    int failures = 0;

    memset(&attributes, 0xa5, sizeof(attributes));
    failures += expect_result(
        "get initial", file_getattr(AT_FDCWD, g_path, &attributes,
                                     sizeof(attributes), 0), 0);
    failures += expect_true(
        "get zero extension",
        attributes.current.fa_xflags == 0 && attributes.extension == 0);

    failures += expect_result(
        "set ordinary flags", set_xflags(FS_XFLAG_NODUMP |
                                          FS_XFLAG_NOATIME), 0);
    memset(&attributes, 0, sizeof(attributes));
    failures += expect_result(
        "get by fd", file_getattr(descriptor, 0, &attributes.current,
                                   sizeof(attributes.current),
                                   AT_EMPTY_PATH), 0);
    failures += expect_true(
        "ordinary flags persisted",
        attributes.current.fa_xflags ==
            (FS_XFLAG_NODUMP | FS_XFLAG_NOATIME));
    failures += expect_result(
        "statx ordinary flags", stat_attributes(&metadata), 0);
    failures += expect_true(
        "statx attribute mask",
        (metadata.attributes_mask &
         (STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND |
          STATX_ATTR_NODUMP)) ==
        (STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND |
         STATX_ATTR_NODUMP));
    failures += expect_true(
        "statx nodump",
        (metadata.attributes & STATX_ATTR_NODUMP) != 0 &&
        (metadata.attributes &
         (STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND)) == 0);

    attributes.current.fa_xflags = FS_XFLAG_NODUMP |
                                   FS_XFLAG_NOATIME;
    attributes.current.fa_extsize = 4096;
    attributes.current.fa_nextents = 7;
    attributes.current.fa_projid = 42;
    attributes.current.fa_cowextsize = 8192;
    failures += expect_result(
        "set ignores get-only scalar fields",
        file_setattr(AT_FDCWD, g_path, &attributes.current,
                     sizeof(attributes.current), 0), 0);
    memset(&attributes, 0, sizeof(attributes));
    failures += expect_result(
        "get after scalar input",
        file_getattr(AT_FDCWD, g_path, &attributes.current,
                     sizeof(attributes.current), 0), 0);
    failures += expect_true(
        "scalar fields unchanged",
        attributes.current.fa_extsize == 0 &&
        attributes.current.fa_nextents == 0 &&
        attributes.current.fa_projid == 0 &&
        attributes.current.fa_cowextsize == 0);

    failures += expect_result(
        "unsupported tmpfs flag", set_xflags(FS_XFLAG_SYNC),
        -EOPNOTSUPP);
    failures += expect_result(
        "set append", set_xflags(FS_XFLAG_APPEND | FS_XFLAG_NODUMP), 0);
    failures += expect_result(
        "statx append", stat_attributes(&metadata), 0);
    failures += expect_true(
        "statx append value",
        (metadata.attributes &
         (STATX_ATTR_APPEND | STATX_ATTR_NODUMP)) ==
        (STATX_ATTR_APPEND | STATX_ATTR_NODUMP));
    failures += expect_result(
        "existing nonappend write",
        raw_syscall6(SYS_write, descriptor, (long)&byte, 1, 0, 0, 0),
        -EPERM);
    failures += expect_result(
        "append open required",
        raw_syscall6(SYS_openat, AT_FDCWD, (long)g_path,
                     O_WRONLY, 0, 0, 0), -EPERM);
    append_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)g_path, O_WRONLY | O_APPEND, 0, 0, 0);
    failures += expect_true("append open", append_descriptor >= 0);
    if (append_descriptor >= 0) {
        failures += expect_result(
            "append write",
            raw_syscall6(SYS_write, append_descriptor, (long)&byte,
                         1, 0, 0, 0), 1);
        (void)raw_syscall6(SYS_close, append_descriptor, 0, 0, 0, 0, 0);
    }
    failures += expect_result(
        "append truncate",
        raw_syscall6(SYS_ftruncate, descriptor, 0, 0, 0, 0, 0),
        -EPERM);
    failures += expect_result(
        "append unlink",
        raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)g_path, 0, 0, 0, 0),
        -EPERM);
    failures += expect_result(
        "append rename",
        raw_syscall6(SYS_renameat, AT_FDCWD, (long)g_path,
                     AT_FDCWD, (long)g_renamed, 0, 0), -EPERM);
    failures += expect_result("clear append", set_xflags(0), 0);

    failures += expect_result(
        "set immutable", set_xflags(FS_XFLAG_IMMUTABLE), 0);
    failures += expect_result(
        "statx immutable", stat_attributes(&metadata), 0);
    failures += expect_true(
        "statx immutable value",
        (metadata.attributes & STATX_ATTR_IMMUTABLE) != 0 &&
        (metadata.attributes &
         (STATX_ATTR_APPEND | STATX_ATTR_NODUMP)) == 0);
    failures += expect_result(
        "immutable write",
        raw_syscall6(SYS_write, descriptor, (long)&byte, 1, 0, 0, 0),
        -EPERM);
    failures += expect_result(
        "immutable truncate",
        raw_syscall6(SYS_ftruncate, descriptor, 0, 0, 0, 0, 0),
        -EPERM);
    failures += expect_result(
        "immutable unlink",
        raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)g_path, 0, 0, 0, 0),
        -EPERM);
    failures += expect_result("clear immutable", set_xflags(0), 0);
    return failures;
}

__attribute__((noreturn)) void _start(void) {
    static const char initial = 'A';
    long descriptor;
    int failures = 0;

    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)g_path,
                       0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)g_renamed,
                       0, 0, 0, 0);
    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)g_path,
        O_RDWR | O_CREAT | O_EXCL, 0600, 0, 0);
    failures += expect_true("create fixture", descriptor >= 0);
    if (descriptor >= 0) {
        failures += expect_result(
            "write fixture",
            raw_syscall6(SYS_write, descriptor, (long)&initial,
                         1, 0, 0, 0), 1);
        failures += test_validation();
        failures += test_attributes(descriptor);
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
        failures += expect_result(
            "cleanup",
            raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)g_path,
                         0, 0, 0, 0), 0);
    }
    print_text(failures ? "FILEATTR_ABI_PROBE_FAILED\n" :
                          "FILEATTR_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
