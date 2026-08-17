/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent statmount and listmount runtime probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_openat 257
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_close 57
#define SYS_exit 93
#define SYS_openat 56
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "statmount_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_statmount 457
#define SYS_listmount 458

#define AT_FDCWD (-100)
#define O_CLOEXEC 0x80000
#define O_PATH 0x200000
#define EINVAL 22
#define EOVERFLOW 75

#define STATMOUNT_SB_BASIC 0x00000001ULL
#define STATMOUNT_MNT_BASIC 0x00000002ULL
#define STATMOUNT_MNT_ROOT 0x00000008ULL
#define STATMOUNT_MNT_POINT 0x00000010ULL
#define STATMOUNT_FS_TYPE 0x00000020ULL
#define STATMOUNT_MNT_NS_ID 0x00000040ULL
#define STATMOUNT_SB_SOURCE 0x00000200ULL
#define STATMOUNT_SUPPORTED_MASK 0x00001000ULL
#define STATMOUNT_BY_FD 0x00000001u
#define LISTMOUNT_REVERSE 0x00000001u
#define LSMT_ROOT UINT64_MAX

struct mnt_id_req {
    uint32_t size;
    uint32_t mnt_ns_fd;
    uint64_t mnt_id;
    uint64_t param;
    uint64_t mnt_ns_id;
};

struct statmount {
    uint32_t size;
    uint32_t mnt_opts;
    uint64_t mask;
    uint32_t sb_dev_major;
    uint32_t sb_dev_minor;
    uint64_t sb_magic;
    uint32_t sb_flags;
    uint32_t fs_type;
    uint64_t mnt_id;
    uint64_t mnt_parent_id;
    uint32_t mnt_id_old;
    uint32_t mnt_parent_id_old;
    uint64_t mnt_attr;
    uint64_t mnt_propagation;
    uint64_t mnt_peer_group;
    uint64_t mnt_master;
    uint64_t propagate_from;
    uint32_t mnt_root;
    uint32_t mnt_point;
    uint64_t mnt_ns_id;
    uint32_t fs_subtype;
    uint32_t sb_source;
    uint32_t opt_num;
    uint32_t opt_array;
    uint32_t opt_sec_num;
    uint32_t opt_sec_array;
    uint64_t supported_mask;
    uint32_t mnt_uidmap_num;
    uint32_t mnt_uidmap;
    uint32_t mnt_gidmap_num;
    uint32_t mnt_gidmap;
    uint64_t spare[43];
};

static unsigned char result_buffer[4096] __attribute__((aligned(16)));
static uint64_t mount_ids[64];
static uint64_t reverse_ids[64];

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
    char buffer[32];
    unsigned long magnitude;
    unsigned long digits = 0;
    unsigned long start = 0;

    if (value < 0) {
        buffer[start++] = '-';
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[start + digits++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude && start + digits < sizeof(buffer));
    for (unsigned long index = 0; index < digits / 2u; ++index) {
        char temporary = buffer[start + index];
        buffer[start + index] = buffer[start + digits - index - 1u];
        buffer[start + digits - index - 1u] = temporary;
    }
    (void)raw_syscall6(SYS_write, 1, (long)buffer,
                       (long)(start + digits), 0, 0, 0);
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

static int string_valid(const struct statmount *result, uint32_t offset) {
    const char *strings = (const char *)result + sizeof(*result);
    uint32_t string_bytes;
    uint32_t index;

    if (result->size < sizeof(*result)) return 0;
    string_bytes = result->size - (uint32_t)sizeof(*result);
    if (!offset || offset >= string_bytes) return 0;
    for (index = offset; index < string_bytes; ++index)
        if (!strings[index]) return index != offset;
    return 0;
}

static int run_tests(void) {
    struct mnt_id_req request = {0};
    struct statmount *result = (struct statmount *)result_buffer;
    const uint64_t requested_mask =
        STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC |
        STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT |
        STATMOUNT_FS_TYPE | STATMOUNT_MNT_NS_ID |
        STATMOUNT_SB_SOURCE | STATMOUNT_SUPPORTED_MASK;
    long listed;
    long reverse_listed;
    long descriptor;
    int failures = 0;

    request.size = sizeof(request);
    request.mnt_id = LSMT_ROOT;
    listed = raw_syscall6(
        SYS_listmount, (long)&request, (long)mount_ids, 64, 0, 0, 0);
    if (listed <= 0)
        failures += expect_result("listmount returns mounts", listed, 1);
    if (listed > 0) {
        for (long index = 1; index < listed; ++index)
            failures += expect_true(
                "listmount ascending order",
                mount_ids[index - 1] < mount_ids[index]);
    }

    reverse_listed = raw_syscall6(
        SYS_listmount, (long)&request, (long)reverse_ids, 64,
        LISTMOUNT_REVERSE, 0, 0);
    failures += expect_result(
        "reverse list count", reverse_listed, listed);
    if (reverse_listed > 0) {
        for (long index = 1; index < reverse_listed; ++index)
            failures += expect_true(
                "listmount descending order",
                reverse_ids[index - 1] > reverse_ids[index]);
        failures += expect_true(
            "reverse list endpoints",
            reverse_ids[0] == mount_ids[listed - 1] &&
            reverse_ids[reverse_listed - 1] == mount_ids[0]);
    }
    failures += expect_result(
        "listmount invalid flags",
        raw_syscall6(SYS_listmount, (long)&request,
                     (long)mount_ids, 1, 0x80000000u, 0, 0),
        -EINVAL);

    if (listed > 0) {
        request.mnt_id = mount_ids[0];
        request.param = requested_mask;
        failures += expect_result(
            "statmount query",
            raw_syscall6(SYS_statmount, (long)&request,
                         (long)result_buffer, sizeof(result_buffer),
                         0, 0, 0),
            0);
        failures += expect_true(
            "statmount fixed fields",
            result->size >= sizeof(*result) &&
            (result->mask & (STATMOUNT_SB_BASIC |
                             STATMOUNT_MNT_BASIC |
                             STATMOUNT_MNT_POINT |
                             STATMOUNT_FS_TYPE |
                             STATMOUNT_MNT_NS_ID |
                             STATMOUNT_SUPPORTED_MASK)) ==
                (STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC |
                 STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE |
                 STATMOUNT_MNT_NS_ID | STATMOUNT_SUPPORTED_MASK) &&
            result->mnt_id == mount_ids[0] && result->mnt_ns_id != 0);
        failures += expect_true(
            "statmount filesystem string",
            string_valid(result, result->fs_type));
        failures += expect_true(
            "statmount mountpoint string",
            string_valid(result, result->mnt_point));
        failures += expect_true(
            "statmount supported mask",
            (result->supported_mask &
             (STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC |
              STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE)) ==
                (STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC |
                 STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE));
        failures += expect_result(
            "statmount string overflow",
            raw_syscall6(SYS_statmount, (long)&request,
                         (long)result_buffer, sizeof(*result),
                         0, 0, 0),
            -EOVERFLOW);

        descriptor = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)"/", O_PATH | O_CLOEXEC,
            0, 0, 0);
        failures += expect_true("open root descriptor", descriptor >= 0);
        if (descriptor >= 0) {
            request.mnt_ns_fd = (uint32_t)descriptor;
            request.mnt_id = 0;
            request.mnt_ns_id = 0;
            failures += expect_result(
                "statmount by descriptor",
                raw_syscall6(SYS_statmount, (long)&request,
                             (long)result_buffer, sizeof(result_buffer),
                             STATMOUNT_BY_FD, 0, 0),
                0);
            failures += expect_result(
                "close root descriptor",
                raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
        }
    }

    if (!failures) print_text("STATMOUNT_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

START_ATTRIBUTES void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
