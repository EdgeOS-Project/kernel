/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux ustat ABI probe for x86_64. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "ustat_abi_probe requires the Linux x86_64 ABI"
#endif

#define SYS_write 1
#define SYS_exit 60
#define SYS_ustat 136
#define SYS_statx 332

#define AT_FDCWD (-100)
#define STATX_BASIC_STATS 0x000007ffu
#define EFAULT 14
#define EINVAL 22

struct linux_statx_timestamp {
    int64_t seconds;
    uint32_t nanoseconds;
    int32_t reserved;
};

struct linux_statx {
    uint32_t mask;
    uint32_t block_size;
    uint64_t attributes;
    uint32_t links;
    uint32_t uid;
    uint32_t gid;
    uint16_t mode;
    uint16_t spare0;
    uint64_t inode;
    uint64_t size;
    uint64_t blocks;
    uint64_t attributes_mask;
    struct linux_statx_timestamp access_time;
    struct linux_statx_timestamp birth_time;
    struct linux_statx_timestamp change_time;
    struct linux_statx_timestamp modification_time;
    uint32_t rdev_major;
    uint32_t rdev_minor;
    uint32_t device_major;
    uint32_t device_minor;
    uint8_t remainder[112];
};

struct linux_ustat {
    int32_t free_blocks;
    uint32_t padding;
    uint64_t free_inodes;
    char filesystem_name[6];
    char filesystem_pack[6];
    uint32_t tail_padding;
};

_Static_assert(sizeof(struct linux_statx) == 256u,
               "Linux statx probe layout mismatch");
_Static_assert(sizeof(struct linux_ustat) == 32u,
               "Linux ustat probe layout mismatch");

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
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

static uint32_t encode_device(uint32_t major, uint32_t minor) {
    return (minor & 0xffu) | ((major & 0xfffu) << 8u) |
           ((minor & ~0xffu) << 12u);
}

static void zero_bytes(void *pointer, unsigned long size) {
    uint8_t *bytes = (uint8_t *)pointer;
    while (size) bytes[--size] = 0;
}

static int run_tests(void) {
    static const char root[] = "/";
    struct linux_statx metadata;
    struct linux_ustat usage;
    uint32_t device;
    long status;
    int failures = 0;

    zero_bytes(&metadata, sizeof(metadata));
    zero_bytes(&usage, sizeof(usage));
    status = raw_syscall6(
        SYS_statx, AT_FDCWD, (long)root, 0, STATX_BASIC_STATS,
        (long)&metadata, 0);
    failures += expect("statx root", status, 0);
    if (status < 0) return failures + 1;
    device = encode_device(metadata.device_major, metadata.device_minor);
    failures += expect(
        "valid device", raw_syscall6(
            SYS_ustat, device, (long)&usage, 0, 0, 0, 0), 0);
    failures += expect(
        "valid device null output", raw_syscall6(
            SYS_ustat, device, 0, 0, 0, 0, 0), -EFAULT);
    failures += expect(
        "invalid device", raw_syscall6(
            SYS_ustat, 0xffffffffu, (long)&usage, 0, 0, 0, 0), -EINVAL);
    return failures;
}

__attribute__((noreturn)) void _start(void) {
    int failures = run_tests();
    print_text(failures ? "USTAT_ABI_PROBE_FAIL\n" :
                          "USTAT_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
