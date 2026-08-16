/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code, licensed under MPL-2.0.
 *
 * This freestanding probe compares Linux UID, GID, filesystem-ID, and
 * capability transition semantics without depending on a C library.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_setuid 105
#define SYS_setgid 106
#define SYS_setreuid 113
#define SYS_setregid 114
#define SYS_setresuid 117
#define SYS_getresuid 118
#define SYS_setresgid 119
#define SYS_getresgid 120
#define SYS_setfsuid 122
#define SYS_setfsgid 123
#define SYS_capget 125
#define SYS_capset 126
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_setregid 143
#define SYS_setgid 144
#define SYS_setreuid 145
#define SYS_setuid 146
#define SYS_setresuid 147
#define SYS_getresuid 148
#define SYS_setresgid 149
#define SYS_getresgid 150
#define SYS_setfsuid 151
#define SYS_setfsgid 152
#define SYS_capget 90
#define SYS_capset 91
#else
#error "credential_transition_abi_probe requires a Linux 64-bit architecture"
#endif

#define EPERM 1
#define EINVAL 22
#define ID_UNCHANGED ((uint32_t)-1)
#define LINUX_CAP_VERSION_3 0x20080522u
#define CAP_SETGID 6u

#define CAP_BIT(capability) (1ULL << (capability))
#define FILESYSTEM_CAPABILITIES \
    (CAP_BIT(0) | CAP_BIT(1) | CAP_BIT(2) | CAP_BIT(3) | CAP_BIT(4) | \
     CAP_BIT(9) | CAP_BIT(27) | CAP_BIT(32))

struct cap_header {
    uint32_t version;
    int32_t pid;
};

struct cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    long result;
#if defined(__x86_64__)
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2)
        : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory");
    result = x0;
#endif
    return result;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) length++;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
}

static void puthex64(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char buffer[19];
    int index;
    buffer[0] = '0';
    buffer[1] = 'x';
    for (index = 0; index < 16; ++index)
        buffer[2 + index] = digits[(value >> (60 - index * 4)) & 15u];
    buffer[18] = 0;
    putstr(buffer);
}

static void putdec(long value) {
    char buffer[32];
    unsigned long magnitude;
    int index = 31;
    buffer[index] = 0;
    if (value < 0) magnitude = (unsigned long)(-(value + 1)) + 1u;
    else magnitude = (unsigned long)value;
    do {
        buffer[--index] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    if (value < 0) buffer[--index] = '-';
    putstr(&buffer[index]);
}

static void memzero(void *destination, unsigned long size) {
    unsigned char *bytes = destination;
    unsigned long index;
    for (index = 0; index < size; ++index) bytes[index] = 0;
}

static uint64_t cap_join(const struct cap_data data[2], int field) {
    uint64_t low;
    uint64_t high;
    if (field == 0) {
        low = data[0].effective;
        high = data[1].effective;
    } else if (field == 1) {
        low = data[0].permitted;
        high = data[1].permitted;
    } else {
        low = data[0].inheritable;
        high = data[1].inheritable;
    }
    return low | (high << 32);
}

static int expect_ret(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": got=");
    putdec(actual);
    putstr(" expected=");
    putdec(expected);
    putstr("\n");
    return 1;
}

static int expect_u64(const char *name, uint64_t actual,
                      uint64_t expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": got=");
    puthex64(actual);
    putstr(" expected=");
    puthex64(expected);
    putstr("\n");
    return 1;
}

static int expect_res_ids(const char *name, long syscall_number,
                          uint32_t expected_real,
                          uint32_t expected_effective,
                          uint32_t expected_saved) {
    uint32_t real_id = UINT32_MAX;
    uint32_t effective_id = UINT32_MAX;
    uint32_t saved_id = UINT32_MAX;
    long result = raw_syscall3(syscall_number, (long)&real_id,
                               (long)&effective_id, (long)&saved_id);
    int failures = expect_ret(name, result, 0);
    if (!failures &&
        (real_id != expected_real || effective_id != expected_effective ||
         saved_id != expected_saved)) {
        putstr(name);
        putstr(": ids=");
        putdec(real_id);
        putstr(",");
        putdec(effective_id);
        putstr(",");
        putdec(saved_id);
        putstr("\n");
        failures++;
    }
    return failures;
}

static int capget(struct cap_data data[2]) {
    struct cap_header header;
    header.version = LINUX_CAP_VERSION_3;
    header.pid = 0;
    memzero(data, 2u * sizeof(data[0]));
    return (int)raw_syscall3(SYS_capget, (long)&header, (long)data, 0);
}

static int capset(const struct cap_data data[2]) {
    struct cap_header header;
    header.version = LINUX_CAP_VERSION_3;
    header.pid = 0;
    return (int)raw_syscall3(SYS_capset, (long)&header, (long)data, 0);
}

static int run_probe(void) {
    struct cap_data capabilities[2];
    uint64_t initial_effective;
    uint64_t initial_permitted;
    int failures = 0;
    long result;

    failures += expect_res_ids("initial_uids", SYS_getresuid, 0, 0, 0);
    failures += expect_res_ids("initial_gids", SYS_getresgid, 0, 0, 0);
    failures += expect_ret("setuid_invalid",
                           raw_syscall3(SYS_setuid, ID_UNCHANGED, 0, 0),
                           -EINVAL);
    failures += expect_ret("setgid_invalid",
                           raw_syscall3(SYS_setgid, ID_UNCHANGED, 0, 0),
                           -EINVAL);

    failures += expect_ret("capget_initial", capget(capabilities), 0);
    initial_effective = cap_join(capabilities, 0);
    initial_permitted = cap_join(capabilities, 1);

    failures += expect_ret("setfsuid_away",
                           raw_syscall3(SYS_setfsuid, 123, 0, 0), 0);
    failures += expect_ret("setfsuid_query_away",
                           raw_syscall3(SYS_setfsuid, ID_UNCHANGED, 0, 0),
                           123);
    failures += expect_ret("capget_fsuid_away", capget(capabilities), 0);
    failures += expect_u64("fsuid_effective_clear",
                           cap_join(capabilities, 0),
                           initial_effective & ~FILESYSTEM_CAPABILITIES);
    failures += expect_u64("fsuid_permitted_preserved",
                           cap_join(capabilities, 1), initial_permitted);
    failures += expect_ret("setfsuid_restore",
                           raw_syscall3(SYS_setfsuid, 0, 0, 0), 123);
    failures += expect_ret("capget_fsuid_restore", capget(capabilities), 0);
    failures += expect_u64("fsuid_effective_restore",
                           cap_join(capabilities, 0), initial_effective);

    failures += expect_ret("setfsuid_before_noop_resuid",
                           raw_syscall3(SYS_setfsuid, 123, 0, 0), 0);
    failures += expect_ret("setresuid_all_unchanged",
                           raw_syscall3(SYS_setresuid, ID_UNCHANGED,
                                        ID_UNCHANGED, ID_UNCHANGED), 0);
    failures += expect_ret("fsuid_preserved_by_unchanged_resuid",
                           raw_syscall3(SYS_setfsuid, ID_UNCHANGED, 0, 0),
                           123);
    failures += expect_ret("setresuid_reset_fsuid",
                           raw_syscall3(SYS_setresuid, ID_UNCHANGED, 0,
                                        ID_UNCHANGED), 0);
    failures += expect_ret("fsuid_reset_by_resuid",
                           raw_syscall3(SYS_setfsuid, ID_UNCHANGED, 0, 0), 0);
    failures += expect_ret("capget_resuid_fs_restore", capget(capabilities),
                           0);
    failures += expect_u64("resuid_fs_cap_state",
                           cap_join(capabilities, 0),
                           initial_effective & ~FILESYSTEM_CAPABILITIES);

    failures += expect_ret("setfsgid_away",
                           raw_syscall3(SYS_setfsgid, 123, 0, 0), 0);
    failures += expect_ret("setresgid_all_unchanged",
                           raw_syscall3(SYS_setresgid, ID_UNCHANGED,
                                        ID_UNCHANGED, ID_UNCHANGED), 0);
    failures += expect_ret("fsgid_preserved_by_unchanged_resgid",
                           raw_syscall3(SYS_setfsgid, ID_UNCHANGED, 0, 0),
                           123);
    failures += expect_ret("setresgid_reset_fsgid",
                           raw_syscall3(SYS_setresgid, ID_UNCHANGED, 0,
                                        ID_UNCHANGED), 0);
    failures += expect_ret("fsgid_reset_by_resgid",
                           raw_syscall3(SYS_setfsgid, ID_UNCHANGED, 0, 0), 0);

    failures += expect_ret("setresgid_privileged",
                           raw_syscall3(SYS_setresgid, 1000, 2000, 3000), 0);
    failures += expect_res_ids("gids_privileged", SYS_getresgid,
                               1000, 2000, 3000);
    failures += expect_ret("capget_before_drop_setgid", capget(capabilities),
                           0);
    capabilities[0].effective &= ~(1u << CAP_SETGID);
    capabilities[0].permitted &= ~(1u << CAP_SETGID);
    failures += expect_ret("capset_drop_setgid", capset(capabilities), 0);
    failures += expect_ret("setgid_current_effective_denied",
                           raw_syscall3(SYS_setgid, 2000, 0, 0), -EPERM);
    failures += expect_ret("setgid_saved_allowed",
                           raw_syscall3(SYS_setgid, 3000, 0, 0), 0);
    failures += expect_res_ids("gids_after_setgid", SYS_getresgid,
                               1000, 3000, 3000);
    failures += expect_ret("setregid_real_allowed",
                           raw_syscall3(SYS_setregid, ID_UNCHANGED, 1000, 0),
                           0);
    failures += expect_res_ids("gids_after_setregid_real", SYS_getresgid,
                               1000, 1000, 3000);
    failures += expect_ret("setregid_saved_allowed",
                           raw_syscall3(SYS_setregid, ID_UNCHANGED, 3000, 0),
                           0);
    failures += expect_ret("setresgid_unknown_denied",
                           raw_syscall3(SYS_setresgid, 9999, ID_UNCHANGED,
                                        ID_UNCHANGED), -EPERM);
    failures += expect_ret("setfsgid_real_allowed",
                           raw_syscall3(SYS_setfsgid, 1000, 0, 0), 3000);
    failures += expect_ret("setfsgid_unknown_ignored",
                           raw_syscall3(SYS_setfsgid, 9999, 0, 0), 1000);
    failures += expect_ret("setfsgid_unknown_stable",
                           raw_syscall3(SYS_setfsgid, ID_UNCHANGED, 0, 0),
                           1000);

    failures += expect_ret("setresuid_privileged",
                           raw_syscall3(SYS_setresuid, 1000, 2000, 3000), 0);
    failures += expect_res_ids("uids_privileged", SYS_getresuid,
                               1000, 2000, 3000);
    failures += expect_ret("capget_after_uid_drop", capget(capabilities), 0);
    failures += expect_u64("uid_drop_effective", cap_join(capabilities, 0),
                           0);
    failures += expect_u64("uid_drop_permitted", cap_join(capabilities, 1),
                           0);
    failures += expect_ret("setuid_current_effective_denied",
                           raw_syscall3(SYS_setuid, 2000, 0, 0), -EPERM);
    failures += expect_ret("setresuid_unknown_denied",
                           raw_syscall3(SYS_setresuid, 9999, ID_UNCHANGED,
                                        ID_UNCHANGED), -EPERM);
    failures += expect_ret("setfsuid_saved_allowed",
                           raw_syscall3(SYS_setfsuid, 3000, 0, 0), 2000);
    failures += expect_ret("setfsuid_unknown_ignored",
                           raw_syscall3(SYS_setfsuid, 9999, 0, 0), 3000);
    failures += expect_ret("setfsuid_unknown_stable",
                           raw_syscall3(SYS_setfsuid, ID_UNCHANGED, 0, 0),
                           3000);
    failures += expect_ret("setreuid_real_allowed",
                           raw_syscall3(SYS_setreuid, ID_UNCHANGED, 1000, 0),
                           0);
    failures += expect_res_ids("uids_after_setreuid_real", SYS_getresuid,
                               1000, 1000, 3000);
    failures += expect_ret("setreuid_saved_allowed",
                           raw_syscall3(SYS_setreuid, ID_UNCHANGED, 3000, 0),
                           0);
    failures += expect_ret("setreuid_effective_to_real",
                           raw_syscall3(SYS_setreuid, 3000, ID_UNCHANGED, 0),
                           0);
    failures += expect_res_ids("uids_final", SYS_getresuid,
                               3000, 3000, 3000);
    result = raw_syscall3(SYS_setuid, 3000, 0, 0);
    failures += expect_ret("setuid_real_allowed", result, 0);

    putstr("credential_transition_abi_probe: ");
    putstr(failures ? "FAIL\n" : "OK\n");
    return failures ? 1 : 0;
}

void _start(void) {
    int result = run_probe();
    (void)raw_syscall3(SYS_exit, result, 0, 0);
    for (;;) {}
}
