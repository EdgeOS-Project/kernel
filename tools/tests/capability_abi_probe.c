/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code, licensed under MPL-2.0.
 *
 * Freestanding raw Linux capability syscall ABI probe.  This intentionally
 * avoids libc so Alpine VM validation is not coupled to EdgeOS' current
 * userland TLS/canary support.
 */
#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_getpid 39
#define SYS_capget 125
#define SYS_capset 126
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_capget 90
#define SYS_capset 91
#else
#error "capability_abi_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22
#define EPERM 1

#define LINUX_CAP_VERSION_1 0x19980330u
#define LINUX_CAP_VERSION_3 0x20080522u
#define CAP_BIT_CHOWN (1ull << 0)
#define CAP_BIT_SETPCAP (1ull << 8)

struct cap_hdr {
    uint32_t version;
    int pid;
};

struct cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

static long raw_syscall3(long nr, long a0, long a1, long a2) {
    long ret;
#if defined(__x86_64__)
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
        : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory");
    ret = x0;
#endif
    return ret;
}

static __attribute__((noreturn)) void raw_exit(int code) {
    raw_syscall3(SYS_exit, code, 0, 0);
    for (;;) {}
}

static uint64_t cstr_len(const char *s) {
    uint64_t n = 0;
    while (s[n]) n++;
    return n;
}

static void putstr(const char *s) {
    raw_syscall3(SYS_write, 1, (long)s, (long)cstr_len(s));
}

static void puthex64(uint64_t v) {
    char buf[19];
    int i;
    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 16; i++) {
        uint32_t shift = (uint32_t)(60 - i * 4);
        uint8_t nib = (uint8_t)((v >> shift) & 0xfu);
        buf[2 + i] = (char)(nib < 10 ? ('0' + nib) : ('a' + nib - 10));
    }
    buf[18] = 0;
    putstr(buf);
}

static void putdec(long v) {
    char buf[24];
    int pos = 23;
    unsigned long x;
    buf[pos] = 0;
    if (v < 0) {
        putstr("-");
        x = (unsigned long)(-v);
    } else {
        x = (unsigned long)v;
    }
    if (x == 0) {
        putstr("0");
        return;
    }
    while (x && pos > 0) {
        buf[--pos] = (char)('0' + (x % 10));
        x /= 10;
    }
    putstr(&buf[pos]);
}

static void memzero(void *p, uint64_t n) {
    uint8_t *b = (uint8_t *)p;
    while (n--) *b++ = 0;
}

static void memcopy(void *dst, const void *src, uint64_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
}

static uint64_t cap_join(const struct cap_data data[2], int field) {
    uint64_t lo;
    uint64_t hi;
    if (field == 0) {
        lo = data[0].effective;
        hi = data[1].effective;
    } else if (field == 1) {
        lo = data[0].permitted;
        hi = data[1].permitted;
    } else {
        lo = data[0].inheritable;
        hi = data[1].inheritable;
    }
    return lo | (hi << 32);
}

static void cap_split(struct cap_data data[2], uint64_t effective,
                      uint64_t permitted, uint64_t inheritable) {
    memzero(data, sizeof(struct cap_data) * 2);
    data[0].effective = (uint32_t)effective;
    data[0].permitted = (uint32_t)permitted;
    data[0].inheritable = (uint32_t)inheritable;
    data[1].effective = (uint32_t)(effective >> 32);
    data[1].permitted = (uint32_t)(permitted >> 32);
    data[1].inheritable = (uint32_t)(inheritable >> 32);
}

static int expect_ret(const char *name, long got, long want) {
    if (got != want) {
        putstr(name);
        putstr(": ret=");
        putdec(got);
        putstr(" expected=");
        putdec(want);
        putstr("\n");
        return 1;
    }
    return 0;
}

static int run_probe(void) {
    struct cap_hdr hdr;
    struct cap_hdr bad;
    struct cap_data data[2];
    struct cap_data saved[2];
    struct cap_data next[2];
    uint64_t saved_eff;
    uint64_t saved_perm;
    uint64_t saved_inh;
    uint64_t keep;
    long self_pid;
    long ret;
    int failures = 0;

    memzero(data, sizeof(data));
    hdr.version = LINUX_CAP_VERSION_3;
    hdr.pid = 0;
    ret = raw_syscall3(SYS_capget, (long)&hdr, (long)data, 0);
    failures += expect_ret("capget_v3", ret, 0);
    if (hdr.version != LINUX_CAP_VERSION_3) {
        putstr("capget_v3: bad version\n");
        failures++;
    }
    saved_eff = cap_join(data, 0);
    saved_perm = cap_join(data, 1);
    saved_inh = cap_join(data, 2);
    memcopy(saved, data, sizeof(saved));
    self_pid = raw_syscall3(SYS_getpid, 0, 0, 0);
    putstr("capget_v3: eff=");
    puthex64(saved_eff);
    putstr(" perm=");
    puthex64(saved_perm);
    putstr(" inh=");
    puthex64(saved_inh);
    putstr("\n");

    ret = raw_syscall3(SYS_capget, (long)&hdr, 0, 0);
    failures += expect_ret("capget_nulldata", ret, 0);

    bad.version = 0x12345678u;
    bad.pid = 0;
    ret = raw_syscall3(SYS_capget, (long)&bad, (long)data, 0);
    failures += expect_ret("capget_badver", ret, -EINVAL);
    if (bad.version != LINUX_CAP_VERSION_3) {
        putstr("capget_badver: preferred version not returned\n");
        failures++;
    }

    bad.version = LINUX_CAP_VERSION_3;
    bad.pid = -1;
    ret = raw_syscall3(SYS_capget, (long)&bad, (long)data, 0);
    failures += expect_ret("capget_negpid", ret, -EINVAL);

    ret = raw_syscall3(SYS_capget, 0, (long)data, 0);
    failures += expect_ret("capget_nullhdr", ret, -EFAULT);

    ret = raw_syscall3(SYS_capset, (long)&hdr, 0, 0);
    failures += expect_ret("capset_nulldata", ret, -EFAULT);

    ret = raw_syscall3(SYS_capset, 0, (long)saved, 0);
    failures += expect_ret("capset_nullhdr", ret, -EFAULT);

    bad.version = 0x87654321u;
    bad.pid = 0;
    ret = raw_syscall3(SYS_capset, (long)&bad, (long)saved, 0);
    failures += expect_ret("capset_badver", ret, -EINVAL);
    if (bad.version != LINUX_CAP_VERSION_3) {
        putstr("capset_badver: preferred version not returned\n");
        failures++;
    }

    bad.version = LINUX_CAP_VERSION_3;
    bad.pid = -1;
    ret = raw_syscall3(SYS_capset, (long)&bad, (long)saved, 0);
    failures += expect_ret("capset_negpid", ret, -EPERM);

    hdr.version = LINUX_CAP_VERSION_3;
    hdr.pid = (int)self_pid;
    ret = raw_syscall3(SYS_capset, (long)&hdr, (long)saved, 0);
    failures += expect_ret("capset_selfpid", ret, 0);
    hdr.pid = 0;

    cap_split(next, CAP_BIT_CHOWN, 0, saved_inh);
    ret = raw_syscall3(SYS_capset, (long)&hdr, (long)next, 0);
    failures += expect_ret("capset_effective_not_permitted", ret, -EPERM);

    hdr.version = LINUX_CAP_VERSION_1;
    hdr.pid = 0;
    memzero(data, sizeof(data));
    ret = raw_syscall3(SYS_capget, (long)&hdr, (long)data, 0);
    failures += expect_ret("capget_v1", ret, 0);
    if (data[1].effective || data[1].permitted || data[1].inheritable) {
        putstr("capget_v1: copied unexpected second word\n");
        failures++;
    }

    keep = saved_perm & (CAP_BIT_CHOWN | CAP_BIT_SETPCAP);
    if (keep == (CAP_BIT_CHOWN | CAP_BIT_SETPCAP)) {
        cap_split(next, CAP_BIT_CHOWN, CAP_BIT_CHOWN,
                  saved_inh | CAP_BIT_CHOWN);
        hdr.version = LINUX_CAP_VERSION_3;
        ret = raw_syscall3(SYS_capset, (long)&hdr, (long)next, 0);
        failures += expect_ret("capset_roundtrip_set", ret, 0);
        memzero(data, sizeof(data));
        ret = raw_syscall3(SYS_capget, (long)&hdr, (long)data, 0);
        failures += expect_ret("capset_roundtrip_get", ret, 0);
        if (cap_join(data, 0) != CAP_BIT_CHOWN ||
            cap_join(data, 1) != CAP_BIT_CHOWN ||
            cap_join(data, 2) != (saved_inh | CAP_BIT_CHOWN)) {
            putstr("capset_roundtrip: persisted values mismatch\n");
            failures++;
        }
        cap_split(next, 0, 0, 0);
        ret = raw_syscall3(SYS_capset, (long)&hdr, (long)next, 0);
        failures += expect_ret("capset_drop_without_setpcap", ret, 0);
        cap_split(next, CAP_BIT_CHOWN, CAP_BIT_CHOWN, 0);
        ret = raw_syscall3(SYS_capset, (long)&hdr, (long)next, 0);
        failures += expect_ret("capset_cannot_regain_permitted", ret, -EPERM);
    } else {
        putstr("capset_roundtrip_skipped: permitted=");
        puthex64(saved_perm);
        putstr("\n");
    }

    putstr("capability_abi_probe: ");
    putstr(failures ? "FAIL\n" : "OK\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    raw_exit(run_probe());
}

#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ __volatile__(
        "andq $-16, %rsp\n"
        "call probe_entry\n");
}
#else
void _start(void) {
    probe_entry();
}
#endif
