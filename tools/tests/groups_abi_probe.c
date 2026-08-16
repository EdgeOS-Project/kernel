/*
 * Original EdgeOS test code, licensed under MPL-2.0.
 *
 * Freestanding raw Linux supplementary group syscall ABI probe.
 */
#include <stdint.h>

#define SYS_write 1
#define SYS_exit 60
#define SYS_getgroups 115
#define SYS_setgroups 116

#define EFAULT 14
#define EINVAL 22

static long raw_syscall3(long nr, long a0, long a1, long a2) {
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
        : "rcx", "r11", "memory");
    return ret;
}

static void raw_exit(int code) {
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

static int expect_gid(const char *name, uint32_t got, uint32_t want) {
    if (got != want) {
        putstr(name);
        putstr(": gid=");
        putdec(got);
        putstr(" expected=");
        putdec(want);
        putstr("\n");
        return 1;
    }
    return 0;
}

static int run_probe(void) {
    uint32_t saved[16];
    uint32_t groups[4];
    uint32_t out[4];
    long saved_count;
    long ret;
    int failures = 0;

    memzero(saved, sizeof(saved));
    saved_count = raw_syscall3(SYS_getgroups, 0, 0, 0);
    if (saved_count < 0) {
        failures += expect_ret("getgroups_initial_count", saved_count, 0);
        saved_count = 0;
    }
    putstr("getgroups_initial_count:");
    putdec(saved_count);
    putstr("\n");
    if (saved_count > 16) {
        putstr("getgroups_initial_too_large_for_probe\n");
        return 1;
    }
    if (saved_count > 0) {
        ret = raw_syscall3(SYS_getgroups, saved_count, (long)saved, 0);
        failures += expect_ret("getgroups_save", ret, saved_count);
    }

    groups[0] = 10;
    groups[1] = 20;
    groups[2] = 30;
    ret = raw_syscall3(SYS_setgroups, 3, (long)groups, 0);
    failures += expect_ret("setgroups_three", ret, 0);

    ret = raw_syscall3(SYS_getgroups, 0, 0, 0);
    failures += expect_ret("getgroups_count_three", ret, 3);

    ret = raw_syscall3(SYS_getgroups, 2, (long)out, 0);
    failures += expect_ret("getgroups_short", ret, -EINVAL);

    ret = raw_syscall3(SYS_getgroups, 3, 0, 0);
    failures += expect_ret("getgroups_null_list", ret, -EFAULT);

    memzero(out, sizeof(out));
    ret = raw_syscall3(SYS_getgroups, 4, (long)out, 0);
    failures += expect_ret("getgroups_copy", ret, 3);
    failures += expect_gid("group0", out[0], 10);
    failures += expect_gid("group1", out[1], 20);
    failures += expect_gid("group2", out[2], 30);
    failures += expect_gid("group3_clear", out[3], 0);

    ret = raw_syscall3(SYS_setgroups, 1, 0, 0);
    failures += expect_ret("setgroups_null_list", ret, -EFAULT);

    ret = raw_syscall3(SYS_setgroups, 65537, (long)groups, 0);
    failures += expect_ret("setgroups_oversize", ret, -EINVAL);

    ret = raw_syscall3(SYS_setgroups, 0, 0, 0);
    failures += expect_ret("setgroups_clear", ret, 0);
    ret = raw_syscall3(SYS_getgroups, 0, 0, 0);
    failures += expect_ret("getgroups_count_clear", ret, 0);

    if (saved_count > 0) {
        ret = raw_syscall3(SYS_setgroups, saved_count, (long)saved, 0);
        failures += expect_ret("setgroups_restore", ret, 0);
    }

    putstr("groups_abi_probe: ");
    putstr(failures ? "FAIL\n" : "OK\n");
    return failures ? 1 : 0;
}

void _start(void) {
    raw_exit(run_probe());
}
