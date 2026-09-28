/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux sched_getaffinity/sched_setaffinity ABI probe for Alpine rootfs
 * validation.  This intentionally uses raw syscalls so libc wrappers cannot
 * hide kernel errno or return-size mismatches.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_sched_setaffinity
#define SYS_sched_setaffinity 203
#endif

#ifndef SYS_sched_getaffinity
#define SYS_sched_getaffinity 204
#endif

static uint64_t g_mask;
static uint64_t g_original_mask;

static __attribute__((no_stack_protector)) int expect_errno(const char *name, long rc, int saved_errno, int expected) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, rc, saved_errno);
    if (rc != -1) return 1;
    if (saved_errno != expected) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_get_valid_pid0(void) {
    g_mask = 0;
    errno = 0;
    long rc = syscall(SYS_sched_getaffinity, 0, sizeof(g_mask), &g_mask);
    dprintf(STDOUT_FILENO, "sched_getaffinity_pid0_rc:%ld errno:%d mask:0x%llx\n",
            rc, errno, (unsigned long long)g_mask);
    if (rc != (long)sizeof(g_mask)) return 1;
    if (errno != 0) return 1;
    if (g_mask == 0) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_get_errors(void) {
    errno = 0;
    long rc = syscall(SYS_sched_getaffinity, 0, 0, &g_mask);
    if (expect_errno("sched_getaffinity_size0", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_getaffinity, 0, 1, &g_mask);
    if (expect_errno("sched_getaffinity_short", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_getaffinity, 0, sizeof(g_mask), (void *)0);
    if (expect_errno("sched_getaffinity_null", rc, errno, EFAULT) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_getaffinity, -1, sizeof(g_mask), &g_mask);
    if (expect_errno("sched_getaffinity_negpid", rc, errno, ESRCH) != 0) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_set_valid_pid0(void) {
    uint64_t selected = g_original_mask & (~g_original_mask + 1u);
    uint64_t observed = 0;
    errno = 0;
    long rc = syscall(SYS_sched_setaffinity, 0, sizeof(selected), &selected);
    dprintf(STDOUT_FILENO, "sched_setaffinity_pid0_rc:%ld errno:%d\n", rc, errno);
    if (rc != 0) return 1;
    if (errno != 0) return 1;
    errno = 0;
    rc = syscall(SYS_sched_getaffinity, 0, sizeof(observed), &observed);
    dprintf(STDOUT_FILENO, "sched_affinity_roundtrip_rc:%ld errno:%d mask:0x%llx\n",
            rc, errno, (unsigned long long)observed);
    if (rc != (long)sizeof(observed) || errno != 0 || observed != selected)
        return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_set_errors(void) {
    uint64_t zero = 0;
    uint64_t invalid_cpu_only = 1ull << 63;
    uint64_t one = 1;
    errno = 0;
    long rc = syscall(SYS_sched_setaffinity, 0, 0, &one);
    if (expect_errno("sched_setaffinity_size0", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setaffinity, 0, sizeof(one), (void *)0);
    if (expect_errno("sched_setaffinity_null", rc, errno, EFAULT) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setaffinity, -1, sizeof(one), &one);
    if (expect_errno("sched_setaffinity_negpid", rc, errno, ESRCH) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setaffinity, 0, sizeof(zero), &zero);
    if (expect_errno("sched_setaffinity_zero_mask", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setaffinity, 0, sizeof(invalid_cpu_only), &invalid_cpu_only);
    if (expect_errno("sched_setaffinity_invalid_cpu_only", rc, errno, EINVAL) != 0) return 1;
    return 0;
}

int main(void) {
    if (test_get_valid_pid0() != 0) _exit(1);
    g_original_mask = g_mask;
    if (test_get_errors() != 0) _exit(1);
    if (test_set_valid_pid0() != 0) _exit(1);
    if (test_set_errors() != 0) _exit(1);
    errno = 0;
    if (syscall(SYS_sched_setaffinity, 0, sizeof(g_original_mask),
                &g_original_mask) != 0 || errno != 0)
        _exit(1);
    dprintf(STDOUT_FILENO, "SCHED_AFFINITY_ABI_PROBE_PASS\n");
    _exit(0);
}
