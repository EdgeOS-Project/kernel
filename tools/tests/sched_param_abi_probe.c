/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux scheduler parameter ABI probe for Alpine rootfs validation.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_sched_setparam
#define SYS_sched_setparam 142
#endif

#ifndef SYS_sched_getparam
#define SYS_sched_getparam 143
#endif

#ifndef SYS_sched_setscheduler
#define SYS_sched_setscheduler 144
#endif

#ifndef SYS_sched_getscheduler
#define SYS_sched_getscheduler 145
#endif

#ifndef SYS_sched_rr_get_interval
#define SYS_sched_rr_get_interval 148
#endif

#ifndef SYS_sched_setattr
#define SYS_sched_setattr 314
#endif

#ifndef SYS_sched_getattr
#define SYS_sched_getattr 315
#endif

#ifndef SCHED_OTHER
#define SCHED_OTHER 0
#endif
#ifndef SCHED_FIFO
#define SCHED_FIFO 1
#endif
#ifndef SCHED_RR
#define SCHED_RR 2
#endif
#ifndef SCHED_BATCH
#define SCHED_BATCH 3
#endif
#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif
#ifndef SCHED_RESET_ON_FORK
#define SCHED_RESET_ON_FORK 0x40000000
#endif
#ifndef SCHED_FLAG_RESET_ON_FORK
#define SCHED_FLAG_RESET_ON_FORK 1u
#endif

struct sched_param_probe {
    int sched_priority;
};

struct sched_attr_probe {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};

static struct sched_param_probe g_param;
static struct sched_attr_probe g_attr;
static struct timespec g_ts;
static struct sched_attr_probe g_saved_attr;

static __attribute__((no_stack_protector)) int expect_errno(const char *name, long rc, int saved_errno, int expected) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, rc, saved_errno);
    if (rc != -1) return 1;
    if (saved_errno != expected) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int expect_success(const char *name, long rc, int saved_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, rc, saved_errno);
    if (rc != 0) return 1;
    if (saved_errno != 0) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_legacy_sched_params(void) {
    memset(&g_param, 0, sizeof(g_param));
    errno = 0;
    long rc = syscall(SYS_sched_getparam, 0, &g_param);
    dprintf(STDOUT_FILENO, "sched_getparam_pid0_rc:%ld errno:%d prio:%d\n", rc, errno, g_param.sched_priority);
    if (rc != 0 || errno != 0 || g_param.sched_priority != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setparam, 0, &g_param);
    if (expect_success("sched_setparam_pid0", rc, errno) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setscheduler, 0, SCHED_OTHER, &g_param);
    if (expect_success("sched_setscheduler_pid0", rc, errno) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_getscheduler, 0);
    dprintf(STDOUT_FILENO, "sched_getscheduler_pid0_rc:%ld errno:%d\n", rc, errno);
    if (rc != SCHED_OTHER || errno != 0) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_legacy_errors(void) {
    errno = 0;
    long rc = syscall(SYS_sched_getparam, 0, (void *)0);
    if (expect_errno("sched_getparam_null", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_getparam, -1, &g_param);
    if (expect_errno("sched_getparam_negpid", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setparam, 0, (void *)0);
    if (expect_errno("sched_setparam_null", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setparam, -1, &g_param);
    if (expect_errno("sched_setparam_negpid", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setscheduler, 0, SCHED_OTHER, (void *)0);
    if (expect_errno("sched_setscheduler_null", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setscheduler, -1, SCHED_OTHER, &g_param);
    if (expect_errno("sched_setscheduler_negpid", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_getscheduler, -1);
    if (expect_errno("sched_getscheduler_negpid", rc, errno, EINVAL) != 0) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_rr_interval(void) {
    memset(&g_ts, 0, sizeof(g_ts));
    errno = 0;
    long rc = syscall(SYS_sched_rr_get_interval, 0, &g_ts);
    dprintf(STDOUT_FILENO, "sched_rr_get_interval_pid0_rc:%ld errno:%d sec:%lld nsec:%lld\n",
            rc, errno, (long long)g_ts.tv_sec, (long long)g_ts.tv_nsec);
    if (rc != 0 || errno != 0) return 1;
    if (g_ts.tv_sec < 0 || g_ts.tv_nsec < 0 || g_ts.tv_nsec >= 1000000000L) return 1;

    errno = 0;
    rc = syscall(SYS_sched_rr_get_interval, 0, (void *)0);
    if (expect_errno("sched_rr_get_interval_null", rc, errno, EFAULT) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_rr_get_interval, -1, &g_ts);
    if (expect_errno("sched_rr_get_interval_negpid", rc, errno, EINVAL) != 0) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_sched_attr(void) {
    memset(&g_attr, 0, sizeof(g_attr));
    g_attr.size = sizeof(g_attr);
    errno = 0;
    long rc = syscall(SYS_sched_getattr, 0, &g_attr, sizeof(g_attr), 0);
    dprintf(STDOUT_FILENO, "sched_getattr_pid0_rc:%ld errno:%d size:%u policy:%u prio:%u\n",
            rc, errno, g_attr.size, g_attr.sched_policy, g_attr.sched_priority);
    if (rc != 0 || errno != 0) return 1;
    if (g_attr.size < 48 || g_attr.sched_policy != SCHED_OTHER || g_attr.sched_priority != 0) return 1;
    g_saved_attr = g_attr;

    errno = 0;
    rc = syscall(SYS_sched_setattr, 0, &g_attr, 0);
    if (expect_success("sched_setattr_pid0", rc, errno) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_getattr, -1, &g_attr, sizeof(g_attr), 0);
    if (expect_errno("sched_getattr_negpid", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_getattr, 0, (void *)0, sizeof(g_attr), 0);
    if (expect_errno("sched_getattr_null", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_getattr, 0, (void *)1, sizeof(g_attr), 0);
    if (expect_errno("sched_getattr_badptr", rc, errno, EFAULT) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setattr, -1, &g_attr, 0);
    if (expect_errno("sched_setattr_negpid", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setattr, 0, (void *)0, 0);
    if (expect_errno("sched_setattr_null", rc, errno, EINVAL) != 0) return 1;

    errno = 0;
    rc = syscall(SYS_sched_setattr, 0, (void *)1, 0);
    if (expect_errno("sched_setattr_badptr", rc, errno, EFAULT) != 0) return 1;

    memset(&g_attr, 0, sizeof(g_attr));
    g_attr.size = 47;
    errno = 0;
    rc = syscall(SYS_sched_setattr, 0, &g_attr, 0);
    if (expect_errno("sched_setattr_short", rc, errno, E2BIG) != 0) return 1;
    if (g_attr.size < sizeof(g_attr)) return 1;

    memset(&g_attr, 0, sizeof(g_attr));
    g_attr.size = 0;
    g_attr.sched_policy = SCHED_OTHER;
    errno = 0;
    rc = syscall(SYS_sched_setattr, 0, &g_attr, 0);
    if (expect_success("sched_setattr_size0", rc, errno) != 0) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int set_and_check_policy(
    int policy, int priority) {
    struct sched_param_probe parameter;
    long rc;
    parameter.sched_priority = priority;
    errno = 0;
    rc = syscall(SYS_sched_setscheduler, 0, policy, &parameter);
    dprintf(STDOUT_FILENO, "sched_setscheduler_policy:%d prio:%d rc:%ld errno:%d\n",
            policy, priority, rc, errno);
    if (rc != 0 || errno != 0) return 1;
    errno = 0;
    rc = syscall(SYS_sched_getscheduler, 0);
    if (rc != policy || errno != 0) return 1;
    memset(&parameter, 0, sizeof(parameter));
    errno = 0;
    rc = syscall(SYS_sched_getparam, 0, &parameter);
    if (rc != 0 || errno != 0 || parameter.sched_priority != priority)
        return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_policy_roundtrip(void) {
    if (set_and_check_policy(SCHED_BATCH, 0) != 0) return 1;
    if (set_and_check_policy(SCHED_IDLE, 0) != 0) return 1;
    if (set_and_check_policy(SCHED_FIFO, 1) != 0) return 1;
    if (set_and_check_policy(SCHED_RR, 1) != 0) return 1;
    memset(&g_ts, 0, sizeof(g_ts));
    errno = 0;
    long rc = syscall(SYS_sched_rr_get_interval, 0, &g_ts);
    dprintf(STDOUT_FILENO, "sched_rr_policy_interval_rc:%ld errno:%d sec:%lld nsec:%lld\n",
            rc, errno, (long long)g_ts.tv_sec, (long long)g_ts.tv_nsec);
    if (rc != 0 || errno != 0 ||
        (g_ts.tv_sec == 0 && g_ts.tv_nsec == 0))
        return 1;
    return set_and_check_policy(SCHED_OTHER, 0);
}

static __attribute__((no_stack_protector)) int test_reset_on_fork(void) {
    pid_t child;
    int status;
    long rc;
    memset(&g_attr, 0, sizeof(g_attr));
    g_attr.size = sizeof(g_attr);
    g_attr.sched_policy = SCHED_OTHER;
    g_attr.sched_flags = SCHED_FLAG_RESET_ON_FORK;
    g_attr.sched_nice = -1;
    errno = 0;
    rc = syscall(SYS_sched_setattr, 0, &g_attr, 0);
    if (expect_success("sched_setattr_reset_on_fork", rc, errno) != 0)
        return 1;
    errno = 0;
    rc = syscall(SYS_sched_getscheduler, 0);
    if (rc != (SCHED_OTHER | SCHED_RESET_ON_FORK) || errno != 0)
        return 1;
    child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        memset(&g_attr, 0, sizeof(g_attr));
        g_attr.size = sizeof(g_attr);
        errno = 0;
        rc = syscall(SYS_sched_getattr, 0, &g_attr, sizeof(g_attr), 0);
        _exit(rc == 0 && errno == 0 &&
              g_attr.sched_policy == SCHED_OTHER &&
              g_attr.sched_nice == 0 &&
              !(g_attr.sched_flags & SCHED_FLAG_RESET_ON_FORK) ? 0 : 1);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 1;
    g_saved_attr.size = sizeof(g_saved_attr);
    g_saved_attr.sched_flags = 0;
    errno = 0;
    rc = syscall(SYS_sched_setattr, 0, &g_saved_attr, 0);
    return expect_success("sched_setattr_restore", rc, errno);
}

static __attribute__((no_stack_protector)) int wait_for_success(
    const char *name, pid_t child) {
    int status = 0;
    if (waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0)
        return 0;
    dprintf(STDOUT_FILENO, "%s:failed status:%d\n", name, status);
    return 1;
}

static __attribute__((no_stack_protector)) int test_reset_flag_privilege(void) {
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        long rc;
        memset(&g_attr, 0, sizeof(g_attr));
        g_attr.size = sizeof(g_attr);
        g_attr.sched_policy = SCHED_OTHER;
        g_attr.sched_flags = SCHED_FLAG_RESET_ON_FORK;
        errno = 0;
        rc = syscall(SYS_sched_setattr, 0, &g_attr, 0);
        if (rc != 0 || errno != 0) _exit(2);
        if (setuid(65534) != 0) _exit(3);
        g_attr.sched_flags = 0;
        errno = 0;
        rc = syscall(SYS_sched_setattr, 0, &g_attr, 0);
        _exit(rc == -1 && errno == EPERM ? 0 : 4);
    }
    if (wait_for_success("sched_reset_clear_unprivileged", child) != 0)
        return 1;

    child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        long rc;
        if (setuid(65534) != 0) _exit(2);
        memset(&g_attr, 0, sizeof(g_attr));
        g_attr.size = sizeof(g_attr);
        g_attr.sched_policy = SCHED_OTHER;
        g_attr.sched_flags = SCHED_FLAG_RESET_ON_FORK;
        errno = 0;
        rc = syscall(SYS_sched_setattr, 0, &g_attr, 0);
        _exit(rc == 0 && errno == 0 ? 0 : 3);
    }
    if (wait_for_success("sched_reset_set_unprivileged", child) != 0)
        return 1;
    dprintf(STDOUT_FILENO, "sched_reset_on_fork_privilege:pass\n");
    return 0;
}

int main(void) {
    if (test_legacy_sched_params() != 0) _exit(1);
    if (test_legacy_errors() != 0) _exit(1);
    if (test_rr_interval() != 0) _exit(1);
    if (test_sched_attr() != 0) _exit(1);
    if (test_policy_roundtrip() != 0) _exit(1);
    if (test_reset_on_fork() != 0) _exit(1);
    if (test_reset_flag_privilege() != 0) _exit(1);
    dprintf(STDOUT_FILENO, "SCHED_PARAM_ABI_PROBE_PASS\n");
    _exit(0);
}
