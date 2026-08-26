/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-neutral Linux resource-limit and accounting ABI probe.
 * Copyright (c) EdgeOS Contributors.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(struct rlimit) == 16, "64-bit Linux rlimit layout");
_Static_assert(offsetof(struct rusage, ru_nivcsw) +
                   sizeof(((struct rusage *)0)->ru_nivcsw) == 144,
               "64-bit Linux kernel rusage payload");
_Static_assert(sizeof(struct tms) == 32, "64-bit Linux tms layout");

static int failures;

static void check(int condition, const char *name)
{
    if (condition) {
        printf("ok: %s\n", name);
    } else {
        printf("FAIL: %s errno=%d\n", name, errno);
        ++failures;
    }
}

static int timeval_valid(const struct timeval *value)
{
    return value->tv_sec >= 0 && value->tv_usec >= 0 &&
           value->tv_usec < 1000000;
}

static rlim_t smaller_soft_limit(rlim_t current)
{
    if (current == RLIM_INFINITY || current > 65536)
        return 65536;
    return current > 1 ? current - 1 : current;
}

static void test_prlimit_copyout_order(void)
{
    pid_t child;
    int status = 0;

    fflush(stdout);
    child = fork();
    if (child == 0) {
        struct rlimit before;
        struct rlimit replacement;
        struct rlimit after;
        long result;

        if (syscall(SYS_getrlimit, RLIMIT_STACK, &before) != 0)
            _exit(20);
        replacement = before;
        replacement.rlim_cur = smaller_soft_limit(before.rlim_cur);
        errno = 0;
        result = syscall(SYS_prlimit64, 0, RLIMIT_STACK, &replacement,
                         (void *)1);
        if (result != -1 || errno != EFAULT)
            _exit(21);
        if (syscall(SYS_getrlimit, RLIMIT_STACK, &after) != 0 ||
            memcmp(&after, &replacement, sizeof(after)) != 0)
            _exit(22);
        _exit(0);
    }
    check(child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "prlimit64 applies replacement before old-limit copyout fault");
}

struct credential_target {
    pid_t pid;
    int ready_fd;
    int release_fd;
};

static int spawn_credential_target(uid_t uid, gid_t gid,
                                   struct credential_target *target)
{
    int ready[2];
    int release[2];
    pid_t child;

    if (!target || pipe(ready) != 0)
        return -1;
    if (pipe(release) != 0) {
        close(ready[0]);
        close(ready[1]);
        return -1;
    }
    fflush(stdout);
    child = fork();
    if (child == 0) {
        char marker = 'R';
        close(ready[0]);
        close(release[1]);
        if (setgid(gid) != 0 || setuid(uid) != 0)
            marker = 'E';
        if (write(ready[1], &marker, 1) != 1)
            _exit(30);
        if (read(release[0], &marker, 1) != 1)
            _exit(31);
        _exit(marker == 'E' ? 32 : 0);
    }
    close(ready[1]);
    close(release[0]);
    if (child < 0) {
        close(ready[0]);
        close(release[1]);
        return -1;
    }
    target->pid = child;
    target->ready_fd = ready[0];
    target->release_fd = release[1];
    return 0;
}

static int credential_target_ready(struct credential_target *target)
{
    char marker = 0;
    int ready = target && read(target->ready_fd, &marker, 1) == 1 &&
                marker == 'R';
    if (target) close(target->ready_fd);
    return ready;
}

static int credential_target_release(struct credential_target *target)
{
    char marker = 'X';
    int status = 0;
    int released;

    if (!target) return 0;
    released = write(target->release_fd, &marker, 1) == 1;
    close(target->release_fd);
    return released && waitpid(target->pid, &status, 0) == target->pid &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void test_prlimit_credentials(void)
{
    struct credential_target matching;
    struct credential_target mismatched;
    struct rlimit limit;
    struct rlimit lowered;
    struct rlimit raised;
    int matching_spawned;
    int mismatched_spawned;
    int matching_released;
    int mismatched_released;
    int matching_ready;
    int mismatched_ready;
    int ready;
    long result;

    memset(&matching, 0, sizeof(matching));
    memset(&mismatched, 0, sizeof(mismatched));
    matching_spawned =
        spawn_credential_target(1234, 1234, &matching) == 0;
    mismatched_spawned =
        spawn_credential_target(1234, 1235, &mismatched) == 0;
    matching_ready = matching_spawned && credential_target_ready(&matching);
    mismatched_ready =
        mismatched_spawned && credential_target_ready(&mismatched);
    ready = matching_ready && mismatched_ready;
    check(ready, "credential targets enter unprivileged state");
    if (!ready) {
        if (matching_spawned) (void)credential_target_release(&matching);
        if (mismatched_spawned) (void)credential_target_release(&mismatched);
        return;
    }

    check(setgid(1234) == 0 && setuid(1234) == 0,
          "caller enters matching unprivileged state");

    errno = 0;
    result = syscall(SYS_prlimit64, matching.pid, RLIMIT_STACK, NULL,
                     &limit);
    check(result == 0,
          "prlimit64 permits matching real UID and GID credentials");

    errno = 0;
    result = syscall(SYS_prlimit64, mismatched.pid, RLIMIT_STACK, NULL,
                     &limit);
    check(result == -1 && errno == EPERM,
          "prlimit64 rejects a mismatched target real GID");

    if (syscall(SYS_getrlimit, RLIMIT_STACK, &limit) == 0) {
        lowered = limit;
        lowered.rlim_cur = smaller_soft_limit(lowered.rlim_cur);
        lowered.rlim_max = lowered.rlim_cur;
        check(syscall(SYS_setrlimit, RLIMIT_STACK, &lowered) == 0,
              "unprivileged caller may lower its hard limit");
        raised = lowered;
        ++raised.rlim_max;
        errno = 0;
        result = syscall(SYS_setrlimit, RLIMIT_STACK, &raised);
        check(result == -1 && errno == EPERM,
              "unprivileged caller cannot raise its hard limit");
    } else {
        check(0, "read stack limit before hard-limit permission test");
    }

    matching_released = credential_target_release(&matching);
    mismatched_released = credential_target_release(&mismatched);
    check(matching_released && mismatched_released,
          "credential targets exit cleanly");
}

int main(void)
{
    struct rlimit get_limit;
    struct rlimit pr_limit;
    struct rusage usage;
    struct tms first_times;
    struct tms second_times;
    clock_t first_elapsed;
    clock_t second_elapsed;
    pid_t child;
    int status = 0;
    long result;

    memset(&get_limit, 0xa5, sizeof(get_limit));
    errno = 0;
    result = syscall(SYS_getrlimit, RLIMIT_NOFILE, &get_limit);
    check(result == 0 && get_limit.rlim_cur <= get_limit.rlim_max,
          "getrlimit nofile");

    memset(&pr_limit, 0x5a, sizeof(pr_limit));
    errno = 0;
    result = syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &pr_limit);
    check(result == 0 && memcmp(&get_limit, &pr_limit, sizeof(pr_limit)) == 0,
          "getrlimit and prlimit64 bytes match");

    if (get_limit.rlim_max != RLIM_INFINITY) {
        struct rlimit oversized = get_limit;
        oversized.rlim_max = RLIM_INFINITY;
        errno = 0;
        result = syscall(SYS_setrlimit, RLIMIT_NOFILE, &oversized);
        check(result == -1 && errno == EPERM,
              "nofile hard limit cannot exceed kernel descriptor ceiling");
    }

    errno = 0;
    result = syscall(SYS_getrlimit, 16, &pr_limit);
    check(result == -1 && errno == EINVAL, "getrlimit invalid resource");

    errno = 0;
    result = syscall(SYS_getrlimit, RLIMIT_NOFILE, NULL);
    check(result == -1 && errno == EFAULT, "getrlimit null output");

    errno = 0;
    result = syscall(SYS_prlimit64, -1, RLIMIT_NOFILE, NULL, &pr_limit);
    check(result == -1 && errno == ESRCH, "prlimit64 negative pid");

    errno = 0;
    result = syscall(SYS_prlimit64, 999999, RLIMIT_NOFILE, NULL, &pr_limit);
    check(result == -1 && errno == ESRCH, "prlimit64 missing pid");

    memset(&pr_limit, 0, sizeof(pr_limit));
    check(syscall(SYS_getrlimit, RLIMIT_STACK, &pr_limit) == 0 &&
              pr_limit.rlim_cur <= pr_limit.rlim_max,
          "getrlimit stack");

    fflush(stdout);
    child = fork();
    if (child != 0)
        check(child > 0, "fork for rlimit inheritance");
    if (child == 0) {
        struct rlimit inherited;
        struct rlimit replacement;
        if (syscall(SYS_getrlimit, RLIMIT_STACK, &inherited) != 0 ||
            memcmp(&inherited, &pr_limit, sizeof(inherited)) != 0)
            _exit(10);
        replacement = inherited;
        replacement.rlim_cur = smaller_soft_limit(inherited.rlim_cur);
        if (syscall(SYS_setrlimit, RLIMIT_STACK, &replacement) != 0)
            _exit(11);
        if (syscall(SYS_getrlimit, RLIMIT_STACK, &inherited) != 0 ||
            inherited.rlim_cur != replacement.rlim_cur)
            _exit(12);
        _exit(0);
    }
    if (child > 0) {
        check(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                  WEXITSTATUS(status) == 0,
              "child inherits and changes private rlimit state");
        memset(&get_limit, 0, sizeof(get_limit));
        check(syscall(SYS_getrlimit, RLIMIT_STACK, &get_limit) == 0 &&
                  memcmp(&get_limit, &pr_limit, sizeof(get_limit)) == 0,
              "child rlimit change does not mutate parent");
    }

    test_prlimit_copyout_order();

    memset(&usage, 0xa5, sizeof(usage));
    errno = 0;
    result = syscall(SYS_getrusage, RUSAGE_SELF, &usage);
    check(result == 0 && timeval_valid(&usage.ru_utime) &&
              timeval_valid(&usage.ru_stime),
          "getrusage self");

    memset(&usage, 0xa5, sizeof(usage));
    errno = 0;
    result = syscall(SYS_getrusage, RUSAGE_THREAD, &usage);
    check(result == 0 && timeval_valid(&usage.ru_utime) &&
              timeval_valid(&usage.ru_stime),
          "getrusage thread");

    memset(&usage, 0xa5, sizeof(usage));
    errno = 0;
    result = syscall(SYS_getrusage, RUSAGE_CHILDREN, &usage);
    check(result == 0 && timeval_valid(&usage.ru_utime) &&
              timeval_valid(&usage.ru_stime),
          "getrusage children");

    errno = 0;
    result = syscall(SYS_getrusage, 2, &usage);
    check(result == -1 && errno == EINVAL, "getrusage invalid selector");

    errno = 0;
    result = syscall(SYS_getrusage, RUSAGE_SELF, NULL);
    check(result == -1 && errno == EFAULT, "getrusage null output");

    memset(&first_times, 0xa5, sizeof(first_times));
    memset(&second_times, 0x5a, sizeof(second_times));
    first_elapsed = times(&first_times);
    second_elapsed = times(&second_times);
    check(first_elapsed != (clock_t)-1 && second_elapsed >= first_elapsed,
          "times elapsed ticks are monotonic");
    check(first_times.tms_utime >= 0 && first_times.tms_stime >= 0 &&
              first_times.tms_cutime >= 0 && first_times.tms_cstime >= 0,
          "times accounting fields are valid");

    if (geteuid() == 0)
        test_prlimit_credentials();

    printf("resource-accounting failures: %d\n", failures);
    return failures ? 1 : 0;
}
