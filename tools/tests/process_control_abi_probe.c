/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-neutral Linux process-control ABI probe.
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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_PRIO_PROCESS 0
#define TEST_PRIO_PGRP 1
#define TEST_PRIO_USER 2

#define TEST_IOPRIO_WHO_PROCESS 1
#define TEST_IOPRIO_WHO_PGRP 2
#define TEST_IOPRIO_WHO_USER 3
#define TEST_IOPRIO_CLASS_SHIFT 13
#define TEST_IOPRIO_CLASS_RT 1
#define TEST_IOPRIO_CLASS_BE 2

struct linux_sysinfo64 {
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram;
    uint64_t freeram;
    uint64_t sharedram;
    uint64_t bufferram;
    uint64_t totalswap;
    uint64_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint32_t alignment_pad;
    uint64_t totalhigh;
    uint64_t freehigh;
    uint32_t mem_unit;
    uint8_t trailing_pad[4];
};

_Static_assert(sizeof(struct linux_sysinfo64) == 112,
               "64-bit Linux sysinfo layout");
_Static_assert(offsetof(struct linux_sysinfo64, loads) == 8,
               "64-bit Linux sysinfo loads offset");
_Static_assert(offsetof(struct linux_sysinfo64, totalram) == 32,
               "64-bit Linux sysinfo total RAM offset");
_Static_assert(offsetof(struct linux_sysinfo64, procs) == 80,
               "64-bit Linux sysinfo process count offset");
_Static_assert(offsetof(struct linux_sysinfo64, mem_unit) == 104,
               "64-bit Linux sysinfo memory unit offset");

static int failures;
static char last_proc_self_stat[1024];

static const int exec_nice_value = 7;
static const int exec_io_priority =
    (TEST_IOPRIO_CLASS_BE << TEST_IOPRIO_CLASS_SHIFT) | (2 << 3) | 6;
static const unsigned long exec_personality = 0x40000ul;

static void check(int condition, const char *name)
{
    if (condition) {
        printf("ok: %s\n", name);
    } else {
        printf("FAIL: %s errno=%d\n", name, errno);
        ++failures;
    }
}

static long raw_getpriority(int which, unsigned int who)
{
    errno = 0;
    return syscall(SYS_getpriority, which, who);
}

static int raw_nice_value(void)
{
    long raw = raw_getpriority(TEST_PRIO_PROCESS, 0);
    return raw < 0 ? 1000 : 20 - (int)raw;
}

static int proc_stat_signed_field(const char *stat_line, int wanted_field)
{
    char *cursor;
    int field = 3;

    cursor = strrchr(stat_line, ')');
    if (!cursor)
        return 1000;
    ++cursor;
    while (field <= wanted_field) {
        int negative = 0;
        int value = 0;

        while (*cursor == ' ' || *cursor == '\t')
            ++cursor;
        if (!*cursor)
            return 1000;
        if (field == wanted_field) {
            if (*cursor == '-') {
                negative = 1;
                ++cursor;
            }
            if (*cursor < '0' || *cursor > '9')
                return 1000;
            while (*cursor >= '0' && *cursor <= '9') {
                value = value * 10 + (*cursor - '0');
                ++cursor;
            }
            return negative ? -value : value;
        }
        while (*cursor && *cursor != ' ' && *cursor != '\t' &&
               *cursor != '\n')
            ++cursor;
        ++field;
    }
    return 1000;
}

static int proc_self_sched_values(int *priority, int *nice_value)
{
    FILE *file = fopen("/proc/self/stat", "r");

    if (!file)
        return -1;
    if (!fgets(last_proc_self_stat, sizeof(last_proc_self_stat), file)) {
        fclose(file);
        return -1;
    }
    fclose(file);
    *priority = proc_stat_signed_field(last_proc_self_stat, 18);
    *nice_value = proc_stat_signed_field(last_proc_self_stat, 19);
    return (*priority == 1000 || *nice_value == 1000) ? -1 : 0;
}

static void test_sysinfo(void)
{
    struct linux_sysinfo64 information;
    long result;

    memset(&information, 0xa5, sizeof(information));
    errno = 0;
    result = syscall(SYS_sysinfo, &information);
    check(result == 0 && information.uptime >= 0 &&
              information.totalram > 0 &&
              information.freeram <= information.totalram &&
              information.procs > 0 && information.mem_unit != 0,
          "sysinfo reports live system state");

    errno = 0;
    result = syscall(SYS_sysinfo, NULL);
    check(result == -1 && errno == EFAULT, "sysinfo null output");
}

static void test_personality(void)
{
    const unsigned long query = 0xfffffffful;
    const unsigned long marker = 0x40000ul;
    long original;
    long previous;
    long observed;
    pid_t child;
    int status = 0;

    original = syscall(SYS_personality, query);
    errno = 0;
    previous = syscall(SYS_personality, marker);
    observed = syscall(SYS_personality, query);
    check(original >= 0 && previous == original && observed == (long)marker,
          "personality stores and returns previous state");

    fflush(stdout);
    child = fork();
    if (child == 0) {
        long inherited = syscall(SYS_personality, query);
        _exit(inherited == (long)marker ? 0 : 10);
    }
    check(child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "personality is inherited across fork");
    if (original >= 0)
        check(syscall(SYS_personality, (unsigned long)original) == marker,
              "personality restores previous state");
}

static void test_set_tid_address(void)
{
    pid_t child;
    int status = 0;

    fflush(stdout);
    child = fork();
    if (child == 0) {
        static int clear_word = 1;
        long tid = syscall(SYS_gettid);
        long result = syscall(SYS_set_tid_address, &clear_word);
        _exit(result == tid ? 0 : 20);
    }
    check(child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "set_tid_address returns the calling thread ID");
}

static void test_nice(void)
{
    int original = raw_nice_value();
    pid_t child;
    int status = 0;
    long result;

    check(original >= -20 && original <= 19,
          "getpriority returns raw translated nice state");

    errno = 0;
    result = syscall(SYS_getpriority, 3, 0);
    check(result == -1 && errno == EINVAL,
          "getpriority rejects an invalid selector");

    errno = 0;
    result = syscall(SYS_getpriority, TEST_PRIO_PROCESS, 0x7fffffffu);
    check(result == -1 && errno == ESRCH,
          "getpriority reports a missing process");

    fflush(stdout);
    child = fork();
    if (child == 0) {
        int inherited = raw_nice_value();
        int proc_priority;
        int proc_nice;
        if (inherited != original) _exit(30);
        if (syscall(SYS_setpriority, TEST_PRIO_PROCESS, 0, 100) != 0 ||
            raw_nice_value() != 19 ||
            proc_self_sched_values(&proc_priority, &proc_nice) < 0 ||
            proc_priority != 39 || proc_nice != 19)
            _exit(31);
        if (geteuid() == 0) {
            if (syscall(SYS_setpriority, TEST_PRIO_PROCESS, 0, -100) != 0 ||
                raw_nice_value() != -20 ||
                proc_self_sched_values(&proc_priority, &proc_nice) < 0 ||
                proc_priority != 0 || proc_nice != -20)
                _exit(32);
        }
        _exit(0);
    }
    check(child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "setpriority, procfs, and fork preserve signed nice state");

    fflush(stdout);
    child = fork();
    if (child == 0) {
        if (setgid(1234) != 0 || setuid(1234) != 0) _exit(40);
        errno = 0;
        result = syscall(SYS_setpriority, TEST_PRIO_PROCESS, 0, -1);
        _exit(result == -1 && errno == EACCES ? 0 : 41);
    }
    check(child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "setpriority enforces CAP_SYS_NICE and RLIMIT_NICE");

    check(raw_getpriority(TEST_PRIO_PGRP, 0) > 0,
          "getpriority selects the current process group");
    check(raw_getpriority(TEST_PRIO_USER, 0) > 0,
          "getpriority selects the current real user");
}

static long raw_ioprio_get(int which, int who)
{
    errno = 0;
    return syscall(SYS_ioprio_get, which, who);
}

static int verify_exec_process_control_state(void)
{
    int nice_value = raw_nice_value();
    int proc_priority = 1000;
    int proc_nice_value = 1000;
    long io_priority = raw_ioprio_get(TEST_IOPRIO_WHO_PROCESS, 0);
    long personality = syscall(SYS_personality, 0xfffffffful);

    (void)proc_self_sched_values(&proc_priority, &proc_nice_value);

    if (nice_value != exec_nice_value) {
        fprintf(stderr, "exec nice mismatch: got=%d expected=%d\n",
                nice_value, exec_nice_value);
        return 71;
    }
    if (proc_nice_value != exec_nice_value) {
        fprintf(stderr, "exec procfs nice mismatch: got=%d expected=%d\n",
                proc_nice_value, exec_nice_value);
        fprintf(stderr, "exec procfs stat: %s", last_proc_self_stat);
        return 74;
    }
    if (proc_priority != 20 + exec_nice_value) {
        fprintf(stderr, "exec procfs priority mismatch: got=%d expected=%d\n",
                proc_priority, 20 + exec_nice_value);
        fprintf(stderr, "exec procfs stat: %s", last_proc_self_stat);
        return 79;
    }
    if (io_priority != exec_io_priority) {
        fprintf(stderr, "exec I/O priority mismatch: got=%ld expected=%d\n",
                io_priority, exec_io_priority);
        return 72;
    }
    if (personality != (long)exec_personality) {
        fprintf(stderr, "exec personality mismatch: got=%ld expected=%lu\n",
                personality, exec_personality);
        return 73;
    }
    return 0;
}

static void test_exec_process_control_state(const char *program_path)
{
    pid_t child;
    int status = 0;

    fflush(stdout);
    child = fork();
    if (child == 0) {
        char *const child_argv[] = {
            (char *)program_path,
            (char *)"--verify-exec-process-control",
            NULL,
        };

        if (syscall(SYS_setpriority, TEST_PRIO_PROCESS, 0,
                    exec_nice_value) != 0)
            _exit(75);
        if (syscall(SYS_ioprio_set, TEST_IOPRIO_WHO_PROCESS, 0,
                    exec_io_priority) != 0)
            _exit(76);
        if (syscall(SYS_personality, exec_personality) < 0)
            _exit(77);
        execv(program_path, child_argv);
        _exit(78);
    }
    check(child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "exec and procfs preserve process-control state");
}

static void test_ioprio(void)
{
    long original = raw_ioprio_get(TEST_IOPRIO_WHO_PROCESS, 0);
    const int hinted_best_effort =
        (TEST_IOPRIO_CLASS_BE << TEST_IOPRIO_CLASS_SHIFT) | (2 << 3) | 7;
    long result;
    pid_t child;
    int status = 0;

    check(original >= 0, "ioprio_get reads current thread state");
    check(syscall(SYS_ioprio_set, TEST_IOPRIO_WHO_PROCESS, 0,
                  hinted_best_effort) == 0 &&
              raw_ioprio_get(TEST_IOPRIO_WHO_PROCESS, 0) ==
                  hinted_best_effort,
          "ioprio_set preserves class, level, and hint bits");

    errno = 0;
    result = syscall(SYS_ioprio_set, TEST_IOPRIO_WHO_PROCESS, 0, 1);
    check(result == -1 && errno == EINVAL,
          "ioprio_set rejects a NONE class with a nonzero level");

    check(syscall(SYS_ioprio_set, TEST_IOPRIO_WHO_PROCESS, 0, 0x10000) == 0 &&
              raw_ioprio_get(TEST_IOPRIO_WHO_PROCESS, 0) == 0,
          "ioprio_set follows the 16-bit kernel priority ABI");

    errno = 0;
    result = raw_ioprio_get(0, 0);
    check(result == -1 && errno == EINVAL,
          "ioprio_get rejects an invalid selector");

    errno = 0;
    result = raw_ioprio_get(TEST_IOPRIO_WHO_PROCESS, -1);
    check(result == -1 && errno == ESRCH,
          "ioprio_get reports a missing thread");

    fflush(stdout);
    child = fork();
    if (child == 0) {
        const int best_effort_five =
            (TEST_IOPRIO_CLASS_BE << TEST_IOPRIO_CLASS_SHIFT) | 5;
        long group_priority;
        if (setpgid(0, 0) != 0) _exit(50);
        if (syscall(SYS_ioprio_set, TEST_IOPRIO_WHO_PGRP, 0,
                    best_effort_five) != 0)
            _exit(51);
        if (raw_ioprio_get(TEST_IOPRIO_WHO_PROCESS, 0) != best_effort_five)
            _exit(52);
        if (syscall(SYS_ioprio_set, TEST_IOPRIO_WHO_PROCESS, 0, 0) != 0)
            _exit(53);
        group_priority = raw_ioprio_get(TEST_IOPRIO_WHO_PGRP, 0);
        _exit(group_priority ==
                      ((TEST_IOPRIO_CLASS_BE << TEST_IOPRIO_CLASS_SHIFT) | 4)
                  ? 0 : 54);
    }
    check(child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "ioprio process-group selection uses effective default priority");

    fflush(stdout);
    child = fork();
    if (child == 0) {
        const int best_effort_six =
            (TEST_IOPRIO_CLASS_BE << TEST_IOPRIO_CLASS_SHIFT) | 6;
        if (setgid(1234) != 0 || setuid(1234) != 0) _exit(60);
        if (syscall(SYS_ioprio_set, TEST_IOPRIO_WHO_PROCESS, 0,
                    best_effort_six) != 0 ||
            raw_ioprio_get(TEST_IOPRIO_WHO_USER, 0) != best_effort_six)
            _exit(61);
        errno = 0;
        result = syscall(SYS_ioprio_set, TEST_IOPRIO_WHO_PROCESS, 0,
                         TEST_IOPRIO_CLASS_RT << TEST_IOPRIO_CLASS_SHIFT);
        _exit(result == -1 && errno == EPERM ? 0 : 62);
    }
    check(child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "ioprio user-zero selection and realtime permissions");

    if (original >= 0)
        check(syscall(SYS_ioprio_set, TEST_IOPRIO_WHO_PROCESS, 0,
                      original) == 0,
              "ioprio restores previous state");
}

int main(int argc, char **argv)
{
    if (argc == 2 &&
        strcmp(argv[1], "--verify-exec-process-control") == 0)
        return verify_exec_process_control_state();

    test_sysinfo();
    test_personality();
    test_set_tid_address();
    test_nice();
    test_ioprio();
    test_exec_process_control_state(argv[0]);
    printf("process-control failures: %d\n", failures);
    return failures ? 1 : 0;
}
