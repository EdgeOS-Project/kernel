#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *name) {
    if (condition) {
        printf("PASS %s\n", name);
    } else {
        printf("FAIL %s errno=%d (%s)\n", name, errno, strerror(errno));
        ++failures;
    }
}

static void check_fault(long result, const char *name) {
    check(result == -1 && errno == EFAULT, name);
}

int main(void) {
    struct timespec timestamp;
    struct timeval timeval;
    struct timezone timezone;
    struct utsname uts;
    unsigned char random_bytes[64];
    unsigned int cpu = UINT32_MAX;
    unsigned int node = UINT32_MAX;
    uint32_t ruid = UINT32_MAX;
    uint32_t euid = UINT32_MAX;
    uint32_t suid = UINT32_MAX;
    uint32_t rgid = UINT32_MAX;
    uint32_t egid = UINT32_MAX;
    uint32_t sgid = UINT32_MAX;
    mode_t previous_umask;
    long seconds;

    check(syscall(SYS_getpid) == getpid(), "getpid matches libc");
    check(syscall(SYS_gettid) > 0, "gettid returns a task ID");
    check(syscall(SYS_getppid) == getppid(), "getppid matches libc");
    check(syscall(SYS_getuid) == (long)getuid(), "getuid matches libc");
    check(syscall(SYS_geteuid) == (long)geteuid(), "geteuid matches libc");
    check(syscall(SYS_getgid) == (long)getgid(), "getgid matches libc");
    check(syscall(SYS_getegid) == (long)getegid(), "getegid matches libc");
    check(syscall(SYS_getresuid, &ruid, &euid, &suid) == 0 &&
              ruid == (uint32_t)getuid() && euid == (uint32_t)geteuid(),
          "getresuid returns Linux credential tuple");
    check(syscall(SYS_getresgid, &rgid, &egid, &sgid) == 0 &&
              rgid == (uint32_t)getgid() && egid == (uint32_t)getegid(),
          "getresgid returns Linux credential tuple");
    errno = 0;
    check_fault(syscall(SYS_getresuid, 0, &euid, &suid),
                "getresuid rejects null output");
    errno = 0;
    check_fault(syscall(SYS_getresgid, &rgid, (void *)1, &sgid),
                "getresgid rejects invalid output");

#ifdef SYS_getpgrp
    check(syscall(SYS_getpgrp) == syscall(SYS_getpgid, 0),
          "getpgrp matches getpgid zero");
#endif
    check(syscall(SYS_getpgid, 0) >= 0, "getpgid returns current group");
    check(syscall(SYS_getsid, 0) >= 0, "getsid returns current session");
    errno = 0;
    check(syscall(SYS_getpgid, -1) == -1 && errno == ESRCH,
          "getpgid rejects negative pid");
    errno = 0;
    check(syscall(SYS_getsid, 1000000000) == -1 && errno == ESRCH,
          "getsid rejects missing pid");

    previous_umask = (mode_t)syscall(SYS_umask, 027);
    check((mode_t)syscall(SYS_umask, previous_umask) == 027,
          "umask returns previous value and restores state");

    memset(&uts, 0, sizeof(uts));
    check(syscall(SYS_uname, &uts) == 0 && uts.sysname[0] &&
              uts.release[0] && uts.machine[0],
          "uname returns complete fields");
    check(strcmp(uts.sysname, "Linux") == 0,
          "uname reports the Linux ABI system name");
    check(uts.version[0] != 0,
          "uname reports a nonempty build version");
    errno = 0;
    check_fault(syscall(SYS_uname, (void *)1), "uname rejects invalid output");

#if defined(SYS_sethostname) && defined(SYS_setdomainname)
    if (geteuid() == 0) {
        struct utsname original_uts;
        struct utsname changed_uts;
        const char host[] = "edge-smoke";
        const char domain[] = "smoke.local";
        check(syscall(SYS_uname, &original_uts) == 0,
              "save UTS names before mutation");
        check(syscall(SYS_sethostname, host, sizeof(host) - 1u) == 0 &&
                  syscall(SYS_uname, &changed_uts) == 0 &&
                  strcmp(changed_uts.nodename, host) == 0,
              "sethostname updates current UTS namespace");
        errno = 0;
        check_fault(syscall(SYS_sethostname, (void *)1, 1),
                    "sethostname rejects invalid input");
        errno = 0;
        check(syscall(SYS_sethostname, host, 65) == -1 && errno == EINVAL,
              "sethostname rejects oversized name");
        check(syscall(SYS_sethostname, 0, 0) == 0,
              "sethostname accepts empty null input");
        check(syscall(SYS_uname, &changed_uts) == 0 &&
                  changed_uts.nodename[0] == 0,
              "uname preserves an empty hostname");
        check(syscall(SYS_sethostname, original_uts.nodename,
                      strlen(original_uts.nodename)) == 0,
              "restore original hostname");

        check(syscall(SYS_setdomainname, domain, sizeof(domain) - 1u) == 0 &&
                  syscall(SYS_uname, &changed_uts) == 0 &&
                  strcmp(changed_uts.domainname, domain) == 0,
              "setdomainname updates current UTS namespace");
        errno = 0;
        check_fault(syscall(SYS_setdomainname, (void *)1, 1),
                    "setdomainname rejects invalid input");
        check(syscall(SYS_setdomainname, 0, 0) == 0,
              "setdomainname accepts empty null input");
        check(syscall(SYS_uname, &changed_uts) == 0 &&
                  changed_uts.domainname[0] == 0,
              "uname preserves an empty domain name");
        check(syscall(SYS_setdomainname, original_uts.domainname,
                      strlen(original_uts.domainname)) == 0,
              "restore original domain name");
    }
#endif

    check(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &timestamp) == 0 &&
              timestamp.tv_nsec >= 0 && timestamp.tv_nsec < 1000000000L,
          "clock_gettime monotonic structure");
    check(syscall(SYS_clock_getres, CLOCK_MONOTONIC, &timestamp) == 0 &&
              timestamp.tv_sec == 0 && timestamp.tv_nsec > 0,
          "clock_getres structure");
    check(syscall(SYS_clock_getres, CLOCK_MONOTONIC, 0) == 0,
          "clock_getres accepts null output");
    errno = 0;
    check_fault(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, (void *)1),
                "clock_gettime rejects invalid output");
    errno = 0;
    check(syscall(SYS_clock_gettime, -1, &timestamp) == -1 && errno == EINVAL,
          "clock_gettime rejects invalid clock");

    memset(&timeval, 0, sizeof(timeval));
    timezone.tz_minuteswest = 1;
    timezone.tz_dsttime = 1;
    check(syscall(SYS_gettimeofday, &timeval, &timezone) == 0 &&
              timeval.tv_sec > 0 && timezone.tz_minuteswest == 0 &&
              timezone.tz_dsttime == 0,
          "gettimeofday copies time and zero timezone");

#ifdef SYS_time
    seconds = 0;
    check(syscall(SYS_time, &seconds) == seconds && seconds > 0,
          "time returns and copies identical seconds");
#else
    seconds = timeval.tv_sec;
#endif
    (void)seconds;

    memset(random_bytes, 0, sizeof(random_bytes));
    check(syscall(SYS_getrandom, random_bytes, sizeof(random_bytes), 0) ==
              (long)sizeof(random_bytes),
          "getrandom fills requested bytes");
    errno = 0;
    check(syscall(SYS_getrandom, random_bytes, sizeof(random_bytes), 8) == -1 &&
              errno == EINVAL,
          "getrandom rejects unknown flags");
    errno = 0;
    check_fault(syscall(SYS_getrandom, (void *)1, 1, 0),
                "getrandom rejects invalid output");

#ifdef SYS_getcpu
    check(syscall(SYS_getcpu, &cpu, &node, 0) == 0 &&
              cpu != UINT32_MAX && node != UINT32_MAX,
          "getcpu returns the current topology");
#endif
    check(syscall(SYS_sched_get_priority_max, SCHED_FIFO) == 99,
          "FIFO maximum priority");
    check(syscall(SYS_sched_get_priority_min, SCHED_FIFO) == 1,
          "FIFO minimum priority");
    check(syscall(SYS_sched_get_priority_min, SCHED_OTHER) == 0,
          "normal minimum priority");

    printf("SHARED_SYSCALL_SMOKE_%s failures=%d\n",
           failures ? "FAILED" : "OK", failures);
    return failures ? 1 : 0;
}
