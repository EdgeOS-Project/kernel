/*
 * Original EdgeOS code, licensed under MPL-2.0.
 *
 * Exercise architecture-independent Linux prctl state, inheritance, pointer
 * errors, and argument validation.  Parent-death delivery has a separate
 * process-lifecycle probe.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_THP_DISABLE
#define PR_SET_THP_DISABLE 41
#endif
#ifndef PR_GET_THP_DISABLE
#define PR_GET_THP_DISABLE 42
#endif
#ifndef PR_THP_DISABLE_EXCEPT_ADVISED
#define PR_THP_DISABLE_EXCEPT_ADVISED (1 << 1)
#endif
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif
#ifndef CAP_CHECKPOINT_RESTORE
#define CAP_CHECKPOINT_RESTORE 40
#endif

static int failure_count;

static void expect_result(const char *name, long actual, long expected) {
    if (actual == expected) {
        printf("ok %-28s %ld\n", name, actual);
        return;
    }
    fprintf(stderr, "FAIL %-26s actual=%ld expected=%ld errno=%d\n",
            name, actual, expected, errno);
    ++failure_count;
}

static void expect_errno(const char *name, int result, int expected_errno) {
    int observed = errno;
    if (result == -1 && observed == expected_errno) {
        printf("ok %-28s errno=%d\n", name, observed);
        return;
    }
    fprintf(stderr,
            "FAIL %-26s result=%d errno=%d expected_result=-1 expected_errno=%d\n",
            name, result, observed, expected_errno);
    ++failure_count;
}

static void test_name(void) {
    static const char requested[] = "edge-prctl-name-is-truncated";
    char original[16];
    char observed[16];
    char expected[16];

    memset(original, 0, sizeof(original));
    memset(observed, 0, sizeof(observed));
    memset(expected, 0, sizeof(expected));
    expect_result("get original name", prctl(PR_GET_NAME, original), 0);
    memcpy(expected, requested, sizeof(expected) - 1u);
    expect_result("set truncated name", prctl(PR_SET_NAME, requested), 0);
    expect_result("get truncated name", prctl(PR_GET_NAME, observed), 0);
    if (memcmp(observed, expected, sizeof(observed)) != 0) {
        fprintf(stderr, "FAIL name bytes observed='%s' expected='%s'\n",
                observed, expected);
        ++failure_count;
    } else {
        printf("ok %-28s %s\n", "name bytes", observed);
    }

    errno = 0;
    expect_errno("get name null", prctl(PR_GET_NAME, 0), EFAULT);
    errno = 0;
    expect_errno("set name bad pointer",
                 prctl(PR_SET_NAME, (const char *)(uintptr_t)1u), EFAULT);
    expect_result("restore name", prctl(PR_SET_NAME, original), 0);
}

static void test_dumpable(void) {
    int original = prctl(PR_GET_DUMPABLE);
    expect_result("dumpable readable", original < 0 ? -1 : 0, 0);
    if (original < 0) return;
    expect_result("set dumpable zero", prctl(PR_SET_DUMPABLE, 0), 0);
    expect_result("get dumpable zero", prctl(PR_GET_DUMPABLE), 0);
    errno = 0;
    expect_errno("reject dumpable two", prctl(PR_SET_DUMPABLE, 2), EINVAL);
    expect_result("restore dumpable", prctl(PR_SET_DUMPABLE, original), 0);
}

static void test_timer_slack(void) {
    const unsigned long requested = 1234567ul;
    long original = prctl(PR_GET_TIMERSLACK);
    int status = 0;
    pid_t child;

    expect_result("timer slack positive", original > 0 ? 1 : 0, 1);
    if (original <= 0) return;
    expect_result("set timer slack", prctl(PR_SET_TIMERSLACK, requested), 0);
    expect_result("get timer slack", prctl(PR_GET_TIMERSLACK),
                  (long)requested);
    child = fork();
    if (child < 0) {
        perror("fork timer slack");
        ++failure_count;
    } else if (child == 0) {
        if (prctl(PR_GET_TIMERSLACK) != (long)requested) _exit(71);
        if (prctl(PR_SET_TIMERSLACK, 0ul) < 0) _exit(72);
        _exit(prctl(PR_GET_TIMERSLACK) == (long)requested ? 0 : 73);
    } else if (waitpid(child, &status, 0) != child ||
               !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL timer slack fork inheritance status=0x%x\n",
                status);
        ++failure_count;
    } else {
        puts("ok timer slack fork inheritance");
    }
    expect_result("reset timer slack", prctl(PR_SET_TIMERSLACK, 0ul), 0);
    expect_result("timer slack default", prctl(PR_GET_TIMERSLACK), original);
}

static void test_thp_disable(void) {
    int original = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    expect_result("THP state readable", original < 0 ? -1 : 0, 0);
    if (original < 0) return;
    expect_result("set THP disable",
                  prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0), 0);
    expect_result("get THP disabled",
                  prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0), 1);
    errno = 0;
    if (prctl(PR_SET_THP_DISABLE, 1, PR_THP_DISABLE_EXCEPT_ADVISED,
              0, 0) == 0) {
        expect_result("get THP except advised",
                      prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0), 3);
    } else if (errno == EINVAL) {
        puts("skip THP except advised: host kernel does not expose it");
    } else {
        fprintf(stderr, "FAIL set THP except advised errno=%d\n", errno);
        ++failure_count;
    }
    errno = 0;
    expect_errno("reject THP flags",
                 prctl(PR_SET_THP_DISABLE, 1, 1, 0, 0), EINVAL);
    errno = 0;
    expect_errno("reject THP extra arg",
                 prctl(PR_GET_THP_DISABLE, 1, 0, 0, 0), EINVAL);
    expect_result("restore THP state",
                  prctl(PR_SET_THP_DISABLE, original != 0,
                        original == 3 ? PR_THP_DISABLE_EXCEPT_ADVISED : 0,
                        0, 0), 0);
}

static void test_miscellaneous(void) {
    int securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    int keepcaps = prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
    int seccomp_mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);

    expect_result("securebits readable", securebits < 0 ? -1 : 0, 0);
    if (securebits >= 0) {
        expect_result("get securebits ignores tail",
                      prctl(PR_GET_SECUREBITS, 0x6ul,
                            0x40400010ul, 0x40400ul, 0x70ul), securebits);
        expect_result("set securebits ignores tail",
                      prctl(PR_SET_SECUREBITS, securebits,
                            0x40400010ul, 0x40400ul, 0x70ul), 0);
        expect_result("securebits unchanged",
                      prctl(PR_GET_SECUREBITS, 0, 0, 0, 0), securebits);
    }
    expect_result("keepcaps readable", keepcaps < 0 ? -1 : 0, 0);
    if (keepcaps >= 0) {
        expect_result("get keepcaps ignores tail",
                      prctl(PR_GET_KEEPCAPS, 0x6ul,
                            0x40400010ul, 0x40400ul, 0x70ul), keepcaps);
        expect_result("set keepcaps ignores tail",
                      prctl(PR_SET_KEEPCAPS, keepcaps,
                            0x40400010ul, 0x40400ul, 0x70ul), 0);
        expect_result("keepcaps unchanged",
                      prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0), keepcaps);
    }
    expect_result("seccomp mode valid",
                  seccomp_mode == 0 || seccomp_mode == 2 ? 1 : 0, 1);
    long cap_chown_bounded = prctl(PR_CAPBSET_READ, 0, 0, 0, 0);
    expect_result("cap bounding read valid",
                  cap_chown_bounded >= 0 ? 1 : 0, 1);
    if (cap_chown_bounded >= 0) {
        expect_result("cap read ignores tail",
                      prctl(PR_CAPBSET_READ, 0, 0x40400010ul,
                            0x40400ul, 0x70ul), cap_chown_bounded);
    }
    errno = 0;
    expect_errno("cap bounding invalid",
                 prctl(PR_CAPBSET_READ, 64, 0, 0, 0), EINVAL);
    if (prctl(PR_CAPBSET_READ, CAP_CHECKPOINT_RESTORE, 0, 0, 0) >= 0) {
        int status = 0;
        pid_t child = fork();
        if (child == 0) {
            _exit(prctl(PR_CAPBSET_DROP, CAP_CHECKPOINT_RESTORE,
                        0x40400010ul, 0x40400ul, 0x70ul) == 0 ? 0 : errno);
        }
        if (child < 0 || waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "FAIL cap drop ignores tail status=0x%x\n",
                    status);
            ++failure_count;
        } else {
            puts("ok cap drop ignores tail");
        }
    }
    errno = 0;
    expect_errno("invalid VMA range",
                 prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0ul, 4096ul,
                       "edge-vma"),
                 EINVAL);
    expect_result("set no new privileges",
                  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
    expect_result("get no new privileges",
                  prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), 1);
    errno = 0;
    expect_errno("reject no-new-privs args",
                 prctl(PR_GET_NO_NEW_PRIVS, 1, 0, 0, 0), EINVAL);
}

int main(void) {
    test_name();
    test_dumpable();
    test_timer_slack();
    test_thp_disable();
    test_miscellaneous();
    if (failure_count) {
        fprintf(stderr, "PRCTL_ABI_PROBE_FAIL failures=%d\n", failure_count);
        return 1;
    }
    puts("PRCTL_ABI_PROBE_PASS");
    return 0;
}
