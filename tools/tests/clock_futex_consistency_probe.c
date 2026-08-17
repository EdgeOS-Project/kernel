/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux time and futex ABI regression test. */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static uint64_t timespec_to_ns(const struct timespec *value)
{
    return (uint64_t)value->tv_sec * 1000000000ull +
           (uint64_t)value->tv_nsec;
}

int main(void)
{
    struct timespec before;
    struct timespec expired = {2, 0};
    struct timespec deadline;
    struct timespec after;
    char uptime[128] = {0};
    int futex_word = 0;
    FILE *stream;
    long result;
    uint64_t expired_elapsed_ns;
    uint64_t elapsed_ns;

    if (clock_gettime(CLOCK_MONOTONIC, &before) != 0) {
        printf("CLOCK_FUTEX_CONSISTENCY_FAIL clock_gettime_before=%d\n", errno);
        return 1;
    }

    stream = fopen("/proc/uptime", "r");
    if (!stream || !fgets(uptime, sizeof(uptime), stream)) {
        printf("CLOCK_FUTEX_CONSISTENCY_FAIL proc_uptime=%d\n", errno);
        if (stream) fclose(stream);
        return 1;
    }
    fclose(stream);
    uptime[strcspn(uptime, "\r\n")] = 0;

    errno = 0;
    result = syscall(SYS_futex, &futex_word,
                     FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
                     0, &expired, NULL, FUTEX_BITSET_MATCH_ANY);
    if (clock_gettime(CLOCK_MONOTONIC, &after) != 0) {
        printf("CLOCK_FUTEX_CONSISTENCY_FAIL clock_gettime_expired=%d\n", errno);
        return 1;
    }
    expired_elapsed_ns = timespec_to_ns(&after) - timespec_to_ns(&before);
    if (result != -1 || errno != ETIMEDOUT ||
        expired_elapsed_ns > 100000000ull) {
        printf("CLOCK_FUTEX_CONSISTENCY_FAIL expired_result=%ld "
               "expired_errno=%d expired_elapsed_ns=%llu\n",
               result, errno, (unsigned long long)expired_elapsed_ns);
        return 1;
    }

    before = after;

    deadline = before;
    deadline.tv_nsec += 100000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    errno = 0;
    result = syscall(SYS_futex, &futex_word,
                     FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
                     0, &deadline, NULL, FUTEX_BITSET_MATCH_ANY);
    if (clock_gettime(CLOCK_MONOTONIC, &after) != 0) {
        printf("CLOCK_FUTEX_CONSISTENCY_FAIL clock_gettime_after=%d\n", errno);
        return 1;
    }

    elapsed_ns = timespec_to_ns(&after) - timespec_to_ns(&before);
    printf("clock_before=%lld.%09ld clock_after=%lld.%09ld "
           "proc_uptime=%s expired_elapsed_ns=%llu "
           "futex_result=%ld futex_errno=%d elapsed_ns=%llu\n",
           (long long)before.tv_sec, before.tv_nsec,
           (long long)after.tv_sec, after.tv_nsec, uptime,
           (unsigned long long)expired_elapsed_ns,
           result, errno, (unsigned long long)elapsed_ns);

    if (result != -1 || errno != ETIMEDOUT ||
        elapsed_ns < 50000000ull || elapsed_ns > 1000000000ull) {
        puts("CLOCK_FUTEX_CONSISTENCY_FAIL");
        return 1;
    }

    puts("CLOCK_FUTEX_CONSISTENCY_PASS");
    return 0;
}
