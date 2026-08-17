/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_futex_wake
#define SYS_futex_wake 454
#endif

#ifndef SYS_futex_wait
#define SYS_futex_wait 455
#endif

#ifndef FUTEX_32
#define FUTEX_32 2
#endif

#define FUTEX_PRIVATE_FLAG 128
#define RETRY_LIMIT 100000

struct split_waker_context {
    volatile int *word;
    long wake_result;
};

static void *split_waker(void *opaque) {
    struct split_waker_context *context = opaque;
    long rc = 0;
    for (int attempt = 0; attempt < RETRY_LIMIT && rc == 0; ++attempt) {
        rc = syscall(SYS_futex_wake, context->word, 0xfffffffful, 1,
                     FUTEX_32 | FUTEX_PRIVATE_FLAG);
        if (rc == 0) sched_yield();
    }
    context->wake_result = rc;
    return 0;
}

static void add_ms_abs(struct timespec *ts, long ms) {
    ts->tv_nsec += (ms % 1000) * 1000000L;
    ts->tv_sec += ms / 1000;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_nsec -= 1000000000L;
        ts->tv_sec++;
    }
}

static int test_split_wake_empty(void) {
    volatile int word = 0;
    long rc;

    errno = 0;
    rc = syscall(SYS_futex_wake, &word, 0xfffffffful, 1, FUTEX_32);
    printf("split_wake_empty_rc:%ld errno:%d\n", rc, errno);
    return rc != 0;
}

static int test_split_wait_mismatch(void) {
    volatile int word = 7;
    long rc;

    errno = 0;
    rc = syscall(SYS_futex_wait, &word, 0, 0xfffffffful, FUTEX_32, 0, CLOCK_MONOTONIC);
    printf("split_wait_mismatch_rc:%ld errno:%d\n", rc, errno);
    return !(rc == -1 && errno == EAGAIN);
}

static int test_split_wait_timeout(void) {
    volatile int word = 0;
    struct timespec ts;
    long rc;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) return 1;
    add_ms_abs(&ts, 10);
    errno = 0;
    rc = syscall(SYS_futex_wait, &word, 0, 0xfffffffful, FUTEX_32, &ts, CLOCK_MONOTONIC);
    printf("split_wait_timeout_rc:%ld errno:%d\n", rc, errno);
    return !(rc == -1 && errno == ETIMEDOUT);
}

static int test_split_wait_wake(void) {
    volatile int word = 0;
    struct split_waker_context context;
    pthread_t waker;
    long rc;

    context.word = &word;
    context.wake_result = 0;
    if (pthread_create(&waker, 0, split_waker, &context) != 0) {
        printf("split_wait_pthread_create_errno:%d\n", errno);
        return 1;
    }

    errno = 0;
    rc = syscall(SYS_futex_wait, &word, 0, 0xfffffffful,
                 FUTEX_32 | FUTEX_PRIVATE_FLAG, 0, CLOCK_MONOTONIC);
    printf("split_wait_wake_rc:%ld errno:%d\n", rc, errno);
    if (pthread_join(waker, 0) != 0) return 1;
    printf("split_waker_result:%ld\n", context.wake_result);
    return !(rc == 0 && context.wake_result == 1);
}

int main(void) {
    int failed = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    failed |= test_split_wake_empty();
    failed |= test_split_wait_mismatch();
    failed |= test_split_wait_timeout();
    failed |= test_split_wait_wake();
    printf("FUTEX_SPLIT_PROBE_%s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
