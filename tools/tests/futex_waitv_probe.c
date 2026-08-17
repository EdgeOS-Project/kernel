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

#ifndef SYS_futex
#define SYS_futex 202
#endif

#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif

#ifndef FUTEX_WAKE
#define FUTEX_WAKE 1
#endif

#ifndef FUTEX_32
#define FUTEX_32 2
#endif

#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#define RETRY_LIMIT 100000

struct edge_test_futex_waitv {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t reserved;
};

struct waitv_waker_context {
    volatile int *word;
    long wake_result;
};

static void *waitv_waker(void *opaque) {
    struct waitv_waker_context *context = opaque;
    long rc = 0;
    for (int attempt = 0; attempt < RETRY_LIMIT && rc == 0; ++attempt) {
        rc = syscall(SYS_futex, context->word, FUTEX_WAKE_PRIVATE,
                     1, 0, 0, 0);
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

static int test_waitv_mismatch(void) {
    volatile int word = 7;
    struct edge_test_futex_waitv w;
    long rc;

    memset(&w, 0, sizeof(w));
    w.val = 0;
    w.uaddr = (uint64_t)(uintptr_t)&word;
    w.flags = FUTEX_32;
    rc = syscall(SYS_futex_waitv, &w, 1, 0, 0, CLOCK_MONOTONIC);
    printf("waitv_mismatch_rc:%ld errno:%d\n", rc, errno);
    return !(rc == -1 && errno == EAGAIN);
}

static int test_waitv_timeout(void) {
    volatile int word = 0;
    struct edge_test_futex_waitv w;
    struct timespec ts;
    long rc;

    memset(&w, 0, sizeof(w));
    w.val = 0;
    w.uaddr = (uint64_t)(uintptr_t)&word;
    w.flags = FUTEX_32;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) return 1;
    add_ms_abs(&ts, 10);
    rc = syscall(SYS_futex_waitv, &w, 1, 0, &ts, CLOCK_MONOTONIC);
    printf("waitv_timeout_rc:%ld errno:%d\n", rc, errno);
    return !(rc == -1 && errno == ETIMEDOUT);
}

static int test_waitv_wake_index(void) {
    volatile int a = 0;
    volatile int b = 0;
    struct edge_test_futex_waitv w[2];
    struct waitv_waker_context context;
    pthread_t waker;
    long rc;

    memset(w, 0, sizeof(w));
    w[0].val = 0;
    w[0].uaddr = (uint64_t)(uintptr_t)&a;
    w[0].flags = FUTEX_32 | FUTEX_PRIVATE_FLAG;
    w[1].val = 0;
    w[1].uaddr = (uint64_t)(uintptr_t)&b;
    w[1].flags = FUTEX_32 | FUTEX_PRIVATE_FLAG;

    context.word = &b;
    context.wake_result = 0;
    if (pthread_create(&waker, 0, waitv_waker, &context) != 0) {
        printf("waitv_pthread_create_errno:%d\n", errno);
        return 1;
    }

    errno = 0;
    rc = syscall(SYS_futex_waitv, w, 2, 0, 0, CLOCK_MONOTONIC);
    printf("waitv_wake_index_rc:%ld errno:%d\n", rc, errno);
    if (pthread_join(waker, 0) != 0) return 1;
    printf("waitv_waker_result:%ld\n", context.wake_result);
    return !(rc == 1 && context.wake_result == 1);
}

int main(void) {
    int failed = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    failed |= test_waitv_mismatch();
    failed |= test_waitv_timeout();
    failed |= test_waitv_wake_index();
    printf("FUTEX_WAITV_PROBE_%s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
