/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_futex_wake
#define SYS_futex_wake 454
#endif

#ifndef SYS_futex_wait
#define SYS_futex_wait 455
#endif

#ifndef SYS_futex_requeue
#define SYS_futex_requeue 456
#endif

#ifndef FUTEX_32
#define FUTEX_32 2
#endif

#define FUTEX_PRIVATE_FLAG 128
#define RETRY_LIMIT 100000

struct futex_waitv_abi {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t reserved;
};

static volatile int futex_a = 0;
static volatile int futex_b = 0;
static _Atomic int waiter_ready;

static void *requeue_waiter(void *unused) {
    long rc;
    (void)unused;
    atomic_store_explicit(&waiter_ready, 1, memory_order_release);
    rc = syscall(SYS_futex_wait, &futex_a, 0, 0xfffffffful,
                 FUTEX_32 | FUTEX_PRIVATE_FLAG, 0, 1);
    return (void *)(uintptr_t)(rc == 0 ? 44 : 144);
}

static int test_requeue_empty(void) {
    struct futex_waitv_abi futexes[2] = {
        {0, (uint64_t)(uintptr_t)&futex_a,
         FUTEX_32 | FUTEX_PRIVATE_FLAG, 0},
        {0, (uint64_t)(uintptr_t)&futex_b,
         FUTEX_32 | FUTEX_PRIVATE_FLAG, 0},
    };
    long rc;

    errno = 0;
    rc = syscall(SYS_futex_requeue, futexes, 0, 0, 1);
    printf("requeue_empty_rc:%ld errno:%d\n", rc, errno);
    return rc != 0;
}

static int test_requeue_cmp_mismatch(void) {
    struct futex_waitv_abi futexes[2] = {
        {0, (uint64_t)(uintptr_t)&futex_a,
         FUTEX_32 | FUTEX_PRIVATE_FLAG, 0},
        {0, (uint64_t)(uintptr_t)&futex_b,
         FUTEX_32 | FUTEX_PRIVATE_FLAG, 0},
    };
    long rc;

    futex_a = 7;
    errno = 0;
    rc = syscall(SYS_futex_requeue, futexes, 0, 0, 1);
    printf("requeue_mismatch_rc:%ld errno:%d\n", rc, errno);
    futex_a = 0;
    return !(rc == -1 && errno == EAGAIN);
}

static int test_requeue_waiter(void) {
    struct futex_waitv_abi futexes[2] = {
        {0, (uint64_t)(uintptr_t)&futex_a,
         FUTEX_32 | FUTEX_PRIVATE_FLAG, 0},
        {0, (uint64_t)(uintptr_t)&futex_b,
         FUTEX_32 | FUTEX_PRIVATE_FLAG, 0},
    };
    pthread_t waiter;
    void *waiter_result = 0;
    long rc;

    futex_a = 0;
    futex_b = 0;
    atomic_store_explicit(&waiter_ready, 0, memory_order_relaxed);
    if (pthread_create(&waiter, 0, requeue_waiter, 0) != 0) {
        printf("requeue_pthread_create_errno:%d\n", errno);
        return 1;
    }
    while (!atomic_load_explicit(&waiter_ready, memory_order_acquire))
        sched_yield();
    rc = 0;
    for (int attempt = 0; attempt < RETRY_LIMIT && rc == 0; ++attempt) {
        errno = 0;
        rc = syscall(SYS_futex_requeue, futexes, 0, 0, 1);
        if (rc == 0) sched_yield();
    }
    printf("requeue_waiter_rc:%ld errno:%d\n", rc, errno);
    if (rc != 1) {
        (void)syscall(SYS_futex_wake, &futex_a, 0xfffffffful, 1,
                      FUTEX_32 | FUTEX_PRIVATE_FLAG);
        (void)pthread_join(waiter, &waiter_result);
        return 1;
    }

    errno = 0;
    rc = syscall(SYS_futex_wake, &futex_b, 0xfffffffful, 1,
                 FUTEX_32 | FUTEX_PRIVATE_FLAG);
    printf("requeue_wake_second_rc:%ld errno:%d\n", rc, errno);
    if (pthread_join(waiter, &waiter_result) != 0) return 1;
    printf("requeue_waiter_result:%lu\n",
           (unsigned long)(uintptr_t)waiter_result);
    return !(rc == 1 && (uintptr_t)waiter_result == 44);
}

int main(void) {
    int failed = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    failed |= test_requeue_empty();
    failed |= test_requeue_cmp_mismatch();
    failed |= test_requeue_waiter();
    printf("FUTEX_REQUEUE_PROBE_%s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
