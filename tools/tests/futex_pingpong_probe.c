/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Exercise the private-futex wakeup path used by pthread condition variables,
 * GLib worker pools, and desktop image loaders.  A correct kernel must not
 * lose a wakeup, and a native VM should complete this bounded exchange without
 * timer-quantum-sized delays between every handoff.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define EXCHANGES 2000
#define FUTEX_WAIT_PRIVATE (0 | 128)
#define FUTEX_WAKE_PRIVATE (1 | 128)

static _Atomic int turn;

static int futex_wait_private(_Atomic int *address, int expected)
{
    int rc = (int)syscall(SYS_futex, address, FUTEX_WAIT_PRIVATE, expected,
                          NULL, NULL, 0);
    if (rc == -1 && errno != EAGAIN && errno != EINTR)
        return -errno;
    return 0;
}

static int futex_wake_private(_Atomic int *address)
{
    int rc = (int)syscall(SYS_futex, address, FUTEX_WAKE_PRIVATE, 1,
                          NULL, NULL, 0);
    return rc < 0 ? -errno : rc;
}

static int wait_for_turn(int expected)
{
    for (;;) {
        int observed = atomic_load_explicit(&turn, memory_order_acquire);
        int rc;

        if (observed == expected)
            return 0;
        rc = futex_wait_private(&turn, observed);
        if (rc < 0)
            return rc;
    }
}

static void *worker_main(void *unused)
{
    int i;

    (void)unused;
    for (i = 0; i < EXCHANGES; ++i) {
        if (wait_for_turn(1) < 0)
            return (void *)(uintptr_t)1;
        atomic_store_explicit(&turn, 0, memory_order_release);
        if (futex_wake_private(&turn) < 0)
            return (void *)(uintptr_t)2;
    }
    return NULL;
}

static uint64_t monotonic_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
}

int main(void)
{
    pthread_t worker;
    void *worker_result = NULL;
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t syscall_start_ns;
    uint64_t syscall_end_ns;
    long pid_accumulator = 0;
    int i;

    atomic_init(&turn, 0);
    syscall_start_ns = monotonic_ns();
    for (i = 0; i < EXCHANGES; ++i)
        pid_accumulator += syscall(SYS_getpid);
    syscall_end_ns = monotonic_ns();
    if (pid_accumulator <= 0 || syscall_end_ns <= syscall_start_ns) {
        fprintf(stderr, "getpid syscall baseline failed\n");
        return 1;
    }

    if (pthread_create(&worker, NULL, worker_main, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    start_ns = monotonic_ns();
    for (i = 0; i < EXCHANGES; ++i) {
        atomic_store_explicit(&turn, 1, memory_order_release);
        if (futex_wake_private(&turn) < 0 || wait_for_turn(0) < 0) {
            fprintf(stderr, "futex exchange failed at iteration %d\n", i);
            return 1;
        }
    }
    end_ns = monotonic_ns();

    if (pthread_join(worker, &worker_result) != 0 || worker_result != NULL) {
        fprintf(stderr, "worker failed: %lu\n",
                (unsigned long)(uintptr_t)worker_result);
        return 1;
    }
    if (end_ns <= start_ns) {
        fprintf(stderr, "monotonic clock did not advance\n");
        return 1;
    }

    printf("FUTEX_PINGPONG_PASS exchanges=%d getpid_us=%llu "
           "elapsed_us=%llu ns_per_handoff=%llu\n",
           EXCHANGES,
           (unsigned long long)((syscall_end_ns - syscall_start_ns) / 1000ull),
           (unsigned long long)((end_ns - start_ns) / 1000ull),
           (unsigned long long)((end_ns - start_ns) /
                                (2ull * EXCHANGES)));
    return 0;
}
