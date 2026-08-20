/* SPDX-License-Identifier: MPL-2.0 */
/* Linux FUTEX_WAIT_REQUEUE_PI and FUTEX_CMP_REQUEUE_PI runtime probe. */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_TID_MASK 0x3fffffffU

static _Atomic uint32_t condition_word;
static _Atomic uint32_t mutex_word;
static _Atomic int waiter_ready;
static _Atomic int waiter_failures;

static long futex_call(_Atomic uint32_t *first, int operation,
                       uint32_t value, const struct timespec *timeout,
                       _Atomic uint32_t *second, uint32_t third) {
    long result = syscall(SYS_futex, first, operation, value, timeout,
                          second, third);
    return result < 0 ? -errno : result;
}

static void *waiter_main(void *argument) {
    uint32_t tid = (uint32_t)syscall(SYS_gettid);
    long result;
    (void)argument;

    atomic_store_explicit(&waiter_ready, 1, memory_order_release);
    result = futex_call(
        &condition_word, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
        0, 0, &mutex_word, 0);
    if (result != 0 ||
        (atomic_load_explicit(&mutex_word, memory_order_acquire) &
         FUTEX_TID_MASK) != tid)
        atomic_fetch_add_explicit(
            &waiter_failures, 1, memory_order_relaxed);
    if (result == 0 && futex_call(
            &mutex_word, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG,
            0, 0, 0, 0) != 0)
        atomic_fetch_add_explicit(
            &waiter_failures, 1, memory_order_relaxed);
    return 0;
}

int main(void) {
    const struct timespec delay = { .tv_sec = 0, .tv_nsec = 1000000 };
    pthread_t waiter;
    long result = 0;

    if (pthread_create(&waiter, 0, waiter_main, 0) != 0) return 1;
    while (!atomic_load_explicit(&waiter_ready, memory_order_acquire))
        sched_yield();
    for (unsigned int attempt = 0; attempt < 1000u; ++attempt) {
        result = futex_call(
            &condition_word,
            FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
            1, (const struct timespec *)(uintptr_t)0,
            &mutex_word, 0);
        if (result == 1) break;
        if (result < 0) break;
        nanosleep(&delay, 0);
    }
    if (result != 1) {
        fprintf(stderr, "CMP_REQUEUE_PI returned %ld\n", result);
        return 1;
    }
    if (pthread_join(waiter, 0) != 0 ||
        atomic_load_explicit(&waiter_failures, memory_order_relaxed) != 0 ||
        atomic_load_explicit(&mutex_word, memory_order_relaxed) != 0) {
        fputs("futex PI requeue state mismatch\n", stderr);
        return 1;
    }
    puts("futex-pi-requeue-abi: PASS");
    return 0;
}
