/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>

static pthread_mutex_t robust_mutex;
static volatile int child_ready;

static void *owner_thread(void *arg) {
    int rc;
    (void)arg;

    rc = pthread_mutex_lock(&robust_mutex);
    if (rc != 0) {
        child_ready = -rc;
        return 0;
    }
    child_ready = 1;
    for (volatile unsigned long i = 0; i < 2000000UL; ++i) {
        __asm__ __volatile__("" ::: "memory");
    }
    return 0;
}

int main(void) {
    pthread_mutexattr_t attr;
    pthread_t thread;
    int rc;

    setvbuf(stdout, NULL, _IONBF, 0);
    rc = pthread_mutexattr_init(&attr);
    if (rc != 0) {
        printf("robust_attr_init_rc:%d\n", rc);
        return 1;
    }
    rc = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    if (rc != 0) {
        printf("robust_attr_setrobust_rc:%d\n", rc);
        return 1;
    }
    rc = pthread_mutex_init(&robust_mutex, &attr);
    if (rc != 0) {
        printf("robust_mutex_init_rc:%d\n", rc);
        return 1;
    }
    rc = pthread_create(&thread, 0, owner_thread, 0);
    if (rc != 0) {
        printf("robust_pthread_create_rc:%d\n", rc);
        return 1;
    }
    while (child_ready == 0) sched_yield();
    if (child_ready < 0) {
        printf("robust_child_lock_rc:%d\n", -child_ready);
        return 1;
    }

    rc = pthread_mutex_lock(&robust_mutex);
    printf("robust_parent_lock_rc:%d expected:%d\n", rc, EOWNERDEAD);
    if (rc != EOWNERDEAD) return 1;
    rc = pthread_mutex_consistent(&robust_mutex);
    printf("robust_consistent_rc:%d\n", rc);
    if (rc != 0) return 1;
    rc = pthread_mutex_unlock(&robust_mutex);
    printf("robust_unlock_rc:%d\n", rc);
    if (rc != 0) return 1;
    rc = pthread_join(thread, 0);
    printf("robust_join_rc:%d\n", rc);
    if (rc != 0) return 1;
    printf("ROBUST_FUTEX_PROBE_PASS\n");
    return 0;
}
