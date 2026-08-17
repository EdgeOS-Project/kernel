/*
 * EdgeOS original code, licensed under MPL-2.0.
 *
 * Verify Linux clone TID-store semantics and the musl pthread ordering that
 * depends on them.  CLONE_CHILD_CLEARTID must not write child_tid at clone
 * time unless CLONE_CHILD_SETTID is also present.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CLONE_STACK_SIZE (128u * 1024u)
#define CHILD_TID_SENTINEL 0x13579bdf
#define NESTED_THREAD_ROUNDS 128

struct clone_child_args {
    int report_fd;
    volatile int *child_tid;
};

#if !defined(__GLIBC__)
extern int __clone(int (*function)(void *), void *stack, int flags,
                   void *argument, int *parent_tid, void *tls,
                   int *child_tid);
#endif

static int clone_child_main(void *opaque) {
    struct clone_child_args *args = opaque;
    int observed = *args->child_tid;

    if (write(args->report_fd, &observed, sizeof(observed)) !=
        (ssize_t)sizeof(observed)) {
        return 10;
    }
    return 0;
}

static int check_clear_tid_has_no_creation_store(void) {
    struct clone_child_args args;
    volatile int child_tid = CHILD_TID_SENTINEL;
    unsigned char *stack;
    void *tls_base;
    int report[2];
    int observed = 0;
    int flags;
    pid_t child;

    if (pipe(report) < 0) return -1;
    stack = malloc(CLONE_STACK_SIZE);
    if (!stack) return -1;

    args.report_fd = report[1];
    args.child_tid = &child_tid;
    tls_base = __builtin_thread_pointer();
    flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
            CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
            CLONE_CHILD_CLEARTID;
#if defined(__GLIBC__)
    child = clone(clone_child_main, stack + CLONE_STACK_SIZE, flags, &args,
                  NULL, tls_base, (int *)&child_tid);
#else
    child = __clone(clone_child_main, stack + CLONE_STACK_SIZE, flags, &args,
                    NULL, tls_base, (int *)&child_tid);
#endif
    if (child < 0) {
        fprintf(stderr, "clone failed: %d\n", errno);
        return -1;
    }
    if (read(report[0], &observed, sizeof(observed)) !=
        (ssize_t)sizeof(observed)) {
        return -1;
    }
    for (int attempt = 0; child_tid != 0 && attempt < 10000; ++attempt)
        sched_yield();
    close(report[1]);
    close(report[0]);
    free(stack);
    return observed == CHILD_TID_SENTINEL && child_tid == 0 ? 0 : -1;
}

static void *nested_thread_main(void *opaque) {
    volatile int *completed = opaque;
    __atomic_add_fetch(completed, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static void *parent_thread_main(void *opaque) {
    volatile int *completed = opaque;
    pthread_t nested;

    if (pthread_create(&nested, NULL, nested_thread_main, opaque) != 0)
        return (void *)(uintptr_t)1;
    if (pthread_join(nested, NULL) != 0)
        return (void *)(uintptr_t)2;
    __atomic_add_fetch(completed, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static int check_nested_pthread_publication(void) {
    volatile int completed = 0;

    for (int round = 0; round < NESTED_THREAD_ROUNDS; ++round) {
        pthread_t parent;
        void *result = NULL;

        if (pthread_create(&parent, NULL, parent_thread_main,
                           (void *)&completed) != 0) {
            return -1;
        }
        if (pthread_join(parent, &result) != 0 || result != NULL)
            return -1;
    }
    return completed == NESTED_THREAD_ROUNDS * 2 ? 0 : -1;
}

int main(void) {
    if (check_clear_tid_has_no_creation_store() < 0) {
        fputs("CLONE_CHILD_CLEARTID performed an illegal creation-time store\n",
              stderr);
        return 1;
    }
    if (check_nested_pthread_publication() < 0) {
        fputs("nested pthread publication failed\n", stderr);
        return 2;
    }
    puts("CLONE_TID_SEMANTICS_PROBE_PASS");
    return 0;
}
