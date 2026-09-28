/* SPDX-License-Identifier: MPL-2.0 */
#include <stddef.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fs/squashfs/upstream/cache.h"

#undef malloc
#undef calloc
#undef free

static sqfs_cache cache;
static void *held_entry;
static void *next_entry;
static unsigned contention_begins;
static unsigned fetch_done;
static unsigned notifications;

static void dispose_entry(void *entry) { (void)entry; }

static void *fetch_next(void *unused) {
    (void)unused;
    next_entry = sqfs_cache_get(&cache, 2u);
    __atomic_store_n(&fetch_done, 1u, __ATOMIC_RELEASE);
    return NULL;
}

void *edge_sqfs_alloc(size_t size) { return malloc(size); }
void *edge_sqfs_calloc(size_t count, size_t size) {
    return calloc(count, size);
}
void edge_sqfs_free(void *pointer) { free(pointer); }
uintptr_t kernel_current_context_token(void) { return 1u; }
int kernel_runtime_yield(void) { return 0; }
int kernel_runtime_wait_sequence(volatile uint64_t *sequence,
                                 uint64_t observed, uint64_t deadline) {
    (void)sequence;
    (void)observed;
    (void)deadline;
    return 0;
}
void kernel_runtime_notify_sequence(volatile uint64_t *sequence) {
    (void)sequence;
    ++notifications;
}
int kernel_runtime_contention_begin(void) {
    __atomic_add_fetch(&contention_begins, 1u, __ATOMIC_RELEASE);
    return 1;
}
void kernel_runtime_contention_end(int released) { (void)released; }
void kernel_runtime_contention_wait(volatile uint32_t *word,
                                    uint32_t observed) {
    (void)word;
    (void)observed;
    sched_yield();
}
void kernel_runtime_contention_notify(void) {}

int main(void) {
    pthread_t worker;

    alarm(3);
    if (sqfs_cache_init(&cache, sizeof(uint64_t), 1u,
                        dispose_entry) != SQFS_OK)
        return 1;
    held_entry = sqfs_cache_get(&cache, 1u);
    if (!held_entry) return 1;
    sqfs_cache_entry_mark_valid(&cache, held_entry);
    if (notifications != 0u) return 1;
    if (pthread_create(&worker, NULL, fetch_next, NULL) != 0)
        return 1;
    while (!__atomic_load_n(&contention_begins, __ATOMIC_ACQUIRE) &&
           !__atomic_load_n(&fetch_done, __ATOMIC_ACQUIRE))
        sched_yield();
    if (__atomic_load_n(&fetch_done, __ATOMIC_ACQUIRE)) {
        fprintf(stderr, "expected fallback wait once, observed %u\n",
                contention_begins);
        return 1;
    }
    sqfs_cache_put(&cache, held_entry);
    if (notifications == 0u) return 1;
    if (pthread_join(worker, NULL) != 0 || !next_entry ||
        sqfs_cache_entry_valid(&cache, next_entry))
        return 1;
    sqfs_cache_put(&cache, next_entry);
    sqfs_cache_destroy(&cache);

    alarm(0);
    puts("squashfs_cache_runtime_unit: PASS");
    return 0;
}
