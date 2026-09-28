/* SPDX-License-Identifier: MPL-2.0 */
/* Shared hashed mutex pool for imported FreeBSD drivers. */

#include <stdint.h>

#include "compat/freebsd/sys/mutex.h"

#define BSD_MUTEX_POOL_SIZE 64u

struct mtx_pool {
    struct mtx locks[BSD_MUTEX_POOL_SIZE];
    volatile uint32_t state;
};

static struct mtx_pool g_sleep_pool;
struct mtx_pool *mtxpool_sleep = &g_sleep_pool;

static void
mutex_pool_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(_M_ARM64)
    __asm__ __volatile__("yield");
#endif
}

static void
mutex_pool_ensure_initialized(struct mtx_pool *pool)
{
    uint32_t expected = 0;

    if (__atomic_load_n(&pool->state, __ATOMIC_ACQUIRE) == 2)
        return;
    if (__atomic_compare_exchange_n(&pool->state, &expected, 1, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        for (uint32_t index = 0; index < BSD_MUTEX_POOL_SIZE; ++index)
            mtx_init(&pool->locks[index], "driver mutex pool", 0, MTX_DEF);
        __atomic_store_n(&pool->state, 2, __ATOMIC_RELEASE);
        return;
    }
    while (__atomic_load_n(&pool->state, __ATOMIC_ACQUIRE) != 2)
        mutex_pool_relax();
}

struct mtx *
mtx_pool_find(struct mtx_pool *pool, void *pointer)
{
    uintptr_t value = (uintptr_t)pointer;
    uint32_t index;

    if (!pool)
        pool = mtxpool_sleep;
    mutex_pool_ensure_initialized(pool);
    value ^= value >> 17;
    value *= UINT64_C(11400714819323198485);
    index = (uint32_t)(value >> 58) & (BSD_MUTEX_POOL_SIZE - 1u);
    return &pool->locks[index];
}
