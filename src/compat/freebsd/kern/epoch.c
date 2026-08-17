/* SPDX-License-Identifier: MPL-2.0 */

#include <sys/epoch.h>
#include <stdint.h>

#define BSD_EPOCH_POOL_SIZE 16u

struct epoch {
    volatile uint32_t readers;
    volatile uint32_t queue_lock;
    epoch_context_t pending_head;
    epoch_context_t pending_tail;
    uint8_t allocated;
};

static struct epoch g_epoch_pool[BSD_EPOCH_POOL_SIZE];
static struct epoch g_global_epoch;

epoch_t global_epoch = &g_global_epoch;
epoch_t global_epoch_preempt = &g_global_epoch;
epoch_t net_epoch_preempt = &g_global_epoch;

static void
epoch_lock(struct epoch *epoch)
{
    while (__atomic_exchange_n(&epoch->queue_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&epoch->queue_lock, __ATOMIC_RELAXED))
            __asm__ volatile("" ::: "memory");
    }
}

static void
epoch_unlock(struct epoch *epoch)
{
    __atomic_store_n(&epoch->queue_lock, 0u, __ATOMIC_RELEASE);
}

static void
epoch_try_drain(struct epoch *epoch)
{
    for (;;) {
        epoch_context_t first;

        if (!epoch ||
            __atomic_load_n(&epoch->readers, __ATOMIC_ACQUIRE) != 0)
            return;
        epoch_lock(epoch);
        if (__atomic_load_n(&epoch->readers, __ATOMIC_ACQUIRE) != 0) {
            epoch_unlock(epoch);
            return;
        }
        first = epoch->pending_head;
        epoch->pending_head = 0;
        epoch->pending_tail = 0;
        epoch_unlock(epoch);

        if (!first)
            return;

        while (first) {
            epoch_context_t next = (epoch_context_t)first->data[1];
            epoch_callback_t *callback =
                (epoch_callback_t *)(uintptr_t)first->data[0];
            first->data[0] = 0;
            first->data[1] = 0;
            if (callback)
                callback(first);
            first = next;
        }
    }
}

epoch_t
epoch_alloc(const char *name, int flags)
{
    (void)name;
    (void)flags;
    for (uint32_t index = 0; index < BSD_EPOCH_POOL_SIZE; ++index) {
        if (__sync_bool_compare_and_swap(
                &g_epoch_pool[index].allocated, 0, 1)) {
            __atomic_store_n(&g_epoch_pool[index].readers, 0,
                __ATOMIC_RELAXED);
            __atomic_store_n(&g_epoch_pool[index].queue_lock, 0,
                __ATOMIC_RELAXED);
            g_epoch_pool[index].pending_head = 0;
            g_epoch_pool[index].pending_tail = 0;
            return &g_epoch_pool[index];
        }
    }
    return 0;
}

void
epoch_free(epoch_t epoch)
{
    if (!epoch || epoch == global_epoch)
        return;
    epoch_wait(epoch);
    epoch_drain_callbacks(epoch);
    __atomic_store_n(&epoch->allocated, 0, __ATOMIC_RELEASE);
}

void
epoch_wait(epoch_t epoch)
{
    if (!epoch)
        return;
    while (__atomic_load_n(&epoch->readers, __ATOMIC_ACQUIRE) != 0)
        __asm__ volatile("" ::: "memory");
    epoch_try_drain(epoch);
}

void
epoch_wait_preempt(epoch_t epoch)
{
    epoch_wait(epoch);
}

void
epoch_drain_callbacks(epoch_t epoch)
{
    epoch_wait(epoch);
}

void
epoch_call(epoch_t epoch, epoch_callback_t callback,
    epoch_context_t context)
{
    if (!epoch || !callback || !context)
        return;
    context->data[0] = (void *)(uintptr_t)callback;
    context->data[1] = 0;
    epoch_lock(epoch);
    if (epoch->pending_tail)
        epoch->pending_tail->data[1] = context;
    else
        epoch->pending_head = context;
    epoch->pending_tail = context;
    epoch_unlock(epoch);
    epoch_try_drain(epoch);
}

int
in_epoch(epoch_t epoch)
{
    return epoch &&
        __atomic_load_n(&epoch->readers, __ATOMIC_ACQUIRE) != 0;
}

int
in_epoch_verbose(epoch_t epoch, int dump_on_failure)
{
    (void)dump_on_failure;
    return in_epoch(epoch);
}

void
_epoch_enter_preempt(epoch_t epoch, epoch_tracker_t tracker)
{
    if (!epoch || !tracker)
        return;
    __atomic_add_fetch(&epoch->readers, 1u, __ATOMIC_ACQUIRE);
    tracker->active = 1;
}

void
_epoch_exit_preempt(epoch_t epoch, epoch_tracker_t tracker)
{
    if (!epoch || !tracker || !tracker->active)
        return;
    tracker->active = 0;
    if (__atomic_sub_fetch(&epoch->readers, 1u, __ATOMIC_RELEASE) == 0)
        epoch_try_drain(epoch);
}

void
epoch_enter(epoch_t epoch)
{
    if (epoch)
        __atomic_add_fetch(&epoch->readers, 1u, __ATOMIC_ACQUIRE);
}

void
epoch_exit(epoch_t epoch)
{
    if (epoch &&
        __atomic_sub_fetch(&epoch->readers, 1u, __ATOMIC_RELEASE) == 0)
        epoch_try_drain(epoch);
}
