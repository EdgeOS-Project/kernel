/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral Linux futex operation policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/futex_runtime.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"

static const kernel_futex_backend_ops_t *g_backend_ops;
static void *g_backend_context;

#define KERNEL_FUTEX_PI_MAX_WAITERS 256u
#define KERNEL_FUTEX_ASYNC_MAX_WAITERS 128u

typedef struct kernel_futex_pi_waiter {
    uint8_t used;
    uint8_t requeue_pending;
    kernel_futex_key_t key;
    kernel_futex_key_t requeue_key;
    uint64_t address;
    uint64_t requeue_address;
    int32_t tid;
    int32_t owner_tid;
    uint64_t sequence;
} kernel_futex_pi_waiter_t;

static kernel_futex_pi_waiter_t
    g_pi_waiters[KERNEL_FUTEX_PI_MAX_WAITERS];
static uint64_t g_pi_sequence;

typedef struct kernel_futex_async_waiter {
    uint8_t used;
    uint8_t ready;
    uint16_t waiter_count;
    int32_t result;
    uint64_t id;
    uint64_t sequence;
    kernel_futex_key_t keys[KERNEL_FUTEX_WAITV_MAX];
    uint32_t bitsets[KERNEL_FUTEX_WAITV_MAX];
} kernel_futex_async_waiter_t;

static kernel_futex_async_waiter_t
    g_async_waiters[KERNEL_FUTEX_ASYNC_MAX_WAITERS];
static uint64_t g_async_wait_id;
static uint64_t g_async_wait_sequence;

static int futex_resolve_key(uint64_t address, int private_futex,
                             kernel_futex_key_t *key);

int kernel_futex_backend_register(
    const kernel_futex_backend_ops_t *ops, void *context) {
    if (!ops || !ops->resolve_key || !ops->wait || !ops->wait_vector ||
        !ops->lock || !ops->unlock || !ops->read_word_locked ||
        !ops->compare_exchange_word_locked || !ops->wake_locked ||
        !ops->requeue_locked)
        return -EDGE_LINUX_EINVAL;
    g_backend_ops = ops;
    g_backend_context = context;
    for (uint32_t index = 0;
         index < KERNEL_FUTEX_ASYNC_MAX_WAITERS; ++index)
        g_async_waiters[index].used = 0u;
    return 0;
}

static int futex_key_equal(const kernel_futex_key_t *left,
                           const kernel_futex_key_t *right) {
    return left->value == right->value && left->scope == right->scope;
}

static int futex_async_match_locked(
        const kernel_futex_async_waiter_t *waiter,
        const kernel_futex_key_t *key, uint32_t bitset,
        uint16_t *waiter_index) {
    if (!waiter || !waiter->used || waiter->ready) return 0;
    for (uint16_t index = 0; index < waiter->waiter_count; ++index) {
        if (futex_key_equal(&waiter->keys[index], key) &&
            (waiter->bitsets[index] & bitset)) {
            if (waiter_index) *waiter_index = index;
            return 1;
        }
    }
    return 0;
}

static int futex_async_best_locked(const kernel_futex_key_t *key,
                                   uint32_t bitset,
                                   uint16_t *waiter_index) {
    int best = -1;
    uint16_t best_waiter = 0u;

    for (uint32_t index = 0;
         index < KERNEL_FUTEX_ASYNC_MAX_WAITERS; ++index) {
        uint16_t candidate_waiter;
        if (!futex_async_match_locked(
                &g_async_waiters[index], key, bitset,
                &candidate_waiter))
            continue;
        if (best < 0 || g_async_waiters[index].sequence <
                            g_async_waiters[best].sequence) {
            best = (int)index;
            best_waiter = candidate_waiter;
        }
    }
    if (best >= 0 && waiter_index) *waiter_index = best_waiter;
    return best;
}

static int futex_async_wake_locked(const kernel_futex_key_t *key,
                                   uint32_t maximum,
                                   uint32_t bitset) {
    uint32_t woken = 0u;

    while (woken < maximum) {
        uint16_t waiter_index;
        int best = futex_async_best_locked(
            key, bitset, &waiter_index);
        if (best < 0) break;
        g_async_waiters[best].ready = 1u;
        g_async_waiters[best].result =
            g_async_waiters[best].waiter_count == 1u ?
                0 : (int32_t)waiter_index;
        ++woken;
    }
    return (int)woken;
}

static int futex_wake_locked(const kernel_futex_key_t *key,
                             uint32_t maximum, uint32_t bitset) {
    int async_woken;
    int backend_woken;

    async_woken = futex_async_wake_locked(key, maximum, bitset);
    if ((uint32_t)async_woken == maximum) return async_woken;
    backend_woken = g_backend_ops->wake_locked(
        g_backend_context, key, maximum - (uint32_t)async_woken,
        bitset);
    return backend_woken < 0 ? backend_woken :
                              async_woken + backend_woken;
}

static int futex_async_requeue_locked(
        const kernel_futex_key_t *source,
        const kernel_futex_key_t *destination,
        uint32_t maximum, uint32_t bitset) {
    uint32_t moved = 0u;

    while (moved < maximum) {
        uint16_t waiter_index;
        int best = futex_async_best_locked(
            source, bitset, &waiter_index);
        if (best < 0) break;
        g_async_waiters[best].keys[waiter_index] = *destination;
        ++moved;
    }
    return (int)moved;
}

int kernel_futex_async_wait_add(const kernel_futex_request_t *request,
                                uint64_t *wait_id) {
    uintptr_t lock_state;
    uint16_t waiter_count;
    uint32_t slot;
    int status;

    if (!request || !wait_id || !g_backend_ops)
        return -EDGE_LINUX_EINVAL;
    if (request->operation == KERNEL_FUTEX_WAIT) {
        if (!request->bitset) return -EDGE_LINUX_EINVAL;
        waiter_count = 1u;
    } else if (request->operation == KERNEL_FUTEX_WAIT_VECTOR) {
        waiter_count = request->waiter_count;
        if (!waiter_count || waiter_count > KERNEL_FUTEX_WAITV_MAX)
            return -EDGE_LINUX_EINVAL;
    } else {
        return -EDGE_LINUX_EINVAL;
    }

    /* Reserve storage before resolving keys to keep this stack bounded. */
    lock_state = g_backend_ops->lock(g_backend_context);
    for (slot = 0; slot < KERNEL_FUTEX_ASYNC_MAX_WAITERS; ++slot)
        if (!g_async_waiters[slot].used) break;
    if (slot == KERNEL_FUTEX_ASYNC_MAX_WAITERS) {
        g_backend_ops->unlock(g_backend_context, lock_state);
        return -EDGE_LINUX_ENOMEM;
    }
    g_async_waiters[slot].used = 1u;
    g_async_waiters[slot].ready = 0u;
    g_async_waiters[slot].waiter_count = 0u;
    g_async_waiters[slot].id = 0u;
    g_backend_ops->unlock(g_backend_context, lock_state);

    for (uint16_t index = 0; index < waiter_count; ++index) {
        uint64_t address = request->operation == KERNEL_FUTEX_WAIT ?
            request->address : request->waiters[index].address;
        int private_futex = request->operation == KERNEL_FUTEX_WAIT ?
            request->private_futex :
            request->waiters[index].private_futex;

        status = futex_resolve_key(
            address, private_futex, &g_async_waiters[slot].keys[index]);
        if (status < 0) goto release_slot;
    }

    lock_state = g_backend_ops->lock(g_backend_context);
    for (uint16_t index = 0; index < waiter_count; ++index) {
        uint64_t address = request->operation == KERNEL_FUTEX_WAIT ?
            request->address : request->waiters[index].address;
        uint32_t expected = request->operation == KERNEL_FUTEX_WAIT ?
            request->expected_value :
            request->waiters[index].expected_value;
        uint32_t observed;

        status = g_backend_ops->read_word_locked(
            g_backend_context, address, &observed);
        if (status < 0) goto release_locked;
        if (observed != expected) {
            status = -EDGE_LINUX_EAGAIN;
            goto release_locked;
        }
    }

    g_async_waiters[slot].result = 0;
    ++g_async_wait_id;
    if (!g_async_wait_id) ++g_async_wait_id;
    ++g_async_wait_sequence;
    if (!g_async_wait_sequence) ++g_async_wait_sequence;
    g_async_waiters[slot].id = g_async_wait_id;
    g_async_waiters[slot].sequence = g_async_wait_sequence;
    for (uint16_t index = 0; index < waiter_count; ++index) {
        g_async_waiters[slot].bitsets[index] =
            request->operation == KERNEL_FUTEX_WAIT ?
                request->bitset : UINT32_MAX;
    }
    g_async_waiters[slot].waiter_count = waiter_count;
    *wait_id = g_async_wait_id;
    status = 0;
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;

release_locked:
    g_async_waiters[slot].used = 0u;
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;

release_slot:
    lock_state = g_backend_ops->lock(g_backend_context);
    g_async_waiters[slot].used = 0u;
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;
}

int kernel_futex_async_wait_poll(uint64_t wait_id, int32_t *result) {
    uintptr_t lock_state;
    int status = -EDGE_LINUX_ENOENT;

    if (!wait_id || !result || !g_backend_ops)
        return -EDGE_LINUX_EINVAL;
    lock_state = g_backend_ops->lock(g_backend_context);
    for (uint32_t index = 0;
         index < KERNEL_FUTEX_ASYNC_MAX_WAITERS; ++index) {
        kernel_futex_async_waiter_t *waiter = &g_async_waiters[index];
        if (!waiter->used || waiter->id != wait_id) continue;
        if (!waiter->ready) {
            status = 0;
        } else {
            *result = waiter->result;
            waiter->used = 0u;
            status = 1;
        }
        break;
    }
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;
}

int kernel_futex_async_wait_cancel(uint64_t wait_id) {
    uintptr_t lock_state;
    int status = -EDGE_LINUX_ENOENT;

    if (!wait_id || !g_backend_ops) return -EDGE_LINUX_EINVAL;
    lock_state = g_backend_ops->lock(g_backend_context);
    for (uint32_t index = 0;
         index < KERNEL_FUTEX_ASYNC_MAX_WAITERS; ++index) {
        kernel_futex_async_waiter_t *waiter = &g_async_waiters[index];
        if (!waiter->used || waiter->id != wait_id) continue;
        waiter->used = 0u;
        status = 0;
        break;
    }
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;
}

static int futex_pi_supported(void) {
    return g_backend_ops && g_backend_ops->current_tid &&
           g_backend_ops->waiter_precedes_locked &&
           g_backend_ops->prepare_pi_wait_locked &&
           g_backend_ops->block_pi_wait &&
           g_backend_ops->wake_tid_locked &&
           g_backend_ops->requeue_tid_locked &&
           g_backend_ops->waiter_active_locked &&
           g_backend_ops->task_exists_locked &&
           g_backend_ops->recompute_pi_owner_locked;
}

int kernel_futex_pi_requeue_waiter_locked(
        const kernel_futex_key_t *key, int32_t tid) {
    if (!key || tid <= 0) return 0;
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        kernel_futex_pi_waiter_t *waiter = &g_pi_waiters[index];
        if (waiter->used && waiter->requeue_pending &&
            waiter->tid == tid && futex_key_equal(&waiter->key, key))
            return 1;
    }
    return 0;
}

static int futex_pi_waiter_active_locked(
        const kernel_futex_pi_waiter_t *waiter) {
    return waiter && waiter->used &&
           g_backend_ops->waiter_active_locked(
               g_backend_context, &waiter->key, waiter->tid);
}

static int futex_pi_best_waiter_locked(const kernel_futex_key_t *key,
                                       int32_t owner_tid) {
    int best = -1;
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        kernel_futex_pi_waiter_t *waiter = &g_pi_waiters[index];
        if (!waiter->used || !futex_key_equal(&waiter->key, key))
            continue;
        if (!futex_pi_waiter_active_locked(waiter)) {
            waiter->used = 0u;
            continue;
        }
        waiter->owner_tid = owner_tid;
        if (best < 0 || g_backend_ops->waiter_precedes_locked(
                g_backend_context, waiter->tid,
                g_pi_waiters[best].tid) > 0 ||
            (g_backend_ops->waiter_precedes_locked(
                 g_backend_context, waiter->tid,
                 g_pi_waiters[best].tid) == 0 &&
             waiter->sequence < g_pi_waiters[best].sequence))
            best = (int)index;
    }
    return best;
}

static int32_t futex_pi_best_donor_locked(int32_t owner_tid) {
    int best = -1;
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        kernel_futex_pi_waiter_t *waiter = &g_pi_waiters[index];
        if (!waiter->used || waiter->owner_tid != owner_tid)
            continue;
        if (!futex_pi_waiter_active_locked(waiter)) {
            waiter->used = 0u;
            continue;
        }
        if (best < 0 || g_backend_ops->waiter_precedes_locked(
                g_backend_context, waiter->tid,
                g_pi_waiters[best].tid) > 0)
            best = (int)index;
    }
    return best < 0 ? 0 : g_pi_waiters[best].tid;
}

static void futex_pi_recompute_owner_locked(int32_t owner_tid) {
    if (owner_tid <= 0 || !futex_pi_supported()) return;
    g_backend_ops->recompute_pi_owner_locked(
        g_backend_context, owner_tid,
        futex_pi_best_donor_locked(owner_tid));
}

void kernel_futex_pi_waiter_cancel_locked(int32_t tid) {
    int32_t owners[KERNEL_FUTEX_PI_MAX_WAITERS];
    uint32_t owner_count = 0;
    if (tid <= 0 || !futex_pi_supported()) return;
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        kernel_futex_pi_waiter_t *waiter = &g_pi_waiters[index];
        int duplicate = 0;
        if (!waiter->used || waiter->tid != tid) continue;
        for (uint32_t owner = 0; owner < owner_count; ++owner)
            if (owners[owner] == waiter->owner_tid) duplicate = 1;
        if (!duplicate && waiter->owner_tid > 0)
            owners[owner_count++] = waiter->owner_tid;
        waiter->used = 0u;
    }
    for (uint32_t owner = 0; owner < owner_count; ++owner)
        futex_pi_recompute_owner_locked(owners[owner]);
}

static int futex_pi_waiter_allocate_locked(
        const kernel_futex_key_t *key, uint64_t address,
        int32_t tid, int32_t owner_tid) {
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        if (g_pi_waiters[index].used) continue;
        g_pi_waiters[index].used = 1u;
        g_pi_waiters[index].requeue_pending = 0u;
        g_pi_waiters[index].key = *key;
        g_pi_waiters[index].requeue_key.value = 0u;
        g_pi_waiters[index].requeue_key.scope = 0u;
        g_pi_waiters[index].address = address;
        g_pi_waiters[index].requeue_address = 0u;
        g_pi_waiters[index].tid = tid;
        g_pi_waiters[index].owner_tid = owner_tid;
        g_pi_waiters[index].sequence = ++g_pi_sequence;
        return (int)index;
    }
    return -EDGE_LINUX_ENOMEM;
}

static int futex_pi_best_requeue_waiter_locked(
        const kernel_futex_key_t *source,
        const kernel_futex_key_t *destination) {
    int best = -1;
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        kernel_futex_pi_waiter_t *waiter = &g_pi_waiters[index];
        if (!waiter->used || !waiter->requeue_pending ||
            !futex_key_equal(&waiter->key, source) ||
            !futex_key_equal(&waiter->requeue_key, destination))
            continue;
        if (!futex_pi_waiter_active_locked(waiter)) {
            waiter->used = 0u;
            continue;
        }
        if (best < 0 || g_backend_ops->waiter_precedes_locked(
                g_backend_context, waiter->tid,
                g_pi_waiters[best].tid) > 0 ||
            (g_backend_ops->waiter_precedes_locked(
                 g_backend_context, waiter->tid,
                 g_pi_waiters[best].tid) == 0 &&
             waiter->sequence < g_pi_waiters[best].sequence))
            best = (int)index;
    }
    return best;
}

static int futex_pi_has_other_requeue_waiter_locked(
        const kernel_futex_key_t *source,
        const kernel_futex_key_t *destination, int excluded) {
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        kernel_futex_pi_waiter_t *waiter = &g_pi_waiters[index];
        if ((int)index == excluded || !waiter->used ||
            !waiter->requeue_pending ||
            !futex_key_equal(&waiter->key, source) ||
            !futex_key_equal(&waiter->requeue_key, destination))
            continue;
        if (futex_pi_waiter_active_locked(waiter)) return 1;
        waiter->used = 0u;
    }
    return 0;
}

static int64_t futex_wait_requeue_pi(
        const kernel_futex_request_t *request) {
    kernel_futex_key_t source;
    kernel_futex_key_t destination;
    uintptr_t lock_state;
    uint32_t word;
    int32_t tid;
    int waiter_index;
    int status;

    if (!futex_pi_supported()) return -EDGE_LINUX_ENOSYS;
    tid = g_backend_ops->current_tid(g_backend_context);
    if (tid <= 0) return -EDGE_LINUX_ESRCH;
    status = futex_resolve_key(
        request->address, request->private_futex, &source);
    if (status < 0) return status;
    status = futex_resolve_key(
        request->secondary_address,
        request->secondary_private_futex, &destination);
    if (status < 0) return status;
    if (futex_key_equal(&source, &destination))
        return -EDGE_LINUX_EINVAL;

    lock_state = g_backend_ops->lock(g_backend_context);
    status = g_backend_ops->read_word_locked(
        g_backend_context, request->address, &word);
    if (status < 0) goto out;
    if (word != request->expected_value) {
        status = -EDGE_LINUX_EAGAIN;
        goto out;
    }
    waiter_index = futex_pi_waiter_allocate_locked(
        &source, request->address, tid, 0);
    if (waiter_index < 0) {
        status = waiter_index;
        goto out;
    }
    g_pi_waiters[waiter_index].requeue_pending = 1u;
    g_pi_waiters[waiter_index].requeue_key = destination;
    g_pi_waiters[waiter_index].requeue_address =
        request->secondary_address;
    status = g_backend_ops->prepare_pi_wait_locked(
        g_backend_context, request, &source);
    if (status < 0) {
        g_pi_waiters[waiter_index].used = 0u;
        goto out;
    }
    g_backend_ops->unlock(g_backend_context, lock_state);
    status = (int)g_backend_ops->block_pi_wait(
        g_backend_context, request);
    lock_state = g_backend_ops->lock(g_backend_context);
    kernel_futex_pi_waiter_cancel_locked(tid);
out:
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;
}

static int64_t futex_compare_requeue_pi(
        const kernel_futex_request_t *request) {
    kernel_futex_key_t source;
    kernel_futex_key_t destination;
    uintptr_t lock_state;
    uint32_t source_word;
    uint32_t destination_word;
    uint32_t expected;
    uint32_t desired;
    uint32_t limit;
    uint32_t moved = 0u;
    int32_t owner_tid;
    int status;

    if (!futex_pi_supported()) return -EDGE_LINUX_ENOSYS;
    if (request->wake_count != 1u) return -EDGE_LINUX_EINVAL;
    status = futex_resolve_key(
        request->address, request->private_futex, &source);
    if (status < 0) return status;
    status = futex_resolve_key(
        request->secondary_address,
        request->secondary_private_futex, &destination);
    if (status < 0) return status;
    if (futex_key_equal(&source, &destination))
        return -EDGE_LINUX_EINVAL;

    lock_state = g_backend_ops->lock(g_backend_context);
    status = g_backend_ops->read_word_locked(
        g_backend_context, request->address, &source_word);
    if (status < 0) goto out;
    if (source_word != request->comparison_value) {
        status = -EDGE_LINUX_EAGAIN;
        goto out;
    }
    status = g_backend_ops->read_word_locked(
        g_backend_context, request->secondary_address,
        &destination_word);
    if (status < 0) goto out;
    owner_tid = (int32_t)(destination_word &
                          EDGE_LINUX_FUTEX_TID_MASK);
    if (owner_tid > 0 && !g_backend_ops->task_exists_locked(
            g_backend_context, owner_tid)) {
        status = -EDGE_LINUX_ESRCH;
        goto out;
    }
    limit = request->secondary_count == UINT32_MAX ?
        UINT32_MAX : request->secondary_count + 1u;

    while (moved < limit) {
        int best = futex_pi_best_requeue_waiter_locked(
            &source, &destination);
        kernel_futex_pi_waiter_t *waiter;
        int direct_acquire;
        int more;

        if (best < 0) break;
        waiter = &g_pi_waiters[best];
        direct_acquire = owner_tid == 0 && moved == 0u;
        more = limit > moved + 1u &&
               futex_pi_has_other_requeue_waiter_locked(
                   &source, &destination, best);
        status = g_backend_ops->requeue_tid_locked(
            g_backend_context, &source, &destination, waiter->tid);
        if (status < 0) goto out;
        if (!status) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        expected = destination_word;
        if (direct_acquire) {
            desired = (destination_word &
                       EDGE_LINUX_FUTEX_OWNER_DIED) |
                      (uint32_t)waiter->tid |
                      (more ? EDGE_LINUX_FUTEX_WAITERS : 0u);
        } else {
            desired = destination_word |
                      EDGE_LINUX_FUTEX_WAITERS;
        }
        status = g_backend_ops->compare_exchange_word_locked(
            g_backend_context, request->secondary_address,
            &expected, desired);
        if (status != 0) {
            (void)g_backend_ops->requeue_tid_locked(
                g_backend_context, &destination, &source,
                waiter->tid);
            status = status < 0 ? status : -EDGE_LINUX_EAGAIN;
            goto out;
        }
        destination_word = desired;
        waiter->key = destination;
        waiter->address = request->secondary_address;
        waiter->requeue_pending = 0u;
        if (direct_acquire) {
            owner_tid = waiter->tid;
            waiter->used = 0u;
            status = g_backend_ops->wake_tid_locked(
                g_backend_context, &destination, owner_tid, 0);
            if (status < 0) goto out;
        } else {
            waiter->owner_tid = owner_tid;
        }
        ++moved;
    }
    if (owner_tid > 0) futex_pi_recompute_owner_locked(owner_tid);
    status = (int)moved;
out:
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;
}

int kernel_futex_pi_owner_died_locked(uint64_t address,
                                      int32_t owner_tid,
                                      uint32_t observed_word) {
    uint32_t expected = observed_word;
    uint32_t desired;
    int best = -1;
    int more = 0;
    int status;

    if (!futex_pi_supported() || !address || owner_tid <= 0) return 0;
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        kernel_futex_pi_waiter_t *waiter = &g_pi_waiters[index];
        if (!waiter->used || waiter->address != address ||
            waiter->owner_tid != owner_tid)
            continue;
        if (!futex_pi_waiter_active_locked(waiter)) {
            waiter->used = 0u;
            continue;
        }
        if (best < 0 || g_backend_ops->waiter_precedes_locked(
                g_backend_context, waiter->tid,
                g_pi_waiters[best].tid) > 0 ||
            (g_backend_ops->waiter_precedes_locked(
                 g_backend_context, waiter->tid,
                 g_pi_waiters[best].tid) == 0 &&
             waiter->sequence < g_pi_waiters[best].sequence))
            best = (int)index;
    }
    if (best < 0) return 0;
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        if ((int)index == best || !g_pi_waiters[index].used ||
            g_pi_waiters[index].address != address ||
            g_pi_waiters[index].owner_tid != owner_tid)
            continue;
        if (futex_pi_waiter_active_locked(&g_pi_waiters[index])) {
            more = 1;
            break;
        }
        g_pi_waiters[index].used = 0u;
    }
    desired = (uint32_t)g_pi_waiters[best].tid |
              EDGE_LINUX_FUTEX_OWNER_DIED |
              (more ? EDGE_LINUX_FUTEX_WAITERS : 0u);
    status = g_backend_ops->compare_exchange_word_locked(
        g_backend_context, address, &expected, desired);
    if (status != 0) return status < 0 ? status : -EDGE_LINUX_EAGAIN;
    {
        int32_t next_tid = g_pi_waiters[best].tid;
        kernel_futex_key_t key = g_pi_waiters[best].key;
        g_pi_waiters[best].used = 0u;
        for (uint32_t index = 0;
             index < KERNEL_FUTEX_PI_MAX_WAITERS; ++index)
            if (g_pi_waiters[index].used &&
                g_pi_waiters[index].address == address &&
                g_pi_waiters[index].owner_tid == owner_tid)
                g_pi_waiters[index].owner_tid = next_tid;
        status = g_backend_ops->wake_tid_locked(
            g_backend_context, &key, next_tid, 0);
        futex_pi_recompute_owner_locked(owner_tid);
        futex_pi_recompute_owner_locked(next_tid);
    }
    return status < 0 ? status : 1;
}

static int futex_pi_key_has_other_waiters_locked(
        const kernel_futex_key_t *key, int excluded) {
    for (uint32_t index = 0; index < KERNEL_FUTEX_PI_MAX_WAITERS;
         ++index) {
        kernel_futex_pi_waiter_t *waiter = &g_pi_waiters[index];
        if ((int)index == excluded || !waiter->used ||
            !futex_key_equal(&waiter->key, key))
            continue;
        if (!futex_pi_waiter_active_locked(waiter)) {
            waiter->used = 0u;
            continue;
        }
        return 1;
    }
    return 0;
}

static int64_t futex_lock_pi(const kernel_futex_request_t *request) {
    kernel_futex_key_t key;
    uintptr_t lock_state;
    uint32_t word;
    uint32_t expected;
    uint32_t desired;
    int32_t owner_tid;
    int32_t tid;
    int waiter_index;
    int status;

    if (!futex_pi_supported()) return -EDGE_LINUX_ENOSYS;
    tid = g_backend_ops->current_tid(g_backend_context);
    if (tid <= 0 || (uint32_t)tid > EDGE_LINUX_FUTEX_TID_MASK)
        return -EDGE_LINUX_ESRCH;
    status = futex_resolve_key(
        request->address, request->private_futex, &key);
    if (status < 0) return status;

    lock_state = g_backend_ops->lock(g_backend_context);
    status = g_backend_ops->read_word_locked(
        g_backend_context, request->address, &word);
    if (status < 0) goto unlock_error;
    owner_tid = (int32_t)(word & EDGE_LINUX_FUTEX_TID_MASK);
    if (!owner_tid) {
        expected = word;
        desired = (word & EDGE_LINUX_FUTEX_OWNER_DIED) |
                  (uint32_t)tid;
        status = g_backend_ops->compare_exchange_word_locked(
            g_backend_context, request->address, &expected, desired);
        if (status == 0) {
            g_backend_ops->unlock(g_backend_context, lock_state);
            return 0;
        }
        if (status < 0) goto unlock_error;
        word = expected;
        owner_tid = (int32_t)(word & EDGE_LINUX_FUTEX_TID_MASK);
    }
    if (owner_tid == tid) {
        status = -EDGE_LINUX_EDEADLK;
        goto unlock_error;
    }
    if (!g_backend_ops->task_exists_locked(
            g_backend_context, owner_tid)) {
        status = -EDGE_LINUX_ESRCH;
        goto unlock_error;
    }
    if (request->operation == KERNEL_FUTEX_TRYLOCK_PI) {
        status = -EDGE_LINUX_EAGAIN;
        goto unlock_error;
    }
    if (!(word & EDGE_LINUX_FUTEX_WAITERS)) {
        expected = word;
        desired = word | EDGE_LINUX_FUTEX_WAITERS;
        status = g_backend_ops->compare_exchange_word_locked(
            g_backend_context, request->address, &expected, desired);
        if (status < 0) goto unlock_error;
        if (status != 0) {
            status = -EDGE_LINUX_EAGAIN;
            goto unlock_error;
        }
    }
    waiter_index = futex_pi_waiter_allocate_locked(
        &key, request->address, tid, owner_tid);
    if (waiter_index < 0) {
        status = waiter_index;
        goto unlock_error;
    }
    status = g_backend_ops->prepare_pi_wait_locked(
        g_backend_context, request, &key);
    if (status < 0) {
        g_pi_waiters[waiter_index].used = 0u;
        goto unlock_error;
    }
    futex_pi_recompute_owner_locked(owner_tid);
    g_backend_ops->unlock(g_backend_context, lock_state);
    status = (int)g_backend_ops->block_pi_wait(
        g_backend_context, request);

    lock_state = g_backend_ops->lock(g_backend_context);
    kernel_futex_pi_waiter_cancel_locked(tid);
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;

unlock_error:
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;
}

static int64_t futex_unlock_pi(const kernel_futex_request_t *request) {
    kernel_futex_key_t key;
    uintptr_t lock_state;
    uint32_t word;
    uint32_t expected;
    uint32_t desired;
    int32_t tid;
    int32_t next_tid = 0;
    int best;
    int more;
    int status;

    if (!futex_pi_supported()) return -EDGE_LINUX_ENOSYS;
    tid = g_backend_ops->current_tid(g_backend_context);
    if (tid <= 0) return -EDGE_LINUX_ESRCH;
    status = futex_resolve_key(
        request->address, request->private_futex, &key);
    if (status < 0) return status;
    lock_state = g_backend_ops->lock(g_backend_context);
    status = g_backend_ops->read_word_locked(
        g_backend_context, request->address, &word);
    if (status < 0) goto out;
    if ((int32_t)(word & EDGE_LINUX_FUTEX_TID_MASK) != tid) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    best = futex_pi_best_waiter_locked(&key, tid);
    expected = word;
    if (best < 0) {
        desired = 0u;
    } else {
        next_tid = g_pi_waiters[best].tid;
        more = futex_pi_key_has_other_waiters_locked(&key, best);
        desired = (uint32_t)next_tid |
                  (more ? EDGE_LINUX_FUTEX_WAITERS : 0u);
    }
    status = g_backend_ops->compare_exchange_word_locked(
        g_backend_context, request->address, &expected, desired);
    if (status != 0) {
        status = status < 0 ? status : -EDGE_LINUX_EAGAIN;
        goto out;
    }
    if (best >= 0) {
        g_pi_waiters[best].used = 0u;
        for (uint32_t index = 0;
             index < KERNEL_FUTEX_PI_MAX_WAITERS; ++index)
            if (g_pi_waiters[index].used &&
                futex_key_equal(&g_pi_waiters[index].key, &key))
                g_pi_waiters[index].owner_tid = next_tid;
        status = g_backend_ops->wake_tid_locked(
            g_backend_context, &key, next_tid, 0);
        if (status < 0) goto out;
        futex_pi_recompute_owner_locked(next_tid);
    }
    futex_pi_recompute_owner_locked(tid);
    status = 0;
out:
    g_backend_ops->unlock(g_backend_context, lock_state);
    return status;
}

static int futex_resolve_key(uint64_t address, int private_futex,
                             kernel_futex_key_t *key) {
    if (!g_backend_ops) return -EDGE_LINUX_ENODEV;
    return g_backend_ops->resolve_key(
        g_backend_context, address, private_futex, key);
}

int64_t kernel_futex_execute(const kernel_futex_request_t *request) {
    kernel_futex_key_t source;
    kernel_futex_key_t destination;
    uintptr_t lock_state;
    int status;

    if (!request) return -EDGE_LINUX_EINVAL;
    if (!g_backend_ops) return -EDGE_LINUX_ENODEV;
    if (g_backend_ops->record_request)
        g_backend_ops->record_request(g_backend_context, request);

    if (request->operation == KERNEL_FUTEX_WAIT)
        return g_backend_ops->wait(g_backend_context, request);
    if (request->operation == KERNEL_FUTEX_WAIT_VECTOR)
        return g_backend_ops->wait_vector(g_backend_context, request);
    if (request->operation == KERNEL_FUTEX_LOCK_PI ||
        request->operation == KERNEL_FUTEX_TRYLOCK_PI)
        return futex_lock_pi(request);
    if (request->operation == KERNEL_FUTEX_UNLOCK_PI)
        return futex_unlock_pi(request);
    if (request->operation == KERNEL_FUTEX_WAIT_REQUEUE_PI)
        return futex_wait_requeue_pi(request);
    if (request->operation == KERNEL_FUTEX_COMPARE_REQUEUE_PI)
        return futex_compare_requeue_pi(request);

    status = futex_resolve_key(
        request->address, request->private_futex, &source);
    if (status < 0) return status;

    if (request->operation == KERNEL_FUTEX_WAKE) {
        int woken;
        lock_state = g_backend_ops->lock(g_backend_context);
        woken = futex_wake_locked(
            &source, request->wake_count, request->bitset);
        g_backend_ops->unlock(g_backend_context, lock_state);
        if (g_backend_ops->record_result)
            g_backend_ops->record_result(
                g_backend_context, request, woken);
        return woken;
    }

    status = futex_resolve_key(
        request->secondary_address, request->secondary_private_futex,
        &destination);
    if (status < 0) return status;
    if (futex_key_equal(&source, &destination))
        return -EDGE_LINUX_EINVAL;

    if (request->operation == KERNEL_FUTEX_REQUEUE ||
        request->operation == KERNEL_FUTEX_COMPARE_REQUEUE) {
        uint32_t observed;
        int woken;
        int moved;

        lock_state = g_backend_ops->lock(g_backend_context);
        if (request->operation == KERNEL_FUTEX_COMPARE_REQUEUE) {
            status = g_backend_ops->read_word_locked(
                g_backend_context, request->address, &observed);
            if (status < 0) {
                g_backend_ops->unlock(g_backend_context, lock_state);
                return status;
            }
            if (observed != request->comparison_value) {
                g_backend_ops->unlock(g_backend_context, lock_state);
                return -EDGE_LINUX_EAGAIN;
            }
        }
        woken = futex_wake_locked(
            &source, request->wake_count, UINT32_MAX);
        if (woken < 0) {
            g_backend_ops->unlock(g_backend_context, lock_state);
            return woken;
        }
        moved = futex_async_requeue_locked(
            &source, &destination,
            request->secondary_count, UINT32_MAX);
        if ((uint32_t)moved < request->secondary_count) {
            int backend_moved = g_backend_ops->requeue_locked(
                g_backend_context, &source, &destination,
                request->secondary_count - (uint32_t)moved,
                UINT32_MAX);
            if (backend_moved < 0) moved = backend_moved;
            else moved += backend_moved;
        }
        g_backend_ops->unlock(g_backend_context, lock_state);
        return moved < 0 ? moved : woken + moved;
    }

    if (request->operation == KERNEL_FUTEX_WAKE_OPERATION) {
        uint32_t old_word;
        int32_t old_value;
        uint32_t expected;
        int wake_destination;
        int woken;
        int destination_woken = 0;

        lock_state = g_backend_ops->lock(g_backend_context);
        status = g_backend_ops->read_word_locked(
            g_backend_context, request->secondary_address, &old_word);
        if (status < 0) {
            g_backend_ops->unlock(g_backend_context, lock_state);
            return status;
        }
        for (;;) {
            uint32_t new_word;

            old_value = (int32_t)old_word;
            new_word = (uint32_t)kernel_futex_atomic_apply(
                request, old_value);
            expected = old_word;
            status = g_backend_ops->compare_exchange_word_locked(
                g_backend_context, request->secondary_address,
                &expected, new_word);
            if (status < 0) {
                g_backend_ops->unlock(g_backend_context, lock_state);
                return status;
            }
            if (status == 0) break;
            old_word = expected;
        }
        wake_destination =
            kernel_futex_atomic_compare(request, old_value);
        woken = futex_wake_locked(
            &source, request->wake_count, UINT32_MAX);
        if (woken >= 0 && wake_destination)
            destination_woken = futex_wake_locked(
                &destination, request->secondary_count, UINT32_MAX);
        g_backend_ops->unlock(g_backend_context, lock_state);
        if (woken < 0) return woken;
        if (destination_woken < 0) return destination_woken;
        return woken + destination_woken;
    }

    return -EDGE_LINUX_ENOSYS;
}
