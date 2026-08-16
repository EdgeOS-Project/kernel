/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral Linux futex operation policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/futex_runtime.h"
#include "kernel/linux_errno.h"

static const kernel_futex_backend_ops_t *g_backend_ops;
static void *g_backend_context;

int kernel_futex_backend_register(
    const kernel_futex_backend_ops_t *ops, void *context) {
    if (!ops || !ops->resolve_key || !ops->wait || !ops->wait_vector ||
        !ops->lock || !ops->unlock || !ops->read_word_locked ||
        !ops->compare_exchange_word_locked || !ops->wake_locked ||
        !ops->requeue_locked)
        return -EDGE_LINUX_EINVAL;
    g_backend_ops = ops;
    g_backend_context = context;
    return 0;
}

static int futex_key_equal(const kernel_futex_key_t *left,
                           const kernel_futex_key_t *right) {
    return left->value == right->value && left->scope == right->scope;
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

    status = futex_resolve_key(
        request->address, request->private_futex, &source);
    if (status < 0) return status;

    if (request->operation == KERNEL_FUTEX_WAKE) {
        int woken;
        lock_state = g_backend_ops->lock(g_backend_context);
        woken = g_backend_ops->wake_locked(
            g_backend_context, &source, request->wake_count,
            request->bitset);
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
        woken = g_backend_ops->wake_locked(
            g_backend_context, &source, request->wake_count, UINT32_MAX);
        if (woken < 0) {
            g_backend_ops->unlock(g_backend_context, lock_state);
            return woken;
        }
        moved = g_backend_ops->requeue_locked(
            g_backend_context, &source, &destination,
            request->secondary_count, UINT32_MAX);
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
        woken = g_backend_ops->wake_locked(
            g_backend_context, &source, request->wake_count, UINT32_MAX);
        if (woken >= 0 && wake_destination)
            destination_woken = g_backend_ops->wake_locked(
                g_backend_context, &destination,
                request->secondary_count, UINT32_MAX);
        g_backend_ops->unlock(g_backend_context, lock_state);
        if (woken < 0) return woken;
        if (destination_woken < 0) return destination_woken;
        return woken + destination_woken;
    }

    return -EDGE_LINUX_ENOSYS;
}
