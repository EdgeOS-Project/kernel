/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for shared Linux PI futex ownership policy. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/futex_runtime.h"
#include "kernel/linux_errno.h"

typedef struct pi_backend {
    uint64_t address;
    uint32_t word;
    uint64_t second_address;
    uint32_t second_word;
    int32_t current_tid;
    int32_t wake_tid;
    int32_t wake_result;
    int32_t boosted_owner;
    int32_t boosted_donor;
    uint8_t owner_dies;
    uint8_t requeue_signal;
    uint8_t waiting[4];
} pi_backend_t;

static int resolve_key(void *context, uint64_t address, int private_futex,
                       kernel_futex_key_t *key) {
    pi_backend_t *backend = context;
    if (address != backend->address &&
        address != backend->second_address)
        return -EDGE_LINUX_EFAULT;
    key->value = address;
    key->scope = (uintptr_t)(private_futex != 0);
    return 0;
}

static int64_t unsupported_wait(
    void *context, const kernel_futex_request_t *request) {
    (void)context;
    (void)request;
    return -EDGE_LINUX_ENOSYS;
}

static uintptr_t lock_backend(void *context) {
    (void)context;
    return 0;
}

static void unlock_backend(void *context, uintptr_t state) {
    (void)context;
    (void)state;
}

static int read_word(void *context, uint64_t address, uint32_t *value) {
    pi_backend_t *backend = context;
    if (!value) return -EDGE_LINUX_EFAULT;
    if (address == backend->address)
        *value = backend->word;
    else if (address == backend->second_address)
        *value = backend->second_word;
    else
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int compare_exchange_word(void *context, uint64_t address,
                                 uint32_t *expected, uint32_t desired) {
    pi_backend_t *backend = context;
    uint32_t *word;
    if (!expected) return -EDGE_LINUX_EFAULT;
    if (address == backend->address)
        word = &backend->word;
    else if (address == backend->second_address)
        word = &backend->second_word;
    else
        return -EDGE_LINUX_EFAULT;
    if (*expected != *word) {
        *expected = *word;
        return 1;
    }
    *word = desired;
    return 0;
}

static int no_wake(void *context, const kernel_futex_key_t *key,
                   uint32_t maximum, uint32_t bitset) {
    (void)context;
    (void)key;
    (void)maximum;
    (void)bitset;
    return 0;
}

static int no_requeue(void *context, const kernel_futex_key_t *source,
                      const kernel_futex_key_t *destination,
                      uint32_t maximum, uint32_t bitset) {
    (void)context;
    (void)source;
    (void)destination;
    (void)maximum;
    (void)bitset;
    return 0;
}

static int requeue_tid(void *context, const kernel_futex_key_t *source,
                       const kernel_futex_key_t *destination,
                       int32_t tid) {
    pi_backend_t *backend = context;
    (void)source;
    (void)destination;
    return tid > 0 && tid < 4 && backend->waiting[tid] ? 1 : 0;
}

static int32_t current_tid(void *context) {
    return ((pi_backend_t *)context)->current_tid;
}

static int waiter_precedes(void *context, int32_t candidate,
                           int32_t current) {
    (void)context;
    return candidate > current ? 1 : candidate < current ? -1 : 0;
}

static int prepare_pi_wait(void *context,
                           const kernel_futex_request_t *request,
                           const kernel_futex_key_t *key) {
    pi_backend_t *backend = context;
    (void)request;
    if (!key || backend->current_tid <= 0 || backend->current_tid >= 4)
        return -EDGE_LINUX_EINVAL;
    backend->waiting[backend->current_tid] = 1u;
    return 0;
}

static int wake_tid(void *context, const kernel_futex_key_t *key,
                    int32_t tid, int result) {
    pi_backend_t *backend = context;
    (void)key;
    if (tid <= 0 || tid >= 4 || !backend->waiting[tid])
        return -EDGE_LINUX_ESRCH;
    backend->waiting[tid] = 0u;
    backend->wake_tid = tid;
    backend->wake_result = result;
    return 0;
}

static int waiter_active(void *context, const kernel_futex_key_t *key,
                         int32_t tid) {
    pi_backend_t *backend = context;
    (void)key;
    return tid > 0 && tid < 4 && backend->waiting[tid];
}

static int task_exists(void *context, int32_t tid) {
    (void)context;
    return tid > 0 && tid < 4;
}

static void recompute_owner(void *context, int32_t owner_tid,
                            int32_t donor_tid) {
    pi_backend_t *backend = context;
    backend->boosted_owner = owner_tid;
    backend->boosted_donor = donor_tid;
}

static int64_t block_pi_wait(
    void *context, const kernel_futex_request_t *request) {
    pi_backend_t *backend = context;
    kernel_futex_request_t unlock;
    int32_t waiter = backend->current_tid;
    int64_t result;
    (void)request;

    memset(&unlock, 0, sizeof(unlock));
    if (backend->requeue_signal) {
        kernel_futex_request_t requeue;
        memset(&requeue, 0, sizeof(requeue));
        requeue.operation = KERNEL_FUTEX_COMPARE_REQUEUE_PI;
        requeue.address = backend->address;
        requeue.secondary_address = backend->second_address;
        requeue.private_futex = 1u;
        requeue.secondary_private_futex = 1u;
        requeue.wake_count = 1u;
        requeue.comparison_value = backend->word;
        backend->current_tid = 1;
        result = kernel_futex_execute(&requeue);
        assert(result == 1);
        backend->current_tid = waiter;
        assert(backend->wake_tid == waiter);
        return backend->wake_result;
    }
    if (backend->owner_dies) {
        result = kernel_futex_pi_owner_died_locked(
            backend->address, 1, backend->word);
        assert(result == 1);
        assert(backend->wake_tid == waiter);
        return backend->wake_result;
    }
    unlock.operation = KERNEL_FUTEX_UNLOCK_PI;
    unlock.address = backend->address;
    unlock.private_futex = 1u;
    backend->current_tid = 1;
    result = kernel_futex_execute(&unlock);
    assert(result == 0);
    backend->current_tid = waiter;
    assert(backend->wake_tid == waiter);
    return backend->wake_result;
}

int32_t kernel_futex_atomic_apply(const kernel_futex_request_t *request,
                                  int32_t old_value) {
    (void)request;
    return old_value;
}

int kernel_futex_atomic_compare(const kernel_futex_request_t *request,
                                int32_t old_value) {
    (void)request;
    (void)old_value;
    return 0;
}

int main(void) {
    pi_backend_t backend;
    kernel_futex_request_t request;
    const kernel_futex_backend_ops_t operations = {
        .resolve_key = resolve_key,
        .wait = unsupported_wait,
        .wait_vector = unsupported_wait,
        .lock = lock_backend,
        .unlock = unlock_backend,
        .read_word_locked = read_word,
        .compare_exchange_word_locked = compare_exchange_word,
        .wake_locked = no_wake,
        .requeue_locked = no_requeue,
        .requeue_tid_locked = requeue_tid,
        .current_tid = current_tid,
        .waiter_precedes_locked = waiter_precedes,
        .prepare_pi_wait_locked = prepare_pi_wait,
        .block_pi_wait = block_pi_wait,
        .wake_tid_locked = wake_tid,
        .waiter_active_locked = waiter_active,
        .task_exists_locked = task_exists,
        .recompute_pi_owner_locked = recompute_owner,
    };

    memset(&backend, 0, sizeof(backend));
    backend.address = UINT64_C(0x4000);
    backend.second_address = UINT64_C(0x5000);
    backend.current_tid = 1;
    assert(kernel_futex_backend_register(&operations, &backend) == 0);

    memset(&request, 0, sizeof(request));
    request.operation = KERNEL_FUTEX_LOCK_PI;
    request.address = backend.address;
    request.private_futex = 1u;
    assert(kernel_futex_execute(&request) == 0);
    assert(backend.word == 1u);
    assert(kernel_futex_execute(&request) == -EDGE_LINUX_EDEADLK);

    request.operation = KERNEL_FUTEX_UNLOCK_PI;
    assert(kernel_futex_execute(&request) == 0);
    assert(backend.word == 0u);

    backend.word = 1u;
    backend.current_tid = 2;
    request.operation = KERNEL_FUTEX_TRYLOCK_PI;
    assert(kernel_futex_execute(&request) == -EDGE_LINUX_EAGAIN);

    request.operation = KERNEL_FUTEX_LOCK_PI;
    assert(kernel_futex_execute(&request) == 0);
    assert(backend.word == 2u);
    assert(backend.boosted_owner == 1);
    assert(backend.wake_tid == 2);

    request.operation = KERNEL_FUTEX_UNLOCK_PI;
    assert(kernel_futex_execute(&request) == 0);
    assert(backend.word == 0u);

    backend.word = 1u;
    backend.current_tid = 2;
    backend.wake_tid = 0;
    backend.owner_dies = 1u;
    request.operation = KERNEL_FUTEX_LOCK_PI;
    assert(kernel_futex_execute(&request) == 0);
    assert(backend.word == (UINT32_C(0x40000000) | 2u));
    assert(backend.wake_tid == 2);
    backend.owner_dies = 0u;
    request.operation = KERNEL_FUTEX_UNLOCK_PI;
    assert(kernel_futex_execute(&request) == 0);
    assert(backend.word == 0u);

    backend.word = 7u;
    backend.second_word = 0u;
    backend.current_tid = 2;
    backend.wake_tid = 0;
    backend.requeue_signal = 1u;
    memset(&request, 0, sizeof(request));
    request.operation = KERNEL_FUTEX_WAIT_REQUEUE_PI;
    request.address = backend.address;
    request.secondary_address = backend.second_address;
    request.private_futex = 1u;
    request.secondary_private_futex = 1u;
    request.expected_value = 7u;
    request.bitset = UINT32_MAX;
    assert(kernel_futex_execute(&request) == 0);
    assert(backend.second_word == 2u);
    backend.requeue_signal = 0u;
    request.operation = KERNEL_FUTEX_UNLOCK_PI;
    request.address = backend.second_address;
    assert(kernel_futex_execute(&request) == 0);
    assert(backend.second_word == 0u);
    puts("futex PI runtime unit: ok");
    return 0;
}
