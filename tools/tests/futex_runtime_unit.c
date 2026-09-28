/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/futex_runtime.h"
#include "kernel/linux_errno.h"

typedef struct futex_test_backend {
    uint32_t word;
    uint32_t source_word;
    uint32_t compare_exchange_calls;
    uint32_t source_wakes;
    uint32_t destination_wakes;
    uint64_t source_address;
    uint64_t destination_address;
} futex_test_backend_t;

int32_t kernel_futex_atomic_apply(const kernel_futex_request_t *request,
                                  int32_t old_value) {
    switch (request->atomic_operation) {
        case KERNEL_FUTEX_ATOMIC_SET:
            return request->atomic_argument;
        case KERNEL_FUTEX_ATOMIC_ADD:
            return old_value + request->atomic_argument;
        case KERNEL_FUTEX_ATOMIC_OR:
            return old_value | request->atomic_argument;
        case KERNEL_FUTEX_ATOMIC_AND_NOT:
            return old_value & ~request->atomic_argument;
        case KERNEL_FUTEX_ATOMIC_XOR:
            return old_value ^ request->atomic_argument;
    }
    return old_value;
}

int kernel_futex_atomic_compare(const kernel_futex_request_t *request,
                                int32_t old_value) {
    return request->atomic_comparison == KERNEL_FUTEX_COMPARE_EQUAL &&
           old_value == request->atomic_comparison_argument;
}

static int resolve_key(void *context, uint64_t address, int private_futex,
                       kernel_futex_key_t *key) {
    (void)context;
    key->value = address;
    key->scope = (uintptr_t)(private_futex != 0);
    return 0;
}

static int64_t unsupported_wait(
    void *context, const kernel_futex_request_t *request) {
    (void)context;
    (void)request;
    return -1;
}

static uintptr_t lock_backend(void *context) {
    (void)context;
    return 0;
}

static void unlock_backend(void *context, uintptr_t lock_state) {
    (void)context;
    (void)lock_state;
}

static int read_word(void *context, uint64_t address, uint32_t *value) {
    futex_test_backend_t *backend = context;
    assert(address == backend->destination_address ||
           address == backend->source_address);
    *value = address == backend->destination_address ?
        backend->word : backend->source_word;
    return 0;
}

static int compare_exchange_word(void *context, uint64_t address,
                                 uint32_t *expected, uint32_t desired) {
    futex_test_backend_t *backend = context;

    assert(address == backend->destination_address);
    ++backend->compare_exchange_calls;
    if (backend->compare_exchange_calls == 1u) {
        ++backend->word;
        *expected = backend->word;
        return 1;
    }
    if (backend->word != *expected) {
        *expected = backend->word;
        return 1;
    }
    backend->word = desired;
    return 0;
}

static int wake_word(void *context, const kernel_futex_key_t *key,
                     uint32_t maximum, uint32_t bitset) {
    futex_test_backend_t *backend = context;
    (void)maximum;
    (void)bitset;
    if (key->value == backend->source_address)
        ++backend->source_wakes;
    else if (key->value == backend->destination_address)
        ++backend->destination_wakes;
    return 0;
}

static int requeue_word(void *context, const kernel_futex_key_t *source,
                        const kernel_futex_key_t *destination,
                        uint32_t maximum, uint32_t bitset) {
    (void)context;
    (void)source;
    (void)destination;
    (void)maximum;
    (void)bitset;
    return 0;
}

int main(void) {
    futex_test_backend_t backend;
    kernel_futex_request_t request;
    const kernel_futex_backend_ops_t ops = {
        .resolve_key = resolve_key,
        .wait = unsupported_wait,
        .wait_vector = unsupported_wait,
        .lock = lock_backend,
        .unlock = unlock_backend,
        .read_word_locked = read_word,
        .compare_exchange_word_locked = compare_exchange_word,
        .wake_locked = wake_word,
        .requeue_locked = requeue_word,
    };

    memset(&backend, 0, sizeof(backend));
    backend.word = 8u;
    backend.source_word = 3u;
    backend.source_address = UINT64_C(0x1000);
    backend.destination_address = UINT64_C(0x2000);
    assert(kernel_futex_backend_register(&ops, &backend) == 0);

    memset(&request, 0, sizeof(request));
    request.operation = KERNEL_FUTEX_WAKE_OPERATION;
    request.address = backend.source_address;
    request.secondary_address = backend.destination_address;
    request.atomic_operation = KERNEL_FUTEX_ATOMIC_OR;
    request.atomic_argument = 0;
    request.atomic_comparison = KERNEL_FUTEX_COMPARE_EQUAL;
    request.atomic_comparison_argument = 8;
    request.wake_count = 1u;
    request.secondary_count = 1u;

    assert(kernel_futex_execute(&request) == 0);
    assert(backend.word == 9u);
    assert(backend.compare_exchange_calls == 2u);
    assert(backend.source_wakes == 1u);
    assert(backend.destination_wakes == 0u);

    {
        uint64_t wait_id;
        int32_t wait_result = -1;

        memset(&request, 0, sizeof(request));
        request.operation = KERNEL_FUTEX_WAIT;
        request.address = backend.destination_address;
        request.expected_value = backend.word;
        request.bitset = 2u;
        assert(kernel_futex_async_wait_add(&request, &wait_id) == 0);
        assert(kernel_futex_async_wait_poll(wait_id, &wait_result) == 0);

        request.operation = KERNEL_FUTEX_WAKE;
        request.wake_count = 1u;
        request.bitset = 1u;
        assert(kernel_futex_execute(&request) == 0);
        assert(kernel_futex_async_wait_poll(wait_id, &wait_result) == 0);
        request.bitset = 2u;
        assert(kernel_futex_execute(&request) == 1);
        assert(kernel_futex_async_wait_poll(wait_id, &wait_result) == 1);
        assert(wait_result == 0);
        assert(kernel_futex_async_wait_poll(wait_id, &wait_result) ==
               -EDGE_LINUX_ENOENT);
    }
    {
        uint64_t wait_id;
        int32_t wait_result = -1;

        memset(&request, 0, sizeof(request));
        request.operation = KERNEL_FUTEX_WAIT_VECTOR;
        request.waiter_count = 2u;
        request.waiters[0].address = backend.source_address;
        request.waiters[0].expected_value = backend.source_word;
        request.waiters[1].address = backend.destination_address;
        request.waiters[1].expected_value = backend.word;
        assert(kernel_futex_async_wait_add(&request, &wait_id) == 0);

        memset(&request, 0, sizeof(request));
        request.operation = KERNEL_FUTEX_WAKE;
        request.address = backend.destination_address;
        request.wake_count = 1u;
        request.bitset = UINT32_MAX;
        assert(kernel_futex_execute(&request) == 1);
        assert(kernel_futex_async_wait_poll(wait_id, &wait_result) == 1);
        assert(wait_result == 1);
    }
    {
        uint64_t wait_id;
        int32_t wait_result = -1;

        memset(&request, 0, sizeof(request));
        request.operation = KERNEL_FUTEX_WAIT;
        request.address = backend.source_address;
        request.expected_value = backend.source_word + 1u;
        request.bitset = UINT32_MAX;
        assert(kernel_futex_async_wait_add(&request, &wait_id) ==
               -EDGE_LINUX_EAGAIN);
        request.expected_value = backend.source_word;
        assert(kernel_futex_async_wait_add(&request, &wait_id) == 0);
        assert(kernel_futex_async_wait_cancel(wait_id) == 0);
        assert(kernel_futex_async_wait_poll(wait_id, &wait_result) ==
               -EDGE_LINUX_ENOENT);

        assert(kernel_futex_async_wait_add(&request, &wait_id) == 0);
        request.operation = KERNEL_FUTEX_REQUEUE;
        request.secondary_address = backend.destination_address;
        request.wake_count = 0u;
        request.secondary_count = 1u;
        assert(kernel_futex_execute(&request) == 1);
        request.operation = KERNEL_FUTEX_WAKE;
        request.address = backend.destination_address;
        request.wake_count = 1u;
        request.bitset = UINT32_MAX;
        assert(kernel_futex_execute(&request) == 1);
        assert(kernel_futex_async_wait_poll(wait_id, &wait_result) == 1);
        assert(wait_result == 0);
    }
    puts("futex runtime unit: ok");
    return 0;
}
