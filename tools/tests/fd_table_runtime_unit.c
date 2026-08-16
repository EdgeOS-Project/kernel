/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#define SYS_SPINLOCK_H
typedef struct {
    atomic_flag value;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock) {
    atomic_flag_clear_explicit(&lock->value, memory_order_relaxed);
}

static inline uint64_t spin_lock_irqsave(spinlock_t *lock) {
    while (atomic_flag_test_and_set_explicit(
               &lock->value, memory_order_acquire))
        sched_yield();
    return 0;
}

static inline void spin_unlock_irqrestore(spinlock_t *lock,
                                          uint64_t flags) {
    (void)flags;
    atomic_flag_clear_explicit(&lock->value, memory_order_release);
}

#include "../../src/kernel/fd_table_runtime.c"

enum {
    TEST_FD_LIMIT = 64,
    TEST_THREAD_COUNT = 8,
    TEST_ITERATIONS = 2000,
    TEST_BATCH_SIZE = 11,
};

typedef struct fd_table_test_context {
    kernel_fd_table_runtime_t *runtime;
    atomic_uint *owners;
} fd_table_test_context_t;

static void *fd_table_worker(void *opaque) {
    fd_table_test_context_t *context =
        (fd_table_test_context_t *)opaque;

    for (uint32_t iteration = 0;
         iteration < TEST_ITERATIONS; ++iteration) {
        uint32_t descriptor;
        uint64_t flags;
        int result;

        for (;;) {
            flags = kernel_fd_table_lock(context->runtime);
            result = kernel_fd_table_reserve_next_locked(
                context->runtime, 0, &descriptor);
            kernel_fd_table_unlock(context->runtime, flags);
            if (result == 0) break;
            assert(result == -EDGE_LINUX_EMFILE);
            sched_yield();
        }

        assert(atomic_fetch_add_explicit(
                   &context->owners[descriptor], 1u,
                   memory_order_acq_rel) == 0u);
        flags = kernel_fd_table_lock(context->runtime);
        assert(kernel_fd_table_publish_locked(
                   context->runtime, descriptor) == 0);
        assert(kernel_fd_table_is_open_locked(
                   context->runtime, descriptor));
        assert(kernel_fd_table_begin_close_locked(
                   context->runtime, descriptor) == 0);
        kernel_fd_table_unlock(context->runtime, flags);

        assert(atomic_fetch_sub_explicit(
                   &context->owners[descriptor], 1u,
                   memory_order_acq_rel) == 1u);
        flags = kernel_fd_table_lock(context->runtime);
        assert(kernel_fd_table_complete_close_locked(
                   context->runtime, descriptor) == 0);
        kernel_fd_table_unlock(context->runtime, flags);
    }
    return 0;
}

static void *fd_table_batch_worker(void *opaque) {
    fd_table_test_context_t *context =
        (fd_table_test_context_t *)opaque;

    for (uint32_t iteration = 0;
         iteration < TEST_ITERATIONS; ++iteration) {
        uint32_t descriptors[TEST_BATCH_SIZE];
        uint32_t reserved;
        uint64_t flags;
        int result;

        for (;;) {
            flags = kernel_fd_table_lock(context->runtime);
            result = kernel_fd_table_reserve_batch_locked(
                context->runtime, 0, descriptors,
                TEST_BATCH_SIZE, &reserved);
            kernel_fd_table_unlock(context->runtime, flags);
            if (result == 0) break;
            assert(result == -EDGE_LINUX_EMFILE);
            assert(reserved == 0);
            sched_yield();
        }

        assert(reserved > 0);
        assert(reserved <= TEST_BATCH_SIZE);
        for (uint32_t index = 0; index < reserved; ++index) {
            assert(atomic_fetch_add_explicit(
                       &context->owners[descriptors[index]], 1u,
                       memory_order_acq_rel) == 0u);
        }

        flags = kernel_fd_table_lock(context->runtime);
        assert(kernel_fd_table_publish_batch_locked(
                   context->runtime, descriptors, reserved) == 0);
        for (uint32_t index = 0; index < reserved; ++index) {
            assert(kernel_fd_table_is_open_locked(
                       context->runtime, descriptors[index]));
            assert(kernel_fd_table_begin_close_locked(
                       context->runtime, descriptors[index]) == 0);
        }
        kernel_fd_table_unlock(context->runtime, flags);

        for (uint32_t index = 0; index < reserved; ++index) {
            assert(atomic_fetch_sub_explicit(
                       &context->owners[descriptors[index]], 1u,
                       memory_order_acq_rel) == 1u);
        }
        flags = kernel_fd_table_lock(context->runtime);
        for (uint32_t index = 0; index < reserved; ++index) {
            assert(kernel_fd_table_complete_close_locked(
                       context->runtime, descriptors[index]) == 0);
        }
        kernel_fd_table_unlock(context->runtime, flags);
    }
    return 0;
}

static void test_state_machine(void) {
    kernel_fd_table_runtime_t runtime;
    uint8_t states[TEST_FD_LIMIT] = { 0 };
    uint32_t descriptor;
    uint64_t flags;

    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, TEST_FD_LIMIT) == 0);
    flags = kernel_fd_table_lock(&runtime);
    assert(kernel_fd_table_reserve_next_locked(
               &runtime, 3u, &descriptor) == 0);
    assert(descriptor == 3u);
    assert(kernel_fd_table_state_locked(
               &runtime, descriptor) == KERNEL_FD_SLOT_RESERVED);
    assert(kernel_fd_table_publish_locked(
               &runtime, descriptor) == 0);
    assert(kernel_fd_table_begin_close_locked(
               &runtime, descriptor) == 0);
    assert(kernel_fd_table_restore_open_locked(
               &runtime, descriptor) == 0);
    assert(kernel_fd_table_begin_close_locked(
               &runtime, descriptor) == 0);
    assert(kernel_fd_table_complete_close_locked(
               &runtime, descriptor) == 0);

    assert(kernel_fd_table_reserve_exact_locked(
               &runtime, 7u) == 0);
    assert(kernel_fd_table_reserve_exact_locked(
               &runtime, 8u) == 0);
    assert(kernel_fd_table_publish_pair_locked(
               &runtime, 7u, 8u) == 0);
    assert(kernel_fd_table_begin_close_locked(
               &runtime, 7u) == 0);
    assert(kernel_fd_table_complete_close_locked(
               &runtime, 7u) == 0);
    assert(kernel_fd_table_begin_close_locked(
               &runtime, 8u) == 0);
    assert(kernel_fd_table_complete_close_locked(
               &runtime, 8u) == 0);

    assert(kernel_fd_table_reserve_exact_locked(
               &runtime, 9u) == 0);
    assert(kernel_fd_table_cancel_reservation_locked(
               &runtime, 9u) == 0);
    assert(kernel_fd_table_reserve_exact_locked(
               &runtime, 10u) == 0);
    assert(kernel_fd_table_publish_locked(
               &runtime, 10u) == 0);
    assert(kernel_fd_table_detach_open_locked(
               &runtime, 10u) == 0);
    assert(kernel_fd_table_state_locked(
               &runtime, 10u) == KERNEL_FD_SLOT_FREE);
    assert(kernel_fd_table_reserve_exact_locked(
               &runtime, 10u) == 0);
    assert(kernel_fd_table_cancel_reservation_locked(
               &runtime, 10u) == 0);
    kernel_fd_table_unlock(&runtime, flags);
}

static void test_batch_reserve_semantics(void) {
    enum { LIMIT = 12 };
    kernel_fd_table_runtime_t runtime;
    uint8_t states[LIMIT];
    uint32_t descriptors[5] = { 0 };
    uint32_t reserved = UINT32_MAX;
    uint64_t flags;

    for (uint32_t descriptor = 0; descriptor < LIMIT; ++descriptor)
        states[descriptor] = KERNEL_FD_SLOT_OPEN;
    states[1] = KERNEL_FD_SLOT_FREE;
    states[4] = KERNEL_FD_SLOT_FREE;
    states[7] = KERNEL_FD_SLOT_FREE;
    states[10] = KERNEL_FD_SLOT_FREE;

    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, LIMIT) == 0);
    flags = kernel_fd_table_lock(&runtime);
    assert(kernel_fd_table_reserve_batch_locked(
               &runtime, UINT32_MAX, NULL, 0, &reserved) == 0);
    assert(reserved == 0);
    assert(kernel_fd_table_reserve_batch_locked(
               &runtime, 3, descriptors, 5, &reserved) == 0);
    assert(reserved == 3);
    assert(descriptors[0] == 4);
    assert(descriptors[1] == 7);
    assert(descriptors[2] == 10);
    assert(kernel_fd_table_state_locked(
               &runtime, 1) == KERNEL_FD_SLOT_FREE);
    for (uint32_t index = 0; index < reserved; ++index) {
        assert(kernel_fd_table_state_locked(
                   &runtime,
                   descriptors[index]) == KERNEL_FD_SLOT_RESERVED);
    }

    assert(kernel_fd_table_publish_batch_locked(
               &runtime, descriptors, reserved) == 0);
    reserved = UINT32_MAX;
    assert(kernel_fd_table_reserve_batch_locked(
               &runtime, 3, descriptors, 5, &reserved) ==
           -EDGE_LINUX_EMFILE);
    assert(reserved == 0);
    assert(kernel_fd_table_reserve_batch_locked(
               &runtime, LIMIT, descriptors, 1, &reserved) ==
           -EDGE_LINUX_EMFILE);
    assert(reserved == 0);
    assert(kernel_fd_table_reserve_batch_locked(
               &runtime, 0, NULL, 1, &reserved) ==
           -EDGE_LINUX_EINVAL);
    assert(reserved == 0);

    for (uint32_t descriptor = 3; descriptor < LIMIT; ++descriptor) {
        if (kernel_fd_table_state_locked(
                &runtime, descriptor) != KERNEL_FD_SLOT_OPEN)
            continue;
        assert(kernel_fd_table_begin_close_locked(
                   &runtime, descriptor) == 0);
        assert(kernel_fd_table_complete_close_locked(
                   &runtime, descriptor) == 0);
    }
    kernel_fd_table_unlock(&runtime, flags);

    assert(states[1] == KERNEL_FD_SLOT_FREE);
    for (uint32_t descriptor = 3; descriptor < LIMIT; ++descriptor)
        assert(states[descriptor] == KERNEL_FD_SLOT_FREE);
}

static void test_allocation_limit(void) {
    enum { LIMIT = 12 };
    kernel_fd_table_runtime_t runtime;
    uint8_t states[LIMIT] = { 0 };
    uint32_t descriptors[3] = { UINT32_MAX, UINT32_MAX, UINT32_MAX };
    uint32_t descriptor = UINT32_MAX;
    uint32_t reserved = UINT32_MAX;
    uint64_t flags;

    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, LIMIT) == 0);
    flags = kernel_fd_table_lock(&runtime);
    states[0] = KERNEL_FD_SLOT_OPEN;
    states[1] = KERNEL_FD_SLOT_OPEN;
    assert(kernel_fd_table_reserve_next_below_locked(
               &runtime, 0, 4, &descriptor) == 0);
    assert(descriptor == 2);
    assert(kernel_fd_table_reserve_next_below_locked(
               &runtime, 3, 3, &descriptor) ==
           -EDGE_LINUX_EMFILE);
    assert(kernel_fd_table_reserve_batch_below_locked(
               &runtime, 0, 4, descriptors, 3, &reserved) == 0);
    assert(reserved == 1);
    assert(descriptors[0] == 3);
    assert(kernel_fd_table_reserve_next_below_locked(
               &runtime, 0, 4, &descriptor) ==
           -EDGE_LINUX_EMFILE);
    assert(kernel_fd_table_reserve_next_below_locked(
               &runtime, 11, UINT32_MAX, &descriptor) == 0);
    assert(descriptor == 11);
    assert(kernel_fd_table_cancel_reservation_locked(
               &runtime, 2) == 0);
    assert(kernel_fd_table_cancel_reservation_locked(
               &runtime, 3) == 0);
    assert(kernel_fd_table_cancel_reservation_locked(
               &runtime, 11) == 0);
    kernel_fd_table_unlock(&runtime, flags);
}

static void test_allocated_limit_tracking(void) {
    enum { LIMIT = 256 };
    kernel_fd_table_runtime_t runtime;
    kernel_fd_table_runtime_t clone;
    uint8_t states[LIMIT] = { 0 };
    uint8_t clone_states[LIMIT] = { 0 };
    uint64_t flags;
    uint64_t clone_flags;

    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, LIMIT) == 0);
    flags = kernel_fd_table_lock(&runtime);
    assert(kernel_fd_table_allocated_limit_locked(&runtime) == 64);
    assert(kernel_fd_table_reserve_exact_locked(&runtime, 100) == 0);
    assert(kernel_fd_table_allocated_limit_locked(&runtime) == 128);
    assert(kernel_fd_table_cancel_reservation_locked(
               &runtime, 100) == 0);
    assert(kernel_fd_table_allocated_limit_locked(&runtime) == 128);

    assert(kernel_fd_table_runtime_initialize(
               &clone, clone_states, LIMIT) == 0);
    clone_flags = kernel_fd_table_lock(&clone);
    assert(kernel_fd_table_allocated_limit_locked(&clone) == 64);
    assert(kernel_fd_table_inherit_allocated_limit_locked(
               &clone, &runtime) == 0);
    assert(kernel_fd_table_allocated_limit_locked(&clone) == 128);
    kernel_fd_table_unlock(&clone, clone_flags);
    kernel_fd_table_unlock(&runtime, flags);

    states[200] = KERNEL_FD_SLOT_OPEN;
    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, LIMIT) == 0);
    flags = kernel_fd_table_lock(&runtime);
    assert(kernel_fd_table_allocated_limit_locked(&runtime) == 256);
    kernel_fd_table_unlock(&runtime, flags);
}

static void test_batch_publish_is_atomic(void) {
    kernel_fd_table_runtime_t runtime;
    uint8_t states[TEST_FD_LIMIT] = { 0 };
    uint32_t descriptors[3];
    uint32_t reserved;
    uint32_t duplicate[2];
    uint32_t out_of_range[2];
    uint32_t wrong_state[2];
    uint64_t flags;

    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, TEST_FD_LIMIT) == 0);
    flags = kernel_fd_table_lock(&runtime);
    assert(kernel_fd_table_publish_batch_locked(
               &runtime, NULL, 0) == 0);
    assert(kernel_fd_table_reserve_batch_locked(
               &runtime, 5, descriptors, 3, &reserved) == 0);
    assert(reserved == 3);

    assert(kernel_fd_table_publish_batch_locked(
               &runtime, NULL, 1) == -EDGE_LINUX_EINVAL);
    for (uint32_t index = 0; index < reserved; ++index) {
        assert(kernel_fd_table_state_locked(
                   &runtime,
                   descriptors[index]) == KERNEL_FD_SLOT_RESERVED);
    }

    duplicate[0] = descriptors[0];
    duplicate[1] = descriptors[0];
    assert(kernel_fd_table_publish_batch_locked(
               &runtime, duplicate, 2) == -EDGE_LINUX_EINVAL);
    for (uint32_t index = 0; index < reserved; ++index) {
        assert(kernel_fd_table_state_locked(
                   &runtime,
                   descriptors[index]) == KERNEL_FD_SLOT_RESERVED);
    }

    out_of_range[0] = descriptors[0];
    out_of_range[1] = TEST_FD_LIMIT;
    assert(kernel_fd_table_publish_batch_locked(
               &runtime, out_of_range, 2) == -EDGE_LINUX_EBADF);
    for (uint32_t index = 0; index < reserved; ++index) {
        assert(kernel_fd_table_state_locked(
                   &runtime,
                   descriptors[index]) == KERNEL_FD_SLOT_RESERVED);
    }

    assert(kernel_fd_table_publish_locked(
               &runtime, descriptors[2]) == 0);
    wrong_state[0] = descriptors[0];
    wrong_state[1] = descriptors[2];
    assert(kernel_fd_table_publish_batch_locked(
               &runtime, wrong_state, 2) == -EDGE_LINUX_EINVAL);
    assert(kernel_fd_table_state_locked(
               &runtime,
               descriptors[0]) == KERNEL_FD_SLOT_RESERVED);
    assert(kernel_fd_table_state_locked(
               &runtime,
               descriptors[1]) == KERNEL_FD_SLOT_RESERVED);
    assert(kernel_fd_table_state_locked(
               &runtime,
               descriptors[2]) == KERNEL_FD_SLOT_OPEN);

    assert(kernel_fd_table_publish_batch_locked(
               &runtime, descriptors, 2) == 0);
    for (uint32_t index = 0; index < reserved; ++index) {
        assert(kernel_fd_table_begin_close_locked(
                   &runtime, descriptors[index]) == 0);
        assert(kernel_fd_table_complete_close_locked(
                   &runtime, descriptors[index]) == 0);
    }
    kernel_fd_table_unlock(&runtime, flags);

    for (uint32_t descriptor = 0;
         descriptor < TEST_FD_LIMIT; ++descriptor)
        assert(states[descriptor] == KERNEL_FD_SLOT_FREE);
}

static void test_batch_cancel_is_atomic(void) {
    kernel_fd_table_runtime_t runtime;
    uint8_t states[TEST_FD_LIMIT] = { 0 };
    uint32_t descriptors[3];
    uint32_t reserved;
    uint32_t duplicate[2];
    uint32_t out_of_range[2];
    uint32_t wrong_state[2];
    uint32_t valid[2];
    uint64_t flags;

    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, TEST_FD_LIMIT) == 0);
    flags = kernel_fd_table_lock(&runtime);
    assert(kernel_fd_table_cancel_batch_locked(
               &runtime, NULL, 0) == 0);
    assert(kernel_fd_table_reserve_batch_locked(
               &runtime, 9, descriptors, 3, &reserved) == 0);
    assert(reserved == 3);

    assert(kernel_fd_table_cancel_batch_locked(
               &runtime, NULL, 1) == -EDGE_LINUX_EINVAL);
    for (uint32_t index = 0; index < reserved; ++index) {
        assert(kernel_fd_table_state_locked(
                   &runtime,
                   descriptors[index]) == KERNEL_FD_SLOT_RESERVED);
    }

    duplicate[0] = descriptors[0];
    duplicate[1] = descriptors[0];
    assert(kernel_fd_table_cancel_batch_locked(
               &runtime, duplicate, 2) == -EDGE_LINUX_EINVAL);
    for (uint32_t index = 0; index < reserved; ++index) {
        assert(kernel_fd_table_state_locked(
                   &runtime,
                   descriptors[index]) == KERNEL_FD_SLOT_RESERVED);
    }

    out_of_range[0] = descriptors[0];
    out_of_range[1] = TEST_FD_LIMIT;
    assert(kernel_fd_table_cancel_batch_locked(
               &runtime, out_of_range, 2) == -EDGE_LINUX_EBADF);
    for (uint32_t index = 0; index < reserved; ++index) {
        assert(kernel_fd_table_state_locked(
                   &runtime,
                   descriptors[index]) == KERNEL_FD_SLOT_RESERVED);
    }

    assert(kernel_fd_table_publish_locked(
               &runtime, descriptors[1]) == 0);
    wrong_state[0] = descriptors[0];
    wrong_state[1] = descriptors[1];
    assert(kernel_fd_table_cancel_batch_locked(
               &runtime, wrong_state, 2) == -EDGE_LINUX_EINVAL);
    assert(kernel_fd_table_state_locked(
               &runtime,
               descriptors[0]) == KERNEL_FD_SLOT_RESERVED);
    assert(kernel_fd_table_state_locked(
               &runtime,
               descriptors[1]) == KERNEL_FD_SLOT_OPEN);
    assert(kernel_fd_table_state_locked(
               &runtime,
               descriptors[2]) == KERNEL_FD_SLOT_RESERVED);

    valid[0] = descriptors[2];
    valid[1] = descriptors[0];
    assert(kernel_fd_table_cancel_batch_locked(
               &runtime, valid, 2) == 0);
    assert(kernel_fd_table_begin_close_locked(
               &runtime, descriptors[1]) == 0);
    assert(kernel_fd_table_complete_close_locked(
               &runtime, descriptors[1]) == 0);
    kernel_fd_table_unlock(&runtime, flags);

    for (uint32_t descriptor = 0;
         descriptor < TEST_FD_LIMIT; ++descriptor)
        assert(states[descriptor] == KERNEL_FD_SLOT_FREE);
}

static void test_batch_begin_cancel_is_atomic(void) {
    kernel_fd_table_runtime_t runtime;
    uint8_t states[TEST_FD_LIMIT] = { 0 };
    uint32_t descriptors[3];
    uint32_t duplicate[2];
    uint32_t wrong_state[2];
    uint32_t reserved;
    uint64_t flags;

    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, TEST_FD_LIMIT) == 0);
    flags = kernel_fd_table_lock(&runtime);
    assert(kernel_fd_table_begin_cancel_batch_locked(
               &runtime, NULL, 0) == 0);
    assert(kernel_fd_table_reserve_batch_locked(
               &runtime, 12, descriptors, 3, &reserved) == 0);
    assert(reserved == 3);

    duplicate[0] = descriptors[0];
    duplicate[1] = descriptors[0];
    assert(kernel_fd_table_begin_cancel_batch_locked(
               &runtime, duplicate, 2) ==
           -EDGE_LINUX_EINVAL);
    for (uint32_t index = 0; index < reserved; ++index)
        assert(kernel_fd_table_state_locked(
                   &runtime, descriptors[index]) ==
               KERNEL_FD_SLOT_RESERVED);

    assert(kernel_fd_table_publish_locked(
               &runtime, descriptors[2]) == 0);
    wrong_state[0] = descriptors[0];
    wrong_state[1] = descriptors[2];
    assert(kernel_fd_table_begin_cancel_batch_locked(
               &runtime, wrong_state, 2) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_table_state_locked(
               &runtime, descriptors[0]) ==
           KERNEL_FD_SLOT_RESERVED);
    assert(kernel_fd_table_state_locked(
               &runtime, descriptors[1]) ==
           KERNEL_FD_SLOT_RESERVED);

    assert(kernel_fd_table_begin_cancel_batch_locked(
               &runtime, descriptors, 2) == 0);
    assert(kernel_fd_table_state_locked(
               &runtime, descriptors[0]) ==
           KERNEL_FD_SLOT_CLOSING);
    assert(kernel_fd_table_state_locked(
               &runtime, descriptors[1]) ==
           KERNEL_FD_SLOT_CLOSING);
    assert(kernel_fd_table_reserve_exact_locked(
               &runtime, descriptors[0]) ==
           -EDGE_LINUX_EBUSY);
    assert(kernel_fd_table_complete_close_locked(
               &runtime, descriptors[0]) == 0);
    assert(kernel_fd_table_complete_close_locked(
               &runtime, descriptors[1]) == 0);
    assert(kernel_fd_table_begin_close_locked(
               &runtime, descriptors[2]) == 0);
    assert(kernel_fd_table_complete_close_locked(
               &runtime, descriptors[2]) == 0);
    kernel_fd_table_unlock(&runtime, flags);
}

static void test_concurrent_reservations(void) {
    kernel_fd_table_runtime_t runtime;
    uint8_t states[TEST_FD_LIMIT] = { 0 };
    atomic_uint owners[TEST_FD_LIMIT];
    fd_table_test_context_t context;
    pthread_t threads[TEST_THREAD_COUNT];
    uint64_t flags;

    for (uint32_t index = 0; index < TEST_FD_LIMIT; ++index)
        atomic_init(&owners[index], 0u);
    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, TEST_FD_LIMIT) == 0);
    context.runtime = &runtime;
    context.owners = owners;
    for (uint32_t index = 0;
         index < TEST_THREAD_COUNT; ++index)
        assert(pthread_create(
                   &threads[index], 0, fd_table_worker,
                   &context) == 0);
    for (uint32_t index = 0;
         index < TEST_THREAD_COUNT; ++index)
        assert(pthread_join(threads[index], 0) == 0);

    flags = kernel_fd_table_lock(&runtime);
    for (uint32_t descriptor = 0;
         descriptor < TEST_FD_LIMIT; ++descriptor) {
        assert(kernel_fd_table_state_locked(
                   &runtime, descriptor) == KERNEL_FD_SLOT_FREE);
        assert(atomic_load_explicit(
                   &owners[descriptor],
                   memory_order_acquire) == 0u);
    }
    kernel_fd_table_unlock(&runtime, flags);
}

static void test_concurrent_batch_reservations(void) {
    kernel_fd_table_runtime_t runtime;
    uint8_t states[TEST_FD_LIMIT] = { 0 };
    atomic_uint owners[TEST_FD_LIMIT];
    fd_table_test_context_t context;
    pthread_t threads[TEST_THREAD_COUNT];
    uint64_t flags;

    for (uint32_t index = 0; index < TEST_FD_LIMIT; ++index)
        atomic_init(&owners[index], 0u);
    assert(kernel_fd_table_runtime_initialize(
               &runtime, states, TEST_FD_LIMIT) == 0);
    context.runtime = &runtime;
    context.owners = owners;
    for (uint32_t index = 0;
         index < TEST_THREAD_COUNT; ++index)
        assert(pthread_create(
                   &threads[index], 0, fd_table_batch_worker,
                   &context) == 0);
    for (uint32_t index = 0;
         index < TEST_THREAD_COUNT; ++index)
        assert(pthread_join(threads[index], 0) == 0);

    flags = kernel_fd_table_lock(&runtime);
    for (uint32_t descriptor = 0;
         descriptor < TEST_FD_LIMIT; ++descriptor) {
        assert(kernel_fd_table_state_locked(
                   &runtime, descriptor) == KERNEL_FD_SLOT_FREE);
        assert(atomic_load_explicit(
                   &owners[descriptor],
                   memory_order_acquire) == 0u);
    }
    kernel_fd_table_unlock(&runtime, flags);
}

int main(void) {
    test_state_machine();
    test_batch_reserve_semantics();
    test_allocation_limit();
    test_allocated_limit_tracking();
    test_batch_publish_is_atomic();
    test_batch_cancel_is_atomic();
    test_batch_begin_cancel_is_atomic();
    test_concurrent_reservations();
    test_concurrent_batch_reservations();
    puts("FD_TABLE_RUNTIME_UNIT_PASS");
    return 0;
}
