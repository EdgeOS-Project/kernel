/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include "kernel/fd_table_runtime.h"
#include "kernel/linux_errno.h"

#define KERNEL_FD_TABLE_INITIAL_ALLOCATION 64u

static int fd_table_runtime_valid(
    const kernel_fd_table_runtime_t *runtime) {
    return runtime && runtime->states && runtime->limit &&
        runtime->allocated_limit &&
        runtime->allocated_limit <= runtime->limit;
}

static void fd_table_grow_allocation_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    uint32_t allocated_limit;

    if (!runtime || descriptor >= runtime->limit)
        return;
    allocated_limit = runtime->allocated_limit;
    while (descriptor >= allocated_limit) {
        if (allocated_limit > runtime->limit / 2u) {
            allocated_limit = runtime->limit;
            break;
        }
        allocated_limit *= 2u;
    }
    runtime->allocated_limit = allocated_limit;
}

static int fd_table_descriptor_valid(
    const kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    return fd_table_runtime_valid(runtime) &&
        descriptor < runtime->limit;
}

static int fd_table_reserved_batch_valid(
    const kernel_fd_table_runtime_t *runtime,
    const uint32_t *descriptors,
    uint32_t count) {
    if (!fd_table_runtime_valid(runtime))
        return -EDGE_LINUX_EINVAL;
    if (!count)
        return 0;
    if (!descriptors)
        return -EDGE_LINUX_EINVAL;

    for (uint32_t index = 0; index < count; ++index) {
        uint32_t descriptor = descriptors[index];

        if (!fd_table_descriptor_valid(runtime, descriptor))
            return -EDGE_LINUX_EBADF;
        if (runtime->states[descriptor] != KERNEL_FD_SLOT_RESERVED)
            return -EDGE_LINUX_EINVAL;
        /*
         * Validation cannot borrow slot states as scratch without weakening
         * the no-mutation-on-error contract.  Descriptor batches are bounded
         * by the table limit, so a lock-local comparison is deterministic and
         * requires no allocation.
         */
        for (uint32_t previous = 0;
             previous < index; ++previous) {
            if (descriptors[previous] == descriptor)
                return -EDGE_LINUX_EINVAL;
        }
    }
    return 0;
}

int kernel_fd_table_runtime_initialize(
    kernel_fd_table_runtime_t *runtime,
    uint8_t *states,
    uint32_t limit) {
    if (!runtime || !states || !limit)
        return -EDGE_LINUX_EINVAL;
    spinlock_init(&runtime->lock);
    runtime->owner_site = 0u;
    runtime->states = states;
    runtime->limit = limit;
    runtime->allocated_limit =
        limit < KERNEL_FD_TABLE_INITIAL_ALLOCATION ?
        limit : KERNEL_FD_TABLE_INITIAL_ALLOCATION;
    for (uint32_t descriptor = 0; descriptor < limit; ++descriptor) {
        if (states[descriptor] != KERNEL_FD_SLOT_FREE)
            fd_table_grow_allocation_locked(runtime, descriptor);
    }
    return 0;
}

uint32_t kernel_fd_table_allocated_limit_locked(
    const kernel_fd_table_runtime_t *runtime) {
    return fd_table_runtime_valid(runtime) ?
        runtime->allocated_limit : 0u;
}

int kernel_fd_table_inherit_allocated_limit_locked(
    kernel_fd_table_runtime_t *destination,
    const kernel_fd_table_runtime_t *source) {
    uint32_t inherited_limit;

    if (!fd_table_runtime_valid(destination) ||
        !fd_table_runtime_valid(source))
        return -EDGE_LINUX_EINVAL;
    inherited_limit = source->allocated_limit;
    if (inherited_limit > destination->limit)
        inherited_limit = destination->limit;
    if (destination->allocated_limit < inherited_limit)
        destination->allocated_limit = inherited_limit;
    return 0;
}

uint64_t kernel_fd_table_lock(kernel_fd_table_runtime_t *runtime) {
    uint64_t irq_flags;

    if (!fd_table_runtime_valid(runtime)) return 0;
    irq_flags = spin_lock_irqsave(&runtime->lock);
    __atomic_store_n(
        &runtime->owner_site,
        (uintptr_t)__builtin_return_address(0), __ATOMIC_RELEASE);
    return irq_flags;
}

void kernel_fd_table_unlock(kernel_fd_table_runtime_t *runtime,
                            uint64_t irq_flags) {
    if (!fd_table_runtime_valid(runtime)) return;
    __atomic_store_n(&runtime->owner_site, 0u, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&runtime->lock, irq_flags);
}

kernel_fd_slot_state_t kernel_fd_table_state_locked(
    const kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    uint8_t state;

    if (!fd_table_descriptor_valid(runtime, descriptor))
        return KERNEL_FD_SLOT_FREE;
    state = runtime->states[descriptor];
    if (state > KERNEL_FD_SLOT_CLOSING)
        return KERNEL_FD_SLOT_FREE;
    return (kernel_fd_slot_state_t)state;
}

int kernel_fd_table_is_open_locked(
    const kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    return kernel_fd_table_state_locked(runtime, descriptor) ==
        KERNEL_FD_SLOT_OPEN;
}

int kernel_fd_table_reserve_next_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t minimum,
    uint32_t *descriptor) {
    return kernel_fd_table_reserve_next_below_locked(
        runtime, minimum, runtime ? runtime->limit : 0u,
        descriptor);
}

int kernel_fd_table_reserve_next_below_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t minimum,
    uint32_t exclusive_limit,
    uint32_t *descriptor) {
    if (!descriptor || !fd_table_runtime_valid(runtime))
        return -EDGE_LINUX_EINVAL;
    if (exclusive_limit > runtime->limit)
        exclusive_limit = runtime->limit;
    if (minimum >= exclusive_limit)
        return -EDGE_LINUX_EMFILE;
    for (uint32_t candidate = minimum;
         candidate < exclusive_limit; ++candidate) {
        if (runtime->states[candidate] != KERNEL_FD_SLOT_FREE)
            continue;
        runtime->states[candidate] = KERNEL_FD_SLOT_RESERVED;
        fd_table_grow_allocation_locked(runtime, candidate);
        *descriptor = candidate;
        return 0;
    }
    return -EDGE_LINUX_EMFILE;
}

int kernel_fd_table_reserve_batch_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t minimum,
    uint32_t *descriptors,
    uint32_t requested,
    uint32_t *reserved) {
    return kernel_fd_table_reserve_batch_below_locked(
        runtime, minimum, runtime ? runtime->limit : 0u,
        descriptors, requested, reserved);
}

int kernel_fd_table_reserve_batch_below_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t minimum,
    uint32_t exclusive_limit,
    uint32_t *descriptors,
    uint32_t requested,
    uint32_t *reserved) {
    uint32_t count = 0;

    if (!fd_table_runtime_valid(runtime) || !reserved)
        return -EDGE_LINUX_EINVAL;
    *reserved = 0;
    if (!requested)
        return 0;
    if (!descriptors)
        return -EDGE_LINUX_EINVAL;
    if (exclusive_limit > runtime->limit)
        exclusive_limit = runtime->limit;
    if (minimum >= exclusive_limit)
        return -EDGE_LINUX_EMFILE;

    for (uint32_t candidate = minimum;
         candidate < exclusive_limit && count < requested;
         ++candidate) {
        if (runtime->states[candidate] != KERNEL_FD_SLOT_FREE)
            continue;
        runtime->states[candidate] = KERNEL_FD_SLOT_RESERVED;
        fd_table_grow_allocation_locked(runtime, candidate);
        descriptors[count++] = candidate;
    }
    *reserved = count;
    return count ? 0 : -EDGE_LINUX_EMFILE;
}

int kernel_fd_table_publish_batch_locked(
    kernel_fd_table_runtime_t *runtime,
    const uint32_t *descriptors,
    uint32_t count) {
    int result = fd_table_reserved_batch_valid(
        runtime, descriptors, count);

    if (result < 0)
        return result;
    for (uint32_t index = 0; index < count; ++index)
        runtime->states[descriptors[index]] = KERNEL_FD_SLOT_OPEN;
    return 0;
}

int kernel_fd_table_cancel_batch_locked(
    kernel_fd_table_runtime_t *runtime,
    const uint32_t *descriptors,
    uint32_t count) {
    int result = fd_table_reserved_batch_valid(
        runtime, descriptors, count);

    if (result < 0)
        return result;
    for (uint32_t index = 0; index < count; ++index)
        runtime->states[descriptors[index]] = KERNEL_FD_SLOT_FREE;
    return 0;
}

int kernel_fd_table_begin_cancel_batch_locked(
    kernel_fd_table_runtime_t *runtime,
    const uint32_t *descriptors,
    uint32_t count) {
    int result = fd_table_reserved_batch_valid(
        runtime, descriptors, count);

    if (result < 0)
        return result;
    for (uint32_t index = 0; index < count; ++index)
        runtime->states[descriptors[index]] =
            KERNEL_FD_SLOT_CLOSING;
    return 0;
}

int kernel_fd_table_reserve_exact_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    if (!fd_table_descriptor_valid(runtime, descriptor))
        return -EDGE_LINUX_EBADF;
    if (runtime->states[descriptor] != KERNEL_FD_SLOT_FREE)
        return -EDGE_LINUX_EBUSY;
    runtime->states[descriptor] = KERNEL_FD_SLOT_RESERVED;
    fd_table_grow_allocation_locked(runtime, descriptor);
    return 0;
}

int kernel_fd_table_publish_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    if (!fd_table_descriptor_valid(runtime, descriptor))
        return -EDGE_LINUX_EBADF;
    if (runtime->states[descriptor] != KERNEL_FD_SLOT_RESERVED)
        return -EDGE_LINUX_EINVAL;
    runtime->states[descriptor] = KERNEL_FD_SLOT_OPEN;
    return 0;
}

int kernel_fd_table_publish_pair_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t first,
    uint32_t second) {
    if (!fd_table_descriptor_valid(runtime, first) ||
        !fd_table_descriptor_valid(runtime, second) ||
        first == second)
        return -EDGE_LINUX_EBADF;
    if (runtime->states[first] != KERNEL_FD_SLOT_RESERVED ||
        runtime->states[second] != KERNEL_FD_SLOT_RESERVED)
        return -EDGE_LINUX_EINVAL;
    runtime->states[first] = KERNEL_FD_SLOT_OPEN;
    runtime->states[second] = KERNEL_FD_SLOT_OPEN;
    return 0;
}

int kernel_fd_table_cancel_reservation_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    if (!fd_table_descriptor_valid(runtime, descriptor))
        return -EDGE_LINUX_EBADF;
    if (runtime->states[descriptor] != KERNEL_FD_SLOT_RESERVED)
        return -EDGE_LINUX_EINVAL;
    runtime->states[descriptor] = KERNEL_FD_SLOT_FREE;
    return 0;
}

int kernel_fd_table_begin_close_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    if (!fd_table_descriptor_valid(runtime, descriptor))
        return -EDGE_LINUX_EBADF;
    if (runtime->states[descriptor] != KERNEL_FD_SLOT_OPEN)
        return -EDGE_LINUX_EBADF;
    runtime->states[descriptor] = KERNEL_FD_SLOT_CLOSING;
    return 0;
}

int kernel_fd_table_detach_open_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    int result = kernel_fd_table_begin_close_locked(
        runtime, descriptor);

    if (result < 0) return result;
    return kernel_fd_table_complete_close_locked(
        runtime, descriptor);
}

int kernel_fd_table_complete_close_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    if (!fd_table_descriptor_valid(runtime, descriptor))
        return -EDGE_LINUX_EBADF;
    if (runtime->states[descriptor] != KERNEL_FD_SLOT_CLOSING)
        return -EDGE_LINUX_EINVAL;
    runtime->states[descriptor] = KERNEL_FD_SLOT_FREE;
    return 0;
}

int kernel_fd_table_restore_open_locked(
    kernel_fd_table_runtime_t *runtime,
    uint32_t descriptor) {
    if (!fd_table_descriptor_valid(runtime, descriptor))
        return -EDGE_LINUX_EBADF;
    if (runtime->states[descriptor] != KERNEL_FD_SLOT_CLOSING)
        return -EDGE_LINUX_EINVAL;
    runtime->states[descriptor] = KERNEL_FD_SLOT_OPEN;
    return 0;
}
