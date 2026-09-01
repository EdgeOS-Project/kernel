/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Host-side regression tests for shared Linux eventfd I/O policy.
 */

#include "kernel/eventfd.h"
#include "kernel/linux_errno.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

typedef struct eventfd_copy_context {
    uint64_t supplied;
    uint64_t received;
    int load_calls;
    int store_calls;
    int fail_load;
    int fail_store;
} eventfd_copy_context_t;

typedef struct eventfd_state_context {
    int calls;
    int last_event_id;
} eventfd_state_context_t;

static void state_changed(void *opaque, int event_id) {
    eventfd_state_context_t *context = opaque;

    ++context->calls;
    context->last_event_id = event_id;
}

static int load_value(void *opaque, uint64_t *value) {
    eventfd_copy_context_t *context = opaque;
    ++context->load_calls;
    if (context->fail_load) return -1;
    *value = context->supplied;
    return 0;
}

static int store_value(void *opaque, uint64_t value) {
    eventfd_copy_context_t *context = opaque;
    ++context->store_calls;
    if (context->fail_store) return -1;
    context->received = value;
    return 0;
}

static void reset_copy_context(eventfd_copy_context_t *context) {
    context->supplied = 0;
    context->received = 0;
    context->load_calls = 0;
    context->store_calls = 0;
    context->fail_load = 0;
    context->fail_store = 0;
}

static void test_count_and_wait_policy(void) {
    eventfd_copy_context_t context;
    kernel_eventfd_state_t state;
    uint64_t value = 0;
    int event_id = kernel_eventfd_create(0, 0);

    assert(event_id >= 0);
    reset_copy_context(&context);
    assert(kernel_eventfd_read_io(
               event_id, 7, 0, store_value, &context, &value) ==
           -EDGE_LINUX_EINVAL);
    assert(context.store_calls == 0);
    assert(kernel_eventfd_read_io(
               event_id, 16, 1, store_value, &context, &value) ==
           -EDGE_LINUX_EAGAIN);
    assert(context.store_calls == 0);
    assert(kernel_eventfd_read_io(
               event_id, 8, 0, store_value, &context, &value) ==
           KERNEL_EVENTFD_IO_WAIT);

    context.supplied = 5;
    assert(kernel_eventfd_write_io(
               event_id, 7, 0, load_value, &context, &value) ==
           -EDGE_LINUX_EINVAL);
    assert(context.load_calls == 0);
    assert(kernel_eventfd_write_io(
               event_id, 16, 0, load_value, &context, &value) ==
           -EDGE_LINUX_EINVAL);
    assert(context.load_calls == 0);
    assert(kernel_eventfd_write_io(
               event_id, 8, 0, load_value, &context, &value) ==
           KERNEL_EVENTFD_IO_BYTES);
    assert(context.load_calls == 1);
    assert(value == 5);
    assert(kernel_eventfd_query(event_id, &state) == 0);
    assert(state.counter == 5);

    assert(kernel_eventfd_read_io(
               event_id, 16, 0, store_value, &context, &value) ==
           KERNEL_EVENTFD_IO_BYTES);
    assert(value == 5);
    assert(context.received == 5);
    assert(kernel_eventfd_query(event_id, &state) == 0);
    assert(state.counter == 0);
    kernel_eventfd_release(event_id);
}

static void test_copy_fault_ordering(void) {
    eventfd_copy_context_t context;
    kernel_eventfd_state_t state;
    uint64_t value = 0;
    int event_id = kernel_eventfd_create(9, 0);

    assert(event_id >= 0);
    reset_copy_context(&context);
    context.fail_store = 1;
    assert(kernel_eventfd_read_io(
               event_id, 8, 0, store_value, &context, &value) ==
           -EDGE_LINUX_EFAULT);
    assert(context.store_calls == 1);
    assert(value == 9);
    assert(kernel_eventfd_query(event_id, &state) == 0);
    assert(state.counter == 0);

    context.fail_store = 0;
    context.fail_load = 1;
    context.supplied = 4;
    assert(kernel_eventfd_write_io(
               event_id, 8, 0, load_value, &context, &value) ==
           -EDGE_LINUX_EFAULT);
    assert(context.load_calls == 1);
    assert(kernel_eventfd_query(event_id, &state) == 0);
    assert(state.counter == 0);
    kernel_eventfd_release(event_id);
}

static void test_counter_and_semaphore_policy(void) {
    eventfd_copy_context_t context;
    kernel_eventfd_state_t state;
    uint64_t value = 0;
    int event_id = kernel_eventfd_create(2, 1);

    assert(event_id >= 0);
    reset_copy_context(&context);
    assert(kernel_eventfd_read_io(
               event_id, 8, 1, store_value, &context, &value) ==
           KERNEL_EVENTFD_IO_BYTES);
    assert(value == 1);
    assert(kernel_eventfd_read_io(
               event_id, 8, 1, store_value, &context, &value) ==
           KERNEL_EVENTFD_IO_BYTES);
    assert(value == 1);
    assert(kernel_eventfd_read_io(
               event_id, 8, 1, store_value, &context, &value) ==
           -EDGE_LINUX_EAGAIN);
    kernel_eventfd_release(event_id);

    event_id = kernel_eventfd_create(0, 0);
    assert(event_id >= 0);
    assert(kernel_eventfd_write_value(
               event_id, 0, UINT64_MAX - 1u) ==
           KERNEL_EVENTFD_IO_BYTES);
    assert(kernel_eventfd_query(event_id, &state) == 0);
    assert(state.counter == UINT64_MAX - 1u);
    assert(kernel_eventfd_write_value(event_id, 1, 1) ==
           -EDGE_LINUX_EAGAIN);
    assert(kernel_eventfd_write_value(event_id, 0, 1) ==
           KERNEL_EVENTFD_IO_WAIT);
    assert(kernel_eventfd_write_value(event_id, 0, UINT64_MAX) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_eventfd_read_io(
               event_id, 8, 0, store_value, &context, &value) ==
           KERNEL_EVENTFD_IO_BYTES);
    assert(value == UINT64_MAX - 1u);
    assert(kernel_eventfd_write_value(event_id, 0, 1) ==
           KERNEL_EVENTFD_IO_BYTES);
    kernel_eventfd_release(event_id);
}

static void test_lifetime_and_zero_write(void) {
    kernel_eventfd_state_t state;
    int event_id = kernel_eventfd_create(0, 0);

    assert(event_id >= 0);
    assert(kernel_eventfd_retain(event_id) == 0);
    assert(kernel_eventfd_query(event_id, &state) == 0);
    assert(state.references == 2);
    assert(kernel_eventfd_write_value(event_id, 0, 0) ==
           KERNEL_EVENTFD_IO_BYTES);
    assert(kernel_eventfd_query(event_id, &state) == 0);
    assert(state.counter == 0);
    assert(state.write_sequence != 0);
    kernel_eventfd_release(event_id);
    assert(kernel_eventfd_query(event_id, &state) == 0);
    assert(state.references == 1);
    kernel_eventfd_release(event_id);
    assert(kernel_eventfd_query(event_id, &state) ==
           -EDGE_LINUX_EBADF);
}

static void test_state_transition_notifications(void) {
    eventfd_copy_context_t copy_context;
    eventfd_state_context_t state_context = {0, -1};
    kernel_eventfd_state_t state;
    uint64_t value = 0;
    int event_id;

    assert(kernel_eventfd_state_backend_register(
               state_changed, &state_context) == 0);
    event_id = kernel_eventfd_create(0, 0);
    assert(event_id >= 0);
    assert(state_context.calls == 0);
    assert(kernel_eventfd_query(event_id, &state) == 0);
    assert(state_context.calls == 0);
    assert(kernel_eventfd_write_value(event_id, 0, 3) ==
           KERNEL_EVENTFD_IO_BYTES);
    assert(state_context.calls == 1);
    assert(state_context.last_event_id == event_id);
    reset_copy_context(&copy_context);
    assert(kernel_eventfd_read_io(
               event_id, 8, 0, store_value, &copy_context, &value) ==
           KERNEL_EVENTFD_IO_BYTES);
    assert(state_context.calls == 2);
    assert(kernel_eventfd_read_io(
               event_id, 8, 1, store_value, &copy_context, &value) ==
           -EDGE_LINUX_EAGAIN);
    assert(state_context.calls == 2);
    kernel_eventfd_release(event_id);
}

int main(void) {
    test_count_and_wait_policy();
    test_copy_fault_ordering();
    test_counter_and_semaphore_policy();
    test_lifetime_and_zero_write();
    test_state_transition_notifications();
    printf("eventfd_runtime_unit: PASS\n");
    return 0;
}
