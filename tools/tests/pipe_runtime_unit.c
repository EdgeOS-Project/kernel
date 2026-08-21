/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side regression tests for the shared EdgeOS pipe ring core. */

#include "kernel/pipe_runtime.h"
#include "kernel/linux_errno.h"
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct copy_fault_context {
    uint64_t fail_at;
} copy_fault_context_t;

typedef struct endpoint_stress_context {
    kernel_pipe_runtime_t *pipe;
    volatile uint32_t *start;
    int reader;
    int writer;
} endpoint_stress_context_t;

static void *endpoint_stress_worker(void *opaque) {
    endpoint_stress_context_t *context = opaque;

    while (!__atomic_load_n(context->start, __ATOMIC_ACQUIRE)) {
    }
    for (uint32_t iteration = 0; iteration < 50000u; ++iteration) {
        assert(kernel_pipe_endpoint_retain(
                   context->pipe, context->reader, context->writer) == 0);
        assert(kernel_pipe_endpoint_drop(
                   context->pipe, context->reader, context->writer,
                   0, 0, 0) == 0);
    }
    return 0;
}

static int test_copy_to_user(void *opaque, uint64_t destination,
                             const void *source, uint64_t size) {
    copy_fault_context_t *context = opaque;
    if (destination >= context->fail_at ||
        size > context->fail_at - destination)
        return -1;
    memcpy((void *)(uintptr_t)destination, source, (size_t)size);
    return 0;
}

static int test_copy_from_user(void *opaque, void *destination,
                               uint64_t source, uint64_t size) {
    copy_fault_context_t *context = opaque;
    if (source >= context->fail_at || size > context->fail_at - source)
        return -1;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)size);
    return 0;
}

static void test_wraparound(void) {
    kernel_pipe_runtime_t pipe;
    uint8_t first[60000];
    uint8_t second[20000];
    uint8_t output[50000];
    uint32_t index;

    kernel_pipe_object_initialize(&pipe);
    for (index = 0; index < sizeof(first); ++index)
        first[index] = (uint8_t)(index * 17u + 3u);
    for (index = 0; index < sizeof(second); ++index)
        second[index] = (uint8_t)(index * 29u + 7u);

    assert(kernel_pipe_write_kernel(&pipe, first, sizeof(first)) ==
           sizeof(first));
    assert(kernel_pipe_read_kernel(&pipe, output, 50000) == 50000);
    assert(memcmp(output, first, 50000) == 0);
    assert(kernel_pipe_write_kernel(&pipe, second, sizeof(second)) ==
           sizeof(second));
    assert(pipe.count == 30000);
    assert(kernel_pipe_read_kernel(&pipe, output, 30000) == 30000);
    assert(memcmp(output, first + 50000, 10000) == 0);
    assert(memcmp(output + 10000, second, sizeof(second)) == 0);
    assert(pipe.count == 0);
}

static void test_copy_fault_commit_order(void) {
    kernel_pipe_runtime_t pipe;
    copy_fault_context_t context;
    uint8_t input[32];
    uint8_t output[32];
    int64_t result;

    memset(input, 0x5a, sizeof(input));
    memset(output, 0, sizeof(output));
    kernel_pipe_object_initialize(&pipe);

    context.fail_at = (uint64_t)(uintptr_t)input + 16u;
    result = kernel_pipe_write_user(
        &pipe, (uint64_t)(uintptr_t)input, sizeof(input),
        test_copy_from_user, &context);
    assert(result < 0);
    assert(pipe.count == 0);
    assert(pipe.write_position == 0);

    assert(kernel_pipe_write_kernel(&pipe, input, sizeof(input)) ==
           sizeof(input));
    context.fail_at = (uint64_t)(uintptr_t)output + 16u;
    result = kernel_pipe_read_user(
        &pipe, (uint64_t)(uintptr_t)output, sizeof(output),
        test_copy_to_user, &context);
    assert(result < 0);
    assert(pipe.count == sizeof(input));
    assert(pipe.read_position == 0);
}

static void test_endpoint_lifetime(void) {
    kernel_pipe_runtime_t pipes[2];
    int index;

    memset(pipes, 0, sizeof(pipes));
    index = kernel_pipe_object_allocate(pipes, 2);
    assert(index == 0);
    assert(kernel_pipe_endpoint_retain(&pipes[index], 1, 1) == 0);
    assert(kernel_pipe_endpoint_drop(
               &pipes[index], 1, 0, 0, 0, (uint32_t)index) == 0);
    assert(kernel_pipe_object_release_if_unused(&pipes[index]) == 0);
    assert(kernel_pipe_endpoint_drop(
               &pipes[index], 0, 1, 0, 0, (uint32_t)index) == 0);
    assert(kernel_pipe_object_release_if_unused(&pipes[index]) == 1);
    assert(!pipes[index].used);
}

static void test_concurrent_endpoint_lifetime(void) {
    enum { WORKER_COUNT = 8 };
    kernel_pipe_runtime_t pipe;
    endpoint_stress_context_t contexts[WORKER_COUNT];
    pthread_t workers[WORKER_COUNT];
    volatile uint32_t start = 0;

    kernel_pipe_object_initialize(&pipe);
    assert(kernel_pipe_endpoint_retain(&pipe, 1, 1) == 0);
    for (int index = 0; index < WORKER_COUNT; ++index) {
        contexts[index].pipe = &pipe;
        contexts[index].start = &start;
        contexts[index].reader = (index & 1) == 0;
        contexts[index].writer = (index & 1) != 0;
        assert(pthread_create(
                   &workers[index], 0, endpoint_stress_worker,
                   &contexts[index]) == 0);
    }
    __atomic_store_n(&start, 1u, __ATOMIC_RELEASE);
    for (int index = 0; index < WORKER_COUNT; ++index)
        assert(pthread_join(workers[index], 0) == 0);
    assert(pipe.readers == 1u);
    assert(pipe.writers == 1u);
    assert(kernel_pipe_endpoint_drop(&pipe, 1, 1, 0, 0, 0) == 0);
    assert(kernel_pipe_object_release_if_unused(&pipe) == 1);
}

static void test_metadata_lifetime(void) {
    kernel_pipe_runtime_t pipe;
    kernel_pipe_metadata_t metadata;

    kernel_pipe_object_initialize(&pipe);
    assert(kernel_pipe_metadata_snapshot(&pipe, &metadata) == 0);
    assert(metadata.uid == 0u);
    assert(metadata.gid == 0u);
    assert(metadata.mode == 0600u);

    kernel_pipe_metadata_initialize(&pipe, 1000u, 1001u, 0640u);
    assert(kernel_pipe_metadata_snapshot(&pipe, &metadata) == 0);
    assert(metadata.uid == 1000u);
    assert(metadata.gid == 1001u);
    assert(metadata.mode == 0640u);

    assert(kernel_pipe_metadata_chown(&pipe, UINT32_MAX, 2000u) == 0);
    assert(kernel_pipe_metadata_snapshot(&pipe, &metadata) == 0);
    assert(metadata.uid == 1000u);
    assert(metadata.gid == 2000u);
    assert(metadata.mode == 0640u);
}

static void test_io_decisions(void) {
    kernel_pipe_runtime_t pipe;

    kernel_pipe_object_initialize(&pipe);
    assert(kernel_pipe_endpoint_retain(&pipe, 1, 1) == 0);
    assert(kernel_pipe_read_decide(&pipe, 0) == KERNEL_PIPE_IO_WAIT);
    assert(kernel_pipe_read_decide(&pipe, 1) ==
           KERNEL_PIPE_IO_WOULD_BLOCK);
    assert(kernel_pipe_write_decide(&pipe, 4096, 1, 0) ==
           KERNEL_PIPE_IO_READY);

    pipe.count = KERNEL_PIPE_RUNTIME_CAPACITY - 2048;
    assert(kernel_pipe_write_decide(&pipe, 4096, 1, 0) ==
           KERNEL_PIPE_IO_WAIT);
    assert(kernel_pipe_write_decide(&pipe, 4096, 1, 1) ==
           KERNEL_PIPE_IO_WOULD_BLOCK);
    assert(kernel_pipe_write_decide(&pipe, 4096, 0, 0) ==
           KERNEL_PIPE_IO_READY);

    pipe.count = 0;
    pipe.writers = 0;
    assert(kernel_pipe_read_decide(&pipe, 0) == KERNEL_PIPE_IO_COMPLETE);
    pipe.readers = 0;
    assert(kernel_pipe_write_decide(&pipe, 1, 1, 0) ==
           KERNEL_PIPE_IO_BROKEN);
}

static void test_poll_and_wake_policy(void) {
    kernel_pipe_runtime_t pipe;
    uint32_t events;

    kernel_pipe_object_initialize(&pipe);
    assert(kernel_pipe_endpoint_retain(&pipe, 1, 1) == 0);
    events = kernel_pipe_poll_events(&pipe, &pipe, 1, 1);
    assert(events == KERNEL_PIPE_POLL_OUT);
    assert(!kernel_pipe_read_wake_ready(&pipe, 0));
    assert(kernel_pipe_write_wake_ready(&pipe));

    assert(kernel_pipe_write_kernel(&pipe, "x", 1) == 1);
    events = kernel_pipe_poll_events(&pipe, &pipe, 1, 1);
    assert((events & (KERNEL_PIPE_POLL_IN | KERNEL_PIPE_POLL_OUT)) ==
           (KERNEL_PIPE_POLL_IN | KERNEL_PIPE_POLL_OUT));
    assert(kernel_pipe_read_wake_ready(&pipe, 0));

    pipe.writers = 0;
    pipe.readers = 0;
    events = kernel_pipe_poll_events(&pipe, &pipe, 1, 1);
    assert(events & KERNEL_PIPE_POLL_HUP);
    assert(events & KERNEL_PIPE_POLL_ERR);
    assert(kernel_pipe_write_wake_ready(&pipe));

    pipe.pending_writers = 1;
    pipe.count = 0;
    pipe.writers = 1;
    assert(!kernel_pipe_read_wake_ready(&pipe, 0));
    assert(kernel_pipe_read_wake_ready(&pipe, 1));
    assert(kernel_pipe_poll_events(0, 0, 1, 1) ==
           KERNEL_PIPE_POLL_NVAL);
}

static void test_readable_byte_query(void) {
    kernel_pipe_runtime_t pipe;

    kernel_pipe_object_initialize(&pipe);
    assert(kernel_pipe_readable_bytes(&pipe) == 0u);
    assert(kernel_pipe_write_kernel(&pipe, "abc", 3u) == 3u);
    assert(kernel_pipe_readable_bytes(&pipe) == 3u);
    pipe.used = 0;
    assert(kernel_pipe_readable_bytes(&pipe) == 0u);
    assert(kernel_pipe_readable_bytes(0) == 0u);
}

static void test_packet_mode(void) {
    kernel_pipe_runtime_t pipe;
    copy_fault_context_t context;
    uint8_t large[KERNEL_PIPE_RUNTIME_BUF + 32u];
    uint8_t output[32];

    memset(large, 0x6b, sizeof(large));
    memset(output, 0, sizeof(output));
    kernel_pipe_object_initialize(&pipe);
    assert(kernel_pipe_packet_mode_set(&pipe, 1) == 0);
    assert(pipe.packet_mode);
    assert(kernel_pipe_endpoint_retain(&pipe, 1, 1) == 0);

    assert(kernel_pipe_write_kernel(&pipe, "abcdef", 6u) == 6u);
    assert(kernel_pipe_write_kernel(&pipe, "WXYZ", 4u) == 4u);
    assert(pipe.packet_count == 2u);
    assert(kernel_pipe_read_kernel(&pipe, output, 3u) == 3u);
    assert(memcmp(output, "abc", 3u) == 0);
    assert(pipe.count == 4u);
    assert(pipe.packet_count == 1u);
    assert(kernel_pipe_read_kernel(&pipe, output, sizeof(output)) == 4u);
    assert(memcmp(output, "WXYZ", 4u) == 0);

    assert(kernel_pipe_write_kernel(&pipe, large, sizeof(large)) ==
           KERNEL_PIPE_RUNTIME_BUF);
    assert(pipe.count == KERNEL_PIPE_RUNTIME_BUF);
    assert(kernel_pipe_read_kernel(&pipe, output, sizeof(output)) ==
           sizeof(output));
    assert(pipe.count == 0u);
    assert(pipe.packet_count == 0u);

    pipe.read_position = KERNEL_PIPE_RUNTIME_CAPACITY - 2u;
    pipe.write_position = KERNEL_PIPE_RUNTIME_CAPACITY - 2u;
    assert(kernel_pipe_write_kernel(&pipe, "wrap", 4u) == 4u);
    assert(kernel_pipe_read_kernel(&pipe, output, 4u) == 4u);
    assert(memcmp(output, "wrap", 4u) == 0);

    assert(kernel_pipe_write_kernel(&pipe, "fault", 5u) == 5u);
    context.fail_at = (uint64_t)(uintptr_t)output;
    assert(kernel_pipe_read_user(
               &pipe, (uint64_t)(uintptr_t)output, sizeof(output),
               test_copy_to_user, &context) == -EDGE_LINUX_EFAULT);
    assert(pipe.count == 5u);
    assert(pipe.packet_count == 1u);
    assert(kernel_pipe_read_kernel(&pipe, output, sizeof(output)) == 5u);

    for (uint32_t index = 0;
         index < KERNEL_PIPE_RUNTIME_PACKET_SLOTS; ++index)
        assert(kernel_pipe_write_kernel(&pipe, "x", 1u) == 1u);
    assert(kernel_pipe_write_kernel(&pipe, "x", 1u) == 0u);
    assert(kernel_pipe_write_decide(&pipe, 1u, 1, 0) ==
           KERNEL_PIPE_IO_WAIT);
    assert(!(kernel_pipe_poll_events(&pipe, &pipe, 0, 1) &
             KERNEL_PIPE_POLL_OUT));
    assert(!kernel_pipe_write_wake_ready(&pipe));
    assert(kernel_pipe_read_kernel(&pipe, output, 1u) == 1u);
    assert(kernel_pipe_write_wake_ready(&pipe));
}

static void test_readiness_sequences(void) {
    kernel_pipe_runtime_t pipe;
    copy_fault_context_t context;
    uint8_t input[16] = {0};
    uint8_t output[16];
    uint64_t read_sequence;
    uint64_t write_sequence;

    kernel_pipe_object_initialize(&pipe);
    assert(pipe.read_ready_sequence != 0);
    assert(pipe.write_ready_sequence != 0);
    assert(kernel_pipe_endpoint_retain(&pipe, 1, 1) == 0);

    read_sequence = pipe.read_ready_sequence;
    write_sequence = pipe.write_ready_sequence;
    assert(kernel_pipe_write_kernel(&pipe, input, sizeof(input)) ==
           sizeof(input));
    assert(pipe.read_ready_sequence == read_sequence + 1u);
    assert(pipe.write_ready_sequence == write_sequence);

    read_sequence = pipe.read_ready_sequence;
    write_sequence = pipe.write_ready_sequence;
    assert(kernel_pipe_read_kernel(&pipe, output, sizeof(output)) ==
           sizeof(output));
    assert(pipe.read_ready_sequence == read_sequence);
    assert(pipe.write_ready_sequence == write_sequence + 1u);

    write_sequence = pipe.write_ready_sequence;
    assert(kernel_pipe_endpoint_drop(&pipe, 1, 0, 0, 0, 0) == 0);
    assert(pipe.write_ready_sequence == write_sequence + 1u);
    read_sequence = pipe.read_ready_sequence;
    assert(kernel_pipe_endpoint_drop(&pipe, 0, 1, 0, 0, 0) == 0);
    assert(pipe.read_ready_sequence == read_sequence + 1u);

    kernel_pipe_object_initialize(&pipe);
    pipe.read_ready_sequence = UINT64_MAX;
    assert(kernel_pipe_write_kernel(&pipe, input, 1) == 1);
    assert(pipe.read_ready_sequence == 1u);
    pipe.write_ready_sequence = UINT64_MAX;
    assert(kernel_pipe_read_kernel(&pipe, output, 1) == 1);
    assert(pipe.write_ready_sequence == 1u);

    kernel_pipe_object_initialize(&pipe);
    context.fail_at = UINT64_MAX;
    read_sequence = pipe.read_ready_sequence;
    assert(kernel_pipe_write_user(
               &pipe, (uint64_t)(uintptr_t)input, sizeof(input),
               test_copy_from_user, &context) == (int64_t)sizeof(input));
    assert(pipe.read_ready_sequence == read_sequence + 1u);
    write_sequence = pipe.write_ready_sequence;
    assert(kernel_pipe_read_user(
               &pipe, (uint64_t)(uintptr_t)output, sizeof(output),
               test_copy_to_user, &context) == (int64_t)sizeof(output));
    assert(pipe.write_ready_sequence == write_sequence + 1u);

    kernel_pipe_object_initialize(&pipe);
    pipe.write_position = KERNEL_PIPE_RUNTIME_CAPACITY - 8u;
    context.fail_at = (uint64_t)(uintptr_t)input + 8u;
    read_sequence = pipe.read_ready_sequence;
    assert(kernel_pipe_write_user(
               &pipe, (uint64_t)(uintptr_t)input, sizeof(input),
               test_copy_from_user, &context) == 8);
    assert(pipe.count == 8u);
    assert(pipe.read_ready_sequence == read_sequence + 1u);
}

int main(void) {
    test_wraparound();
    test_copy_fault_commit_order();
    test_endpoint_lifetime();
    test_concurrent_endpoint_lifetime();
    test_metadata_lifetime();
    test_io_decisions();
    test_poll_and_wake_policy();
    test_readable_byte_query();
    test_packet_mode();
    test_readiness_sequences();
    puts("pipe_runtime_unit: PASS");
    return 0;
}
