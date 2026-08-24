/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for the architecture-independent io_uring core. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/io_uring_runtime.h"
#include "kernel/anonymous_fd.h"
#include "kernel/fd_runtime.h"
#include "kernel/event_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"

#define TEST_PAGE_COUNT 16u

static uint8_t g_pages[TEST_PAGE_COUNT][KERNEL_IO_URING_PAGE_SIZE]
    __attribute__((aligned(KERNEL_IO_URING_PAGE_SIZE)));
static uint32_t g_references[TEST_PAGE_COUNT];
static int32_t g_ready_descriptor = -1;
static uint32_t g_ready_generation;
static uint32_t g_descriptor_generation[128];
static uint32_t g_fixed_file_references;
static uint32_t g_materialize_flags;
static uint32_t g_epoll_references;
static int g_epoll_ready;
static kernel_futex_request_t g_futex_request;
static uint64_t g_futex_wait_id;
static uint64_t g_next_futex_wait_id;
static int32_t g_futex_result;
static uint32_t g_futex_cancel_count;
static int g_futex_ready;
static kernel_process_wait_request_t g_process_wait_request;
static kernel_process_wait_result_t g_process_wait_result;
static int32_t g_process_waiter_tid;
static int64_t g_process_wait_status;
static uint32_t g_waitid_copy_count;
static uint8_t g_multishot_read_data[64];
static uint32_t g_multishot_read_length;
static int32_t g_multishot_read_result;

int64_t kernel_process_wait_for_tid(
        const kernel_process_wait_request_t *request,
        kernel_process_wait_result_t *result, int32_t waiter_tid) {
    assert(request);
    assert(result);
    g_process_wait_request = *request;
    g_process_waiter_tid = waiter_tid;
    if (g_process_wait_status > 0)
        *result = g_process_wait_result;
    return g_process_wait_status;
}

static int test_waitid_copy(
        uint64_t address_space, uint64_t user_address,
        const kernel_process_wait_result_t *result,
        int event_present) {
    assert(address_space == 0xabc000u);
    assert(user_address == 0x123000u);
    assert(result);
    assert(event_present == 1);
    assert(result->pid == g_process_wait_result.pid);
    ++g_waitid_copy_count;
    return 0;
}

int kernel_futex_async_wait_add(const kernel_futex_request_t *request,
                                uint64_t *wait_id) {
    if (!request || !wait_id || g_futex_wait_id)
        return -EDGE_LINUX_EINVAL;
    g_futex_request = *request;
    ++g_next_futex_wait_id;
    if (!g_next_futex_wait_id) ++g_next_futex_wait_id;
    g_futex_wait_id = g_next_futex_wait_id;
    *wait_id = g_futex_wait_id;
    return 0;
}

int kernel_futex_async_wait_poll(uint64_t wait_id, int32_t *result) {
    if (!wait_id || wait_id != g_futex_wait_id || !result)
        return -EDGE_LINUX_ENOENT;
    if (!g_futex_ready) return 0;
    *result = g_futex_result;
    g_futex_wait_id = 0u;
    g_futex_ready = 0;
    return 1;
}

int kernel_futex_async_wait_cancel(uint64_t wait_id) {
    if (!wait_id || wait_id != g_futex_wait_id)
        return -EDGE_LINUX_ENOENT;
    g_futex_wait_id = 0u;
    g_futex_ready = 0;
    ++g_futex_cancel_count;
    return 0;
}

int kernel_anonymous_fd_descriptor_object_id(
        int32_t descriptor, kernel_anonymous_fd_kind_t kind) {
    return kind == KERNEL_ANONYMOUS_FD_IO_URING && descriptor == 98 ? 1 : -1;
}

int kernel_fd_operation_acquire(
        int32_t descriptor, kernel_fd_operation_lease_t *lease) {
    if (!lease || descriptor < 0 || descriptor == 99)
        return -EDGE_LINUX_EBADF;
    *(int32_t *)(void *)lease = descriptor + 1;
    ((uint32_t *)(void *)lease)[1] =
        descriptor < 128 ? g_descriptor_generation[descriptor] : 0u;
    ++g_fixed_file_references;
    return 0;
}

int kernel_fd_operation_acquire_from_publication(
        const kernel_fd_publication_t *publication,
        uint32_t index, kernel_fd_operation_lease_t *lease) {
    if (!publication || !publication->active ||
        !publication->descriptors || index >= publication->count || !lease)
        return -EDGE_LINUX_EINVAL;
    *(int32_t *)(void *)lease = publication->descriptors[index] + 1;
    ((uint32_t *)(void *)lease)[1] =
        publication->descriptors[index] >= 0 &&
        publication->descriptors[index] < 128 ?
            g_descriptor_generation[publication->descriptors[index]] : 0u;
    ++g_fixed_file_references;
    return 0;
}

const void *kernel_fd_operation_view(
        const kernel_fd_operation_lease_t *lease) {
    return lease && *(const int32_t *)(const void *)lease > 0 ?
        (const void *)lease : 0;
}

int kernel_fd_operation_description_id(
        const kernel_fd_operation_lease_t *lease,
        uint64_t *description_id) {
    int32_t stored;

    if (!lease || !description_id ||
        (stored = *(const int32_t *)(const void *)lease) <= 0)
        return -EDGE_LINUX_EBADF;
    *description_id = ((uint64_t)(uint32_t)stored << 32u) |
        ((const uint32_t *)(const void *)lease)[1];
    return 0;
}

int kernel_fd_operation_move(
        kernel_fd_operation_lease_t *destination,
        kernel_fd_operation_lease_t *source) {
    if (!destination || !source || destination == source ||
        *(int32_t *)(void *)destination != 0 ||
        *(int32_t *)(void *)source <= 0)
        return -EDGE_LINUX_EINVAL;
    *(int32_t *)(void *)destination = *(int32_t *)(void *)source;
    ((uint32_t *)(void *)destination)[1] =
        ((uint32_t *)(void *)source)[1];
    *(int32_t *)(void *)source = 0;
    ((uint32_t *)(void *)source)[1] = 0u;
    return 0;
}

int kernel_fd_operation_clone(
        kernel_fd_operation_lease_t *destination,
        const kernel_fd_operation_lease_t *source) {
    if (!destination || !source || destination == source ||
        *(int32_t *)(void *)destination != 0 ||
        *(const int32_t *)(const void *)source <= 0)
        return -EDGE_LINUX_EINVAL;
    *(int32_t *)(void *)destination =
        *(const int32_t *)(const void *)source;
    ((uint32_t *)(void *)destination)[1] =
        ((const uint32_t *)(const void *)source)[1];
    ++g_fixed_file_references;
    return 0;
}

int kernel_fd_operation_release(kernel_fd_operation_lease_t *lease) {
    if (!lease || *(int32_t *)(void *)lease <= 0)
        return -EDGE_LINUX_EBADF;
    *(int32_t *)(void *)lease = 0;
    ((uint32_t *)(void *)lease)[1] = 0u;
    assert(g_fixed_file_references != 0u);
    --g_fixed_file_references;
    return 0;
}

int kernel_fd_operation_materialize(
        const kernel_fd_operation_lease_t *source,
        uint32_t descriptor_flags, int32_t *descriptor) {
    int32_t stored;
    g_materialize_flags = descriptor_flags;
    if (!source || !descriptor) return -EDGE_LINUX_EINVAL;
    stored = *(const int32_t *)(const void *)source;
    if (stored <= 0) return -EDGE_LINUX_EBADF;
    *descriptor = stored - 1;
    return 0;
}

int kernel_eventfd_retain(int event_id) {
    (void)event_id;
    return -EDGE_LINUX_EBADF;
}

void kernel_eventfd_release(int event_id) {
    (void)event_id;
}

int64_t kernel_eventfd_write_value(int event_id, int nonblocking,
                                   uint64_t value) {
    (void)event_id;
    (void)nonblocking;
    (void)value;
    return -EDGE_LINUX_EBADF;
}

int kernel_io_descriptor_ready(int32_t descriptor,
                               kernel_io_operation_t operation) {
    (void)operation;
    return descriptor == g_ready_descriptor;
}

int kernel_fd_operation_ready(
        kernel_fd_operation_lease_t *lease, uint32_t operation) {
    const int32_t descriptor = *(int32_t *)(void *)lease - 1;

    (void)operation;
    if (descriptor < 0) return -EDGE_LINUX_EBADF;
    return descriptor == g_ready_descriptor &&
           ((uint32_t *)(void *)lease)[1] == g_ready_generation;
}

int64_t kernel_fd_operation_file_range(
        kernel_fd_operation_lease_t *lease,
        const kernel_io_file_range_request_t *request) {
    int32_t descriptor;

    if (!lease || !request) return -EDGE_LINUX_EINVAL;
    descriptor = *(int32_t *)(void *)lease - 1;
    if (descriptor < 0) return -EDGE_LINUX_EBADF;
    if (request->operation == KERNEL_IO_FILE_RANGE_QUERY) {
        if (!request->information) return -EDGE_LINUX_EINVAL;
        memset(request->information, 0,
               sizeof(*request->information));
        request->information->kind = KERNEL_IO_FILE_PIPE;
        request->information->readable = 1u;
        return 0;
    }
    if (request->operation != KERNEL_IO_FILE_RANGE_READ)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (g_multishot_read_result <= 0)
        return g_multishot_read_result;
    assert(request->buffer);
    assert(request->length >= g_multishot_read_length);
    memcpy(request->buffer, g_multishot_read_data,
           g_multishot_read_length);
    g_multishot_read_result = -EDGE_LINUX_EAGAIN;
    return (int64_t)g_multishot_read_length;
}

int kernel_epoll_descriptor_retain(int32_t descriptor,
                                   int32_t *epoll_index) {
    if (descriptor != 55 || !epoll_index)
        return -EDGE_LINUX_EBADF;
    *epoll_index = 3;
    ++g_epoll_references;
    return 0;
}

void kernel_epoll_object_release(int32_t epoll_index) {
    assert(epoll_index == 3);
    assert(g_epoll_references != 0u);
    --g_epoll_references;
}

int kernel_epoll_deliver_events(int32_t epoll_index,
                                uint32_t maximum_events,
                                kernel_epoll_event_copy_fn copy_event,
                                void *copy_context) {
    const kernel_epoll_event_t event = {
        .events = 0x11u,
        .data = 0x8877665544332211ull,
    };
    int result;

    if (epoll_index != 3 || !maximum_events || !copy_event)
        return -EDGE_LINUX_EINVAL;
    if (!g_epoll_ready) return 0;
    result = copy_event(copy_context, 0u, &event);
    if (result < 0) return result;
    g_epoll_ready = 0;
    return 1;
}

int kernel_mm_address_space_copy(
        uint64_t address_space, uint64_t address, void *buffer,
        uint64_t size, kernel_mm_process_vm_operation_t operation) {
    if (address_space != 1u || !address || !buffer ||
        operation != KERNEL_MM_PROCESS_VM_WRITE)
        return -EDGE_LINUX_EFAULT;
    memcpy((void *)(uintptr_t)address, buffer, (size_t)size);
    return 0;
}

static int test_page_allocate(void *context, kernel_io_uring_page_t *page) {
    (void)context;
    for (uint32_t index = 0; index < TEST_PAGE_COUNT; ++index) {
        if (g_references[index]) continue;
        g_references[index] = 1u;
        page->address = g_pages[index];
        page->cookie = index;
        return 0;
    }
    return -EDGE_LINUX_ENOMEM;
}

static int test_page_retain(void *context,
                            const kernel_io_uring_page_t *page) {
    (void)context;
    if (!page || page->cookie >= TEST_PAGE_COUNT ||
        !g_references[page->cookie])
        return -EDGE_LINUX_EINVAL;
    ++g_references[page->cookie];
    return 0;
}

static void test_page_release(void *context,
                              const kernel_io_uring_page_t *page) {
    (void)context;
    assert(page && page->cookie < TEST_PAGE_COUNT);
    assert(g_references[page->cookie] != 0);
    --g_references[page->cookie];
}

static uint32_t *page_u32(const kernel_io_uring_page_t *page,
                          uint32_t offset) {
    return (uint32_t *)((uint8_t *)page->address + offset);
}

int main(void) {
    kernel_io_uring_page_allocator_t allocator = {
        .allocate = test_page_allocate,
        .retain = test_page_retain,
        .release = test_page_release,
    };
    struct edge_linux_io_uring_params parameters = {0};
    struct edge_linux_io_uring_sqe *mapped_sqe;
    struct edge_linux_io_uring_sqe submission;
    struct edge_linux_io_uring_cqe *completion;
    kernel_io_uring_page_t sq_ring;
    kernel_io_uring_page_t cq_ring;
    kernel_io_uring_page_t sqes;
    kernel_io_uring_page_t wait_region;
    uint32_t pages;
    const int32_t fixed_files[] = {4, -1, 7};
    const uint64_t fixed_tags[] = {
        0x54414741u, 0u, 0x54414742u,
    };
    int32_t materialized = -1;
    int32_t ring_id;
    int32_t second_ring_id;
    int32_t looked_up_ring = -1;
    uint32_t registered_slot = UINT32_MAX;
    uint32_t allocation_offset = UINT32_MAX;
    uint32_t allocation_length = UINT32_MAX;
    uint64_t selected_time = 0u;
    uint64_t capability_features = 0u;
    uint64_t capability_setup_flags = 0u;

    {
        uint64_t minimum_deadline;
        uint64_t wait_deadline;

        assert(kernel_io_uring_wait_deadlines(
                   100u, 25u, 1, 0, 0u,
                   &minimum_deadline, &wait_deadline) == 0);
        assert(minimum_deadline == 0u && wait_deadline == 125u);
        assert(kernel_io_uring_wait_deadlines(
                   100u, 80u, 1, 1, 40u,
                   &minimum_deadline, &wait_deadline) == 0);
        assert(minimum_deadline == 140u && wait_deadline == 140u);
        assert(kernel_io_uring_wait_deadlines(
                   UINT64_MAX - 5u, 20u, 1, 0, 10u,
                   &minimum_deadline, &wait_deadline) == 0);
        assert(minimum_deadline == UINT64_MAX &&
               wait_deadline == UINT64_MAX);
        assert(kernel_io_uring_wait_deadlines(
                   100u, 0u, 0, 0, 30u,
                   &minimum_deadline, &wait_deadline) == 0);
        assert(minimum_deadline == 130u && wait_deadline == 130u);
    }
    assert(kernel_io_uring_page_allocator_register(&allocator) == 0);
    assert(kernel_io_uring_create(8, &parameters, &ring_id) == 0);
    kernel_io_uring_capabilities(
        &capability_features, &capability_setup_flags);
    assert(capability_features == parameters.features);
    assert(capability_setup_flags == 0x1d3fd8u);
    assert(parameters.sq_entries == 8);
    assert(parameters.cq_entries == 16);
    assert(kernel_io_uring_completion_capacity(ring_id) == 16u);
    assert(parameters.sq_off.array == 64);
    assert(parameters.cq_off.cqes == 64);
    assert(kernel_io_uring_clock_now(
               ring_id, 100u, 200u, &selected_time) == 0);
    assert(selected_time == 100u);
    assert(kernel_io_uring_clock_set(ring_id, 7u) == 0);
    assert(kernel_io_uring_clock_now(
               ring_id, 100u, 200u, &selected_time) == 0);
    assert(selected_time == 200u);
    assert(kernel_io_uring_clock_set(ring_id, 0u) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_io_uring_clock_set(ring_id, 1u) == 0);
    assert(kernel_io_uring_file_alloc_range_get(
               ring_id, &allocation_offset,
               &allocation_length) == 0);
    assert(allocation_offset == 0u && allocation_length == 0u);
    {
        struct edge_linux_io_uring_params second_parameters = {0};
        assert(kernel_io_uring_create(
                   2, &second_parameters, &second_ring_id) == 0);
    }
    assert(kernel_io_uring_task_ring_register(
               41, second_ring_id, 3u, &registered_slot) == 0);
    assert(registered_slot == 3u);
    assert(kernel_io_uring_task_ring_lookup(
               41, 3u, &looked_up_ring) == 0);
    assert(looked_up_ring == second_ring_id);
    assert(kernel_io_uring_task_ring_register(
               41, second_ring_id, 3u, &registered_slot) ==
           -EDGE_LINUX_EBUSY);
    assert(kernel_io_uring_task_ring_register(
               41, second_ring_id,
               KERNEL_IO_URING_REGISTERED_RING_ALLOC,
               &registered_slot) == 0);
    assert(registered_slot == 0u);
    assert(kernel_io_uring_task_ring_unregister(41, 3u) == 0);
    assert(kernel_io_uring_task_ring_lookup(
               41, 3u, &looked_up_ring) == -EDGE_LINUX_EBADF);
    assert(kernel_io_uring_task_ring_unregister(41, 3u) == 0);
    assert(kernel_io_uring_task_ring_lookup(
               41, KERNEL_IO_URING_REGISTERED_RINGS,
               &looked_up_ring) == -EDGE_LINUX_EINVAL);
    kernel_io_uring_task_release(41);
    assert(kernel_io_uring_task_ring_lookup(
               41, 0u, &looked_up_ring) == -EDGE_LINUX_EBADF);
    assert(kernel_io_uring_region_register(
               second_ring_id, 1u, 1) == -EDGE_LINUX_EINVAL);
    kernel_io_uring_release(second_ring_id);
    {
        struct edge_linux_io_uring_params wait_parameters = {
            .flags = 1u << 6,
        };
        struct edge_linux_io_uring_reg_wait wait_value = {
            .timeout_seconds = 3,
            .timeout_nanoseconds = 4000,
            .minimum_wait_microseconds = 55,
            .flags = 1,
        };
        struct edge_linux_io_uring_reg_wait wait_copy = {0};

        assert(kernel_io_uring_create(
                   2u, &wait_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_region_registered(second_ring_id) == 0);
        assert(kernel_io_uring_region_register(
                   second_ring_id, 1u, 1) == 0);
        assert(kernel_io_uring_region_registered(second_ring_id) == 1);
        assert(kernel_io_uring_region_register(
                   second_ring_id, 1u, 1) == -EDGE_LINUX_EBUSY);
        assert(kernel_io_uring_mmap_info(
                   second_ring_id, KERNEL_IO_URING_OFF_PARAM_REGION,
                   KERNEL_IO_URING_PAGE_SIZE, &pages) == 0);
        assert(pages == 1u);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_PARAM_REGION,
                   0u, &wait_region) == 0);
        memcpy(wait_region.address, &wait_value, sizeof(wait_value));
        assert(kernel_io_uring_registered_wait_read(
                   second_ring_id, 0u, &wait_copy) == 0);
        assert(memcmp(&wait_copy, &wait_value, sizeof(wait_value)) == 0);
        assert(kernel_io_uring_registered_wait_read(
                   second_ring_id, 1u, &wait_copy) ==
               -EDGE_LINUX_EFAULT);
        assert(kernel_io_uring_enable(second_ring_id) == 0);
        assert(kernel_io_uring_region_unregister(second_ring_id) == 0);
        assert(kernel_io_uring_region_registered(second_ring_id) == 0);
        test_page_release(0, &wait_region);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params extended_parameters = {
            .flags = (1u << 10) | (1u << 11),
        };
        struct edge_linux_io_uring_sqe extended_submission = {0};
        struct edge_linux_io_uring_cqe *extended_completion;
        kernel_io_uring_page_t extended_sq_ring;
        kernel_io_uring_page_t extended_cq_ring;
        kernel_io_uring_page_t extended_sqes;
        uint64_t *completion_extra;
        uint32_t setup_flags = 0u;

        assert(kernel_io_uring_create(
                   8u, &extended_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_setup_flags(
                   second_ring_id, &setup_flags) == 0);
        assert(setup_flags == extended_parameters.flags);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_SQ_RING,
                   0u, &extended_sq_ring) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &extended_cq_ring) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_SQES,
                   0u, &extended_sqes) == 0);
        mapped_sqe = (struct edge_linux_io_uring_sqe *)(void *)(
            (uint8_t *)extended_sqes.address + 128u);
        memset(mapped_sqe, 0, sizeof(*mapped_sqe));
        mapped_sqe->opcode = 63u;
        mapped_sqe->user_data = 0x535145313238u;
        *page_u32(&extended_sq_ring, 64u) = 1u;
        *page_u32(&extended_sq_ring, 4u) = 1u;
        {
            uint32_t entries_consumed = 0u;
            int32_t layout_result = 0;
            assert(kernel_io_uring_take_submission(
                       second_ring_id, 0u, 1u, &extended_submission,
                       &entries_consumed, &layout_result) == 0);
            assert(entries_consumed == 1u);
            assert(layout_result == 0);
        }
        assert(extended_submission.opcode == 63u);
        assert(extended_submission.user_data == 0x535145313238u);
        assert(kernel_io_uring_completion_add32(
                   second_ring_id, 0x4351453332u, -7, 3u,
                   0x1111222233334444ull,
                   0x5555666677778888ull) == 0);
        extended_completion =
            (struct edge_linux_io_uring_cqe *)(void *)(
                (uint8_t *)extended_cq_ring.address + 64u);
        completion_extra = (uint64_t *)(void *)(extended_completion + 1);
        assert(extended_completion->user_data == 0x4351453332u);
        assert(extended_completion->result == -7);
        assert(extended_completion->flags == 3u);
        assert(completion_extra[0] == 0x1111222233334444ull);
        assert(completion_extra[1] == 0x5555666677778888ull);
        test_page_release(0, &extended_sq_ring);
        test_page_release(0, &extended_cq_ring);
        test_page_release(0, &extended_sqes);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params invalid_mixed_parameters = {
            .flags = (1u << 10) | (1u << 19),
        };
        struct edge_linux_io_uring_params mixed_parameters = {
            .flags = (1u << 18) | (1u << 19),
        };
        struct edge_linux_io_uring_sqe mixed_submission = {0};
        struct edge_linux_io_uring_cqe *mixed_completion;
        kernel_io_uring_page_t mixed_sq_ring;
        kernel_io_uring_page_t mixed_cq_ring;
        kernel_io_uring_page_t mixed_sqes;
        uint64_t *completion_extra;
        uint32_t entries_consumed;
        int32_t layout_result;

        assert(kernel_io_uring_create(
                   2u, &invalid_mixed_parameters,
                   &second_ring_id) == -EDGE_LINUX_EINVAL);
        invalid_mixed_parameters.flags = (1u << 11) | (1u << 18);
        assert(kernel_io_uring_create(
                   2u, &invalid_mixed_parameters,
                   &second_ring_id) == -EDGE_LINUX_EINVAL);
        invalid_mixed_parameters.flags = (1u << 19);
        assert(kernel_io_uring_create(
                   1u, &invalid_mixed_parameters,
                   &second_ring_id) == -EDGE_LINUX_EOVERFLOW);

        assert(kernel_io_uring_create(
                   4u, &mixed_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_SQ_RING,
                   0u, &mixed_sq_ring) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &mixed_cq_ring) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_SQES,
                   0u, &mixed_sqes) == 0);

        mapped_sqe = (struct edge_linux_io_uring_sqe *)(void *)(
            (uint8_t *)mixed_sqes.address + 2u * 64u);
        memset(mapped_sqe, 0, 2u * sizeof(*mapped_sqe));
        mapped_sqe->opcode = 63u;
        mapped_sqe->user_data = 0x4d49584544535145ull;
        *page_u32(&mixed_sq_ring, 64u) = 2u;
        *page_u32(&mixed_sq_ring, 68u) = 3u;
        *page_u32(&mixed_sq_ring, 4u) = 2u;
        entries_consumed = 0u;
        layout_result = 0;
        assert(kernel_io_uring_take_submission(
                   second_ring_id, 0u, 2u, &mixed_submission,
                   &entries_consumed, &layout_result) == 0);
        assert(entries_consumed == 2u);
        assert(layout_result == 0);
        assert(mixed_submission.user_data == 0x4d49584544535145ull);
        assert(*page_u32(&mixed_sq_ring, 0u) == 2u);

        mapped_sqe = (struct edge_linux_io_uring_sqe *)(void *)
            mixed_sqes.address;
        memset(mapped_sqe, 0, sizeof(*mapped_sqe));
        mapped_sqe->opcode = 63u;
        mapped_sqe->user_data = 0x4d49584544424144ull;
        *page_u32(&mixed_sq_ring, 72u) = 0u;
        *page_u32(&mixed_sq_ring, 4u) = 3u;
        entries_consumed = 0u;
        layout_result = 0;
        assert(kernel_io_uring_take_submission(
                   second_ring_id, 0u, 1u, &mixed_submission,
                   &entries_consumed, &layout_result) == 0);
        assert(entries_consumed == 1u);
        assert(layout_result == -EDGE_LINUX_EINVAL);
        assert(*page_u32(&mixed_sq_ring, 0u) == 3u);

        assert(kernel_io_uring_completion_add(
                   second_ring_id, 0x4d49584544435131ull,
                   1, 0u) == 0);
        assert(kernel_io_uring_completion_add32(
                   second_ring_id, 0x4d49584544435132ull,
                   2, 0u, 0x1111222233334444ull,
                   0x5555666677778888ull) == 0);
        assert(*page_u32(&mixed_cq_ring, 4u) == 3u);
        mixed_completion =
            (struct edge_linux_io_uring_cqe *)(void *)(
                (uint8_t *)mixed_cq_ring.address + 64u + 16u);
        completion_extra = (uint64_t *)(void *)(mixed_completion + 1);
        assert(mixed_completion->user_data == 0x4d49584544435132ull);
        assert(mixed_completion->result == 2);
        assert(mixed_completion->flags == (1u << 15));
        assert(completion_extra[0] == 0x1111222233334444ull);
        assert(completion_extra[1] == 0x5555666677778888ull);

        *page_u32(&mixed_cq_ring, 0u) = 7u;
        *page_u32(&mixed_cq_ring, 4u) = 7u;
        assert(kernel_io_uring_completion_add32(
                   second_ring_id, 0x4d49584544575250ull,
                   3, 0u, 9u, 10u) == 0);
        assert(*page_u32(&mixed_cq_ring, 4u) == 10u);
        mixed_completion =
            (struct edge_linux_io_uring_cqe *)(void *)(
                (uint8_t *)mixed_cq_ring.address + 64u + 7u * 16u);
        assert(mixed_completion->user_data == 0u);
        assert(mixed_completion->result == 0);
        assert(mixed_completion->flags == (1u << 5));
        mixed_completion =
            (struct edge_linux_io_uring_cqe *)(void *)(
                (uint8_t *)mixed_cq_ring.address + 64u);
        assert(mixed_completion->user_data == 0x4d49584544575250ull);
        assert(mixed_completion->flags == (1u << 15));

        test_page_release(0, &mixed_sq_ring);
        test_page_release(0, &mixed_cq_ring);
        test_page_release(0, &mixed_sqes);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params no_array_parameters = {
            .flags = 1u << 16,
            .sq_off = {
                .array = UINT32_MAX,
                .reserved1 = UINT32_MAX,
            },
            .cq_off = {
                .reserved1 = UINT32_MAX,
            },
        };
        struct edge_linux_io_uring_params rewind_parameters = {
            .flags = (1u << 16) | (1u << 20),
        };
        struct edge_linux_io_uring_params invalid_parameters = {
            .flags = 1u << 20,
        };
        struct edge_linux_io_uring_sqe no_array_submission = {0};
        kernel_io_uring_page_t no_array_sq_ring;
        kernel_io_uring_page_t no_array_sqes;
        uint32_t entries_consumed = 0u;
        int32_t layout_result = 0;

        assert(kernel_io_uring_create(
                   4u, &invalid_parameters, &second_ring_id) ==
               -EDGE_LINUX_EINVAL);
        invalid_parameters.flags = 1u << 13;
        assert(kernel_io_uring_create(
                   4u, &invalid_parameters, &second_ring_id) ==
               -EDGE_LINUX_EINVAL);

        assert(kernel_io_uring_create(
                   4u, &no_array_parameters, &second_ring_id) == 0);
        assert(no_array_parameters.sq_off.array == 0u);
        assert(no_array_parameters.sq_off.reserved1 == 0u);
        assert(no_array_parameters.cq_off.reserved1 == 0u);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_SQ_RING,
                   0u, &no_array_sq_ring) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_SQES,
                   0u, &no_array_sqes) == 0);
        mapped_sqe = (struct edge_linux_io_uring_sqe *)(void *)
            no_array_sqes.address;
        memset(mapped_sqe, 0, 2u * sizeof(*mapped_sqe));
        mapped_sqe[0].user_data = 0x4e4f5f4152524159ull;
        *page_u32(&no_array_sq_ring, no_array_parameters.sq_off.tail) = 1u;
        assert(kernel_io_uring_take_submission(
                   second_ring_id, 0u, 1u, &no_array_submission,
                   &entries_consumed, &layout_result) == 0);
        assert(no_array_submission.user_data == 0x4e4f5f4152524159ull);
        assert(*page_u32(
                   &no_array_sq_ring, no_array_parameters.sq_off.head) == 1u);
        test_page_release(0, &no_array_sq_ring);
        test_page_release(0, &no_array_sqes);
        kernel_io_uring_release(second_ring_id);

        assert(kernel_io_uring_create(
                   4u, &rewind_parameters, &second_ring_id) == 0);
        assert(rewind_parameters.sq_off.array == 0u);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_SQ_RING,
                   0u, &no_array_sq_ring) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_SQES,
                   0u, &no_array_sqes) == 0);
        mapped_sqe = (struct edge_linux_io_uring_sqe *)(void *)
            no_array_sqes.address;
        memset(mapped_sqe, 0, 2u * sizeof(*mapped_sqe));
        mapped_sqe[0].user_data = 0x524557494e4430ull;
        mapped_sqe[1].user_data = 0x524557494e4431ull;
        entries_consumed = 0u;
        layout_result = 0;
        assert(kernel_io_uring_take_submission(
                   second_ring_id, 0u, 2u, &no_array_submission,
                   &entries_consumed, &layout_result) == 0);
        assert(no_array_submission.user_data == 0x524557494e4430ull);
        assert(*page_u32(
                   &no_array_sq_ring, rewind_parameters.sq_off.head) == 0u);
        assert(kernel_io_uring_take_submission(
                   second_ring_id, 1u, 1u, &no_array_submission,
                   &entries_consumed, &layout_result) == 0);
        assert(no_array_submission.user_data == 0x524557494e4431ull);
        assert(kernel_io_uring_take_submission(
                   second_ring_id, 4u, 1u, &no_array_submission,
                   &entries_consumed, &layout_result) ==
               -EDGE_LINUX_EAGAIN);
        test_page_release(0, &no_array_sq_ring);
        test_page_release(0, &no_array_sqes);
        kernel_io_uring_release(second_ring_id);
    }
    assert(kernel_io_uring_files_register(
               ring_id, fixed_files, 3u) == 0);
    assert(kernel_io_uring_file_alloc_range_get(
               ring_id, &allocation_offset,
               &allocation_length) == 0);
    assert(allocation_offset == 0u && allocation_length == 3u);
    assert(kernel_io_uring_file_alloc_range_set(
               ring_id, 1u, 2u) == 0);
    assert(kernel_io_uring_file_alloc_range_get(
               ring_id, &allocation_offset,
               &allocation_length) == 0);
    assert(allocation_offset == 1u && allocation_length == 2u);
    assert(kernel_io_uring_file_alloc_range_set(
               ring_id, UINT32_MAX, 2u) == -EDGE_LINUX_EOVERFLOW);
    assert(kernel_io_uring_file_alloc_range_set(
               ring_id, 2u, 2u) == -EDGE_LINUX_EINVAL);
    assert(g_fixed_file_references == 2u);
    assert(kernel_io_uring_files_register(
               ring_id, fixed_files, 3u) == -EDGE_LINUX_EBUSY);
    assert(kernel_io_uring_fixed_file_materialize(
               ring_id, 0u, &materialized) == 0 && materialized == 4);
    assert(g_materialize_flags == KERNEL_FD_CLOEXEC);
    assert(kernel_io_uring_fixed_file_install(
               ring_id, 0u, 0u, &materialized) == 0 && materialized == 4);
    assert(g_materialize_flags == 0u);
    assert(kernel_io_uring_fixed_file_install(
               ring_id, 0u, KERNEL_FD_CLOEXEC << 1u,
               &materialized) == -EDGE_LINUX_EINVAL);
    assert(kernel_io_uring_fixed_file_materialize(
               ring_id, 1u, &materialized) == -EDGE_LINUX_EBADF);
    assert(kernel_io_uring_fixed_file_materialize(
               ring_id, 2u, &materialized) == 0 && materialized == 7);
    {
        const int32_t update[] = {8};
        assert(kernel_io_uring_files_update(
                   ring_id, 1u, update, 1u) == 1);
    }
    assert(g_fixed_file_references == 3u);
    assert(kernel_io_uring_fixed_file_materialize(
               ring_id, 1u, &materialized) == 0 && materialized == 8);
    {
        const int32_t update[] = {
            KERNEL_IO_URING_REGISTER_FILES_SKIP, 98,
        };
        assert(kernel_io_uring_files_update(
                   ring_id, 0u, update, 2u) == 1);
    }
    assert(g_fixed_file_references == 2u);
    assert(kernel_io_uring_fixed_file_materialize(
               ring_id, 1u, &materialized) == -EDGE_LINUX_EBADF);
    {
        const int32_t update[] = {-1};
        assert(kernel_io_uring_files_update(
                   ring_id, 2u, update, 1u) == 1);
    }
    assert(g_fixed_file_references == 1u);
    {
        const int32_t update[] = {4};
        assert(kernel_io_uring_files_update(
                   ring_id, 3u, update, 1u) == -EDGE_LINUX_EINVAL);
    }
    assert(kernel_io_uring_files_unregister(ring_id) == 0);
    assert(g_fixed_file_references == 0u);
    assert(kernel_io_uring_files_unregister(ring_id) ==
           -EDGE_LINUX_ENXIO);
    {
        const int32_t sparse_files[] = {-1, -1, -1, -1};
        const int32_t pipe_files[] = {31, 32};
        kernel_fd_publication_t publication = {
            .descriptors = pipe_files,
            .count = 2u,
            .active = 1u,
        };
        kernel_io_uring_fixed_file_reservation_t reservation = {0};
        const int32_t update[] = {9};

        assert(kernel_io_uring_files_register(
                   ring_id, sparse_files, 4u) == 0);
        assert(kernel_io_uring_fixed_file_pair_reserve(
                   ring_id, 2u, &reservation) == 0);
        assert(reservation.active && reservation.indices[0] == 1u &&
               reservation.indices[1] == 2u);
        assert(kernel_io_uring_files_update(
                   ring_id, 1u, update, 1u) == -EDGE_LINUX_EBUSY);
        assert(kernel_io_uring_files_unregister(ring_id) ==
               -EDGE_LINUX_EBUSY);
        assert(kernel_io_uring_fixed_file_pair_cancel(
                   &reservation) == 0);
        assert(!reservation.active);

        assert(kernel_io_uring_fixed_file_pair_reserve(
                   ring_id, 2u, &reservation) == 0);
        assert(kernel_io_uring_fixed_file_pair_commit(
                   &reservation, &publication) == 0);
        assert(!reservation.active);
        assert(g_fixed_file_references == 2u);
        assert(kernel_io_uring_fixed_file_materialize(
                   ring_id, 1u, &materialized) == 0 &&
               materialized == 31);
        assert(kernel_io_uring_fixed_file_materialize(
                   ring_id, 2u, &materialized) == 0 &&
               materialized == 32);
        assert(kernel_io_uring_files_unregister(ring_id) == 0);
        assert(g_fixed_file_references == 0u);
    }
    {
        struct edge_linux_io_uring_params target_parameters = {0};
        const int32_t source_files[] = {4};
        const int32_t target_files[] = {-1, -1, -1};

        assert(kernel_io_uring_create(
                   2u, &target_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_files_register(
                   ring_id, source_files, 1u) == 0);
        assert(kernel_io_uring_files_register(
                   second_ring_id, target_files, 3u) == 0);
        assert(g_fixed_file_references == 1u);
        assert(kernel_io_uring_fixed_file_transfer(
                   ring_id, 0u, second_ring_id, 2u) == 0);
        assert(g_fixed_file_references == 2u);
        assert(kernel_io_uring_fixed_file_materialize(
                   second_ring_id, 1u, &materialized) == 0 &&
               materialized == 4);
        assert(kernel_io_uring_fixed_file_transfer(
                   ring_id, 0u, second_ring_id, UINT32_MAX) == 0);
        assert(g_fixed_file_references == 3u);
        assert(kernel_io_uring_fixed_file_materialize(
                   second_ring_id, 0u, &materialized) == 0 &&
               materialized == 4);
        assert(kernel_io_uring_fixed_file_transfer(
                   ring_id, 0u, second_ring_id, 2u) == 0);
        assert(g_fixed_file_references == 3u);
        assert(kernel_io_uring_fixed_file_transfer(
                   ring_id, 1u, second_ring_id, 3u) ==
               -EDGE_LINUX_EBADF);
        assert(kernel_io_uring_fixed_file_transfer(
                   ring_id, 1u, second_ring_id, 0u) ==
               -EDGE_LINUX_EBADF);
        assert(kernel_io_uring_fixed_file_transfer(
                   ring_id, 0u, ring_id, 1u) ==
               -EDGE_LINUX_EINVAL);
        assert(kernel_io_uring_fixed_file_transfer(
                   ring_id, 0u, second_ring_id, 0u) ==
               -EDGE_LINUX_EINVAL);
        assert(kernel_io_uring_files_unregister(second_ring_id) == 0);
        assert(g_fixed_file_references == 1u);
        assert(kernel_io_uring_fixed_file_transfer(
                   ring_id, 0u, second_ring_id, 1u) ==
               -EDGE_LINUX_ENXIO);
        assert(kernel_io_uring_files_unregister(ring_id) == 0);
        assert(g_fixed_file_references == 0u);
        kernel_io_uring_release(second_ring_id);
    }
    assert(kernel_io_uring_files_register_tagged(
               ring_id, fixed_files, fixed_tags, 3u) == 0);
    assert(kernel_io_uring_mmap_info(
               ring_id, KERNEL_IO_URING_OFF_SQ_RING,
               KERNEL_IO_URING_PAGE_SIZE, &pages) == 0);
    assert(pages == 1);
    assert(kernel_io_uring_mmap_page(
               ring_id, KERNEL_IO_URING_OFF_SQ_RING, 0, &sq_ring) == 0);
    assert(kernel_io_uring_mmap_page(
               ring_id, KERNEL_IO_URING_OFF_CQ_RING, 0, &cq_ring) == 0);
    assert(kernel_io_uring_mmap_page(
               ring_id, KERNEL_IO_URING_OFF_SQES, 0, &sqes) == 0);

    mapped_sqe = (struct edge_linux_io_uring_sqe *)sqes.address;
    mapped_sqe[0].opcode = 0;
    mapped_sqe[0].user_data = 0x12345678u;
    page_u32(&sq_ring, parameters.sq_off.array)[0] = 0;
    *page_u32(&sq_ring, parameters.sq_off.tail) = 1;
    {
        uint32_t entries_consumed = 0u;
        int32_t layout_result = 0;
        assert(kernel_io_uring_take_submission(
                   ring_id, 0u, 1u, &submission,
                   &entries_consumed, &layout_result) == 0);
        assert(entries_consumed == 1u);
        assert(layout_result == 0);
    }
    assert(submission.opcode == 0 &&
           submission.user_data == 0x12345678u);
    assert(*page_u32(&sq_ring, parameters.sq_off.head) == 1);
    assert(kernel_io_uring_completion_add(
               ring_id, submission.user_data, 7, 0) == 0);
    assert(kernel_io_uring_completion_count(ring_id) == 1);
    completion = (struct edge_linux_io_uring_cqe *)(
        (uint8_t *)cq_ring.address + parameters.cq_off.cqes);
    assert(completion[0].user_data == submission.user_data);
    assert(completion[0].result == 7 && completion[0].flags == 0);

    assert(kernel_io_uring_timeout_add(
               ring_id, 0x54494d45u, 100u, 0,
               -EDGE_LINUX_ETIME, 0, 0u, 0u, 0) == 0);
    assert(kernel_io_uring_collect(ring_id, 99u) == 0);
    assert(kernel_io_uring_collect(ring_id, 100u) == 1);
    assert(kernel_io_uring_completion_count(ring_id) == 2);
    assert(completion[1].user_data == 0x54494d45u);
    assert(completion[1].result == -EDGE_LINUX_ETIME);

    assert(kernel_io_uring_poll_add(
               ring_id, 0x504f4c4cu, 9, 1u, 0) == 0);
    assert(kernel_io_uring_collect(ring_id, 101u) == 0);
    g_ready_descriptor = 9;
    assert(kernel_io_uring_collect(ring_id, 102u) == 1);
    assert(kernel_io_uring_completion_count(ring_id) == 3);
    assert(completion[2].user_data == 0x504f4c4cu);
    assert(completion[2].result == 1);

    {
        uint32_t references_before_poll = g_fixed_file_references;

        g_descriptor_generation[10] = 7u;
        g_ready_generation = 8u;
        g_ready_descriptor = 10;
        assert(kernel_io_uring_poll_add(
                   ring_id, 0x4c454153u, 10, 1u, 0) == 0);
        assert(g_fixed_file_references == references_before_poll + 1u);
        g_descriptor_generation[10] = 8u;
        assert(kernel_io_uring_collect(ring_id, 103u) == 0);
        g_ready_generation = 7u;
        assert(kernel_io_uring_collect(ring_id, 104u) == 1);
        assert(g_fixed_file_references == references_before_poll);
        assert(completion[3].user_data == 0x4c454153u);
        assert(completion[3].result == 1);
        g_ready_generation = 0u;
    }

    assert(kernel_io_uring_timeout_add(
               ring_id, 0x55504454u, UINT64_MAX, 7u,
               -EDGE_LINUX_ETIME, 0, 0u, 0u, 0) == 0);
    assert(kernel_io_uring_timeout_update(
               ring_id, 0x55504454u, 20u, 0, 100u, 1000u) == 0);
    assert(kernel_io_uring_collect(ring_id, 119u) == 0);
    assert(kernel_io_uring_collect(ring_id, 120u) == 1);
    assert(kernel_io_uring_completion_count(ring_id) == 5);
    assert(completion[4].user_data == 0x55504454u);
    assert(completion[4].result == -EDGE_LINUX_ETIME);
    assert(kernel_io_uring_timeout_update(
               ring_id, 0x55504454u, 1u, 0, 120u, 1000u) ==
           -EDGE_LINUX_ENOENT);

    assert(kernel_io_uring_timeout_add(
               ring_id, 0x43414e43u, UINT64_MAX, 0,
               -EDGE_LINUX_ETIME, 0, 0u, 0u, 0) == 0);
    assert(kernel_io_uring_pending_cancel(ring_id, 0x43414e43u) == 0);
    assert(kernel_io_uring_pending_cancel(ring_id, 0x43414e43u) ==
           -EDGE_LINUX_ENOENT);

    {
        const int32_t update[] = {8};
        const uint64_t tags[] = {0x54414743u};
        assert(kernel_io_uring_files_update_tagged(
                   ring_id, 0u, update, tags, 1u) == 1);
    }
    assert(completion[5].user_data == 0x54414741u);
    assert(completion[5].result == 0 && completion[5].flags == 0);
    assert(kernel_io_uring_files_unregister(ring_id) == 0);
    assert(completion[6].user_data == 0x54414743u);
    assert(completion[6].result == 0 && completion[6].flags == 0);
    assert(completion[7].user_data == 0x54414742u);
    assert(completion[7].result == 0 && completion[7].flags == 0);
    assert(g_fixed_file_references == 0u);

    g_ready_descriptor = -1;
    assert(kernel_io_uring_poll_add(
               ring_id, 0x4d554c54u, 9, 1u, 1) == 0);
    assert(kernel_io_uring_collect(ring_id, 121u) == 0);
    g_ready_descriptor = 9;
    assert(kernel_io_uring_collect(ring_id, 122u) == 1);
    assert(completion[8].user_data == 0x4d554c54u);
    assert(completion[8].result == 1 && completion[8].flags == 2u);
    assert(kernel_io_uring_collect(ring_id, 123u) == 0);
    g_ready_descriptor = -1;
    assert(kernel_io_uring_collect(ring_id, 124u) == 0);
    assert(kernel_io_uring_poll_update(
               ring_id, 0x4d554c54u, 1, 1u, 1,
               0x4e455755u, 1) == 0);
    g_ready_descriptor = 9;
    assert(kernel_io_uring_collect(ring_id, 125u) == 1);
    assert(completion[9].user_data == 0x4e455755u);
    assert(completion[9].result == 1 && completion[9].flags == 2u);
    assert(kernel_io_uring_pending_cancel(ring_id, 0x4e455755u) == 0);
    assert(kernel_io_uring_poll_update(
               ring_id, 0x4e455755u, 0, 0u, 1,
               0x4d495353u, 0) == -EDGE_LINUX_ENOENT);

    g_ready_descriptor = -1;
    assert(kernel_io_uring_poll_add(
               ring_id, 0x52455452u, 9, 1u, 1) == 0);
    for (uint32_t index = 0; index < 6u; ++index)
        assert(kernel_io_uring_completion_add(
                   ring_id, 0x46494c4cu + index, 0, 0) == 0);
    g_ready_descriptor = 9;
    assert(kernel_io_uring_collect(ring_id, 126u) == 1);
    *page_u32(&cq_ring, parameters.cq_off.head) = 1u;
    assert(kernel_io_uring_completion_flush(ring_id) == 1);
    assert(completion[0].user_data == 0x52455452u);
    assert(completion[0].result == 1 && completion[0].flags == 2u);
    assert(kernel_io_uring_pending_cancel(ring_id, 0x52455452u) == 0);

    test_page_release(0, &sq_ring);
    test_page_release(0, &cq_ring);
    test_page_release(0, &sqes);
    kernel_io_uring_release(ring_id);
    assert(g_fixed_file_references == 0u);

    {
        struct edge_linux_io_uring_params timeout_parameters = {0};
        kernel_io_uring_page_t timeout_cq;
        struct edge_linux_io_uring_cqe *timeout_completion;

        assert(kernel_io_uring_create(
                   4u, &timeout_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &timeout_cq) == 0);
        timeout_completion = (struct edge_linux_io_uring_cqe *)(
            (uint8_t *)timeout_cq.address +
            timeout_parameters.cq_off.cqes);

        assert(kernel_io_uring_timeout_add(
                   second_ring_id, 0x4d54494du, 100u, 0u,
                   -EDGE_LINUX_ETIME, 0, 10u, 3u, 1) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 99u) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 100u) == 1);
        assert(timeout_completion[0].user_data == 0x4d54494du);
        assert(timeout_completion[0].result == -EDGE_LINUX_ETIME &&
               timeout_completion[0].flags == 2u);
        assert(kernel_io_uring_collect(second_ring_id, 109u) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 110u) == 1);
        assert(timeout_completion[1].result == -EDGE_LINUX_ETIME &&
               timeout_completion[1].flags == 2u);
        assert(kernel_io_uring_collect(second_ring_id, 120u) == 1);
        assert(timeout_completion[2].result == -EDGE_LINUX_ETIME &&
               timeout_completion[2].flags == 0u);
        assert(kernel_io_uring_pending_cancel(
                   second_ring_id, 0x4d54494du) == -EDGE_LINUX_ENOENT);

        assert(kernel_io_uring_timeout_add(
                   second_ring_id, 0x494e4654u, 200u, 0u,
                   -EDGE_LINUX_ETIME, 0, 5u, 0u, 1) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 200u) == 1);
        assert(timeout_completion[3].flags == 2u);
        assert(kernel_io_uring_timeout_update(
                   second_ring_id, 0x494e4654u, 20u, 0,
                   200u, 1000u) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 219u) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 220u) == 1);
        assert(timeout_completion[4].user_data == 0x494e4654u);
        assert(timeout_completion[4].flags == 2u);
        assert(kernel_io_uring_pending_cancel(
                   second_ring_id, 0x494e4654u) == 0);

        for (uint32_t index = 0; index < 3u; ++index)
            assert(kernel_io_uring_completion_add(
                       second_ring_id, 0x46494c54u + index,
                       0, 0) == 0);
        assert(kernel_io_uring_timeout_add(
                   second_ring_id, 0x52455454u, 300u, 0u,
                   -EDGE_LINUX_ETIME, 0, 10u, 0u, 1) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 300u) == 1);
        *page_u32(&timeout_cq, timeout_parameters.cq_off.head) = 1u;
        assert(kernel_io_uring_completion_flush(second_ring_id) == 1);
        assert(timeout_completion[0].user_data == 0x52455454u);
        assert(timeout_completion[0].result == -EDGE_LINUX_ETIME &&
               timeout_completion[0].flags == 2u);
        assert(kernel_io_uring_pending_cancel(
                   second_ring_id, 0x52455454u) == 0);

        test_page_release(0, &timeout_cq);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params epoll_parameters = {0};
        kernel_io_uring_page_t epoll_cq;
        struct edge_linux_io_uring_cqe *epoll_completion;
        struct {
            uint32_t events;
            uint8_t data[8];
        } __attribute__((packed)) delivered = {0};
        struct {
            uint32_t events;
            uint32_t padding;
            uint8_t data[8];
        } aligned_delivered = {0};

        assert(kernel_io_uring_create(
                   4u, &epoll_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &epoll_cq) == 0);
        epoll_completion = (struct edge_linux_io_uring_cqe *)(
            (uint8_t *)epoll_cq.address +
            epoll_parameters.cq_off.cqes);
        assert(kernel_io_uring_epoll_wait_add(
                   second_ring_id, 0x45504f4c4cu, 55,
                   (uint64_t)(uintptr_t)&delivered, 1u, 4u,
                   12u, 4u) == 0);
        assert(g_epoll_references == 1u);
        assert(kernel_io_uring_collect(second_ring_id, 1u) == 0);
        g_epoll_ready = 1;
        assert(kernel_io_uring_collect(second_ring_id, 2u) == 1);
        assert(g_epoll_references == 0u);
        assert(epoll_completion[0].user_data == 0x45504f4c4cu);
        assert(epoll_completion[0].result == 1);
        assert(delivered.events == 0x11u);
        {
            uint64_t data = 0;
            memcpy(&data, delivered.data, sizeof(data));
            assert(data == 0x8877665544332211ull);
        }
        assert(kernel_io_uring_epoll_wait_add(
                   second_ring_id, 0x414c49474e4544u, 55,
                   (uint64_t)(uintptr_t)&aligned_delivered, 1u, 1u,
                   16u, 8u) == 0);
        g_epoll_ready = 1;
        assert(kernel_io_uring_collect(second_ring_id, 3u) == 1);
        assert(epoll_completion[1].user_data == 0x414c49474e4544u);
        assert(epoll_completion[1].result == 1);
        assert(aligned_delivered.events == 0x11u);
        assert(aligned_delivered.padding == 0u);
        {
            uint64_t data = 0;
            memcpy(&data, aligned_delivered.data, sizeof(data));
            assert(data == 0x8877665544332211ull);
        }
        assert(kernel_io_uring_epoll_wait_add(
                   second_ring_id, 0x43414e43454cu, 55,
                   (uint64_t)(uintptr_t)&delivered, 1u, 1u,
                   12u, 4u) == 0);
        assert(kernel_io_uring_pending_cancel(
                   second_ring_id, 0x43414e43454cu) == 0);
        assert(g_epoll_references == 0u);
        test_page_release(0, &epoll_cq);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params link_parameters = {0};
        kernel_io_uring_page_t link_cq;
        struct edge_linux_io_uring_cqe *link_completion;
        uint64_t target_sequence = 0;

        assert(kernel_io_uring_create(
                   4u, &link_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &link_cq) == 0);
        link_completion = (struct edge_linux_io_uring_cqe *)(
            (uint8_t *)link_cq.address + link_parameters.cq_off.cqes);
        g_descriptor_generation[10] = 7u;
        g_ready_generation = 7u;
        g_ready_descriptor = -1;

        assert(kernel_io_uring_poll_add(
                   second_ring_id, 0x4c544152u, 10, 1u, 0) == 0);
        assert(kernel_io_uring_pending_sequence(
                   second_ring_id, 0x4c544152u,
                   &target_sequence) == 0);
        assert(target_sequence != 0u);
        assert(kernel_io_uring_link_timeout_add(
                   second_ring_id, 0x4c54494du,
                   target_sequence, 100u, 0) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 50u) == 0);
        g_ready_descriptor = 10;
        assert(kernel_io_uring_collect(second_ring_id, 60u) == 2);
        assert(link_completion[0].user_data == 0x4c544152u);
        assert(link_completion[0].result == 1);
        assert(link_completion[1].user_data == 0x4c54494du);
        assert(link_completion[1].result == -EDGE_LINUX_ECANCELED);
        assert(g_fixed_file_references == 0u);

        g_ready_descriptor = -1;
        assert(kernel_io_uring_poll_add(
                   second_ring_id, 0x4c544252u, 10, 1u, 0) == 0);
        assert(kernel_io_uring_pending_sequence(
                   second_ring_id, 0x4c544252u,
                   &target_sequence) == 0);
        assert(kernel_io_uring_link_timeout_add(
                   second_ring_id, 0x4c54424du,
                   target_sequence, 100u, 0) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 99u) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 100u) == 2);
        assert(link_completion[2].user_data == 0x4c544252u);
        assert(link_completion[2].result == -EDGE_LINUX_ECANCELED);
        assert(link_completion[3].user_data == 0x4c54424du);
        assert(link_completion[3].result == -EDGE_LINUX_ETIME);
        assert(g_fixed_file_references == 0u);

        assert(kernel_io_uring_poll_add(
                   second_ring_id, 0x4c544352u, 10, 1u, 0) == 0);
        assert(kernel_io_uring_pending_sequence(
                   second_ring_id, 0x4c544352u,
                   &target_sequence) == 0);
        assert(kernel_io_uring_link_timeout_add(
                   second_ring_id, 0u,
                   target_sequence, 200u, 0) == 0);
        assert(kernel_io_uring_pending_cancel(
                   second_ring_id, 0x4c544352u) == 0);
        assert(link_completion[4].user_data == 0u);
        assert(link_completion[4].result == -EDGE_LINUX_ECANCELED);
        assert(kernel_io_uring_link_timeout_add(
                   second_ring_id, 0x494e564cu,
                   target_sequence, 200u, 0) == -EDGE_LINUX_EINVAL);
        assert(g_fixed_file_references == 0u);

        test_page_release(0, &link_cq);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params futex_parameters = {0};
        kernel_io_uring_page_t futex_cq;
        struct edge_linux_io_uring_cqe *futex_completion;
        kernel_futex_request_t futex_request = {0};
        uint32_t cancel_count;

        futex_request.operation = KERNEL_FUTEX_WAIT;
        futex_request.address = 0x1000u;
        futex_request.expected_value = 7u;
        futex_request.bitset = UINT32_MAX;
        assert(kernel_io_uring_create(
                   4u, &futex_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &futex_cq) == 0);
        futex_completion = (struct edge_linux_io_uring_cqe *)(
            (uint8_t *)futex_cq.address +
            futex_parameters.cq_off.cqes);
        assert(kernel_io_uring_futex_wait_add(
                   second_ring_id, 0x46555458u, 51u,
                   &futex_request) == 0);
        assert(g_futex_request.operation == KERNEL_FUTEX_WAIT);
        assert(kernel_io_uring_collect(second_ring_id, 0u) == 0);
        g_futex_result = 0;
        g_futex_ready = 1;
        assert(kernel_io_uring_collect(second_ring_id, 0u) == 1);
        assert(futex_completion[0].user_data == 0x46555458u);
        assert(futex_completion[0].result == 0);

        assert(kernel_io_uring_futex_wait_add(
                   second_ring_id, 0x46555443u, 51u,
                   &futex_request) == 0);
        cancel_count = g_futex_cancel_count;
        assert(kernel_io_uring_pending_cancel(
                   second_ring_id, 0x46555443u) == 0);
        assert(g_futex_cancel_count == cancel_count + 1u);

        assert(kernel_io_uring_futex_wait_add(
                   second_ring_id, 0x46555452u, 51u,
                   &futex_request) == 0);
        cancel_count = g_futex_cancel_count;
        test_page_release(0, &futex_cq);
        kernel_io_uring_release(second_ring_id);
        assert(g_futex_cancel_count == cancel_count + 1u);
    }
    {
        struct edge_linux_io_uring_params wait_parameters = {0};
        kernel_io_uring_page_t wait_cq;
        struct edge_linux_io_uring_cqe *wait_completion;
        kernel_process_wait_request_t wait_request = {0};

        wait_request.selector = 17;
        wait_request.flags = KERNEL_PROCESS_WAIT_EXITED |
                             KERNEL_PROCESS_WAIT_NOHANG;
        wait_request.pid_namespace_id = 3u;
        g_process_wait_status = 0;
        g_waitid_copy_count = 0u;
        assert(kernel_io_uring_create(
                   4u, &wait_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &wait_cq) == 0);
        wait_completion = (struct edge_linux_io_uring_cqe *)(
            (uint8_t *)wait_cq.address + wait_parameters.cq_off.cqes);
        assert(kernel_io_uring_waitid_add(
                   second_ring_id, 0x57414954u, &wait_request, 41,
                   0x123000u, 0xabc000u, test_waitid_copy) == 0);
        assert(kernel_io_uring_collect(second_ring_id, 0u) == 0);
        assert(g_process_waiter_tid == 41);
        assert(g_process_wait_request.selector == 17);
        g_process_wait_result.pid = 17;
        g_process_wait_result.uid = 1000u;
        g_process_wait_result.status = 0x2a00u;
        g_process_wait_status = 1;
        assert(kernel_io_uring_collect(second_ring_id, 0u) == 1);
        assert(g_waitid_copy_count == 1u);
        assert(wait_completion[0].user_data == 0x57414954u);
        assert(wait_completion[0].result == 0);

        g_process_wait_status = 0;
        assert(kernel_io_uring_waitid_add(
                   second_ring_id, 0x57414943u, &wait_request, 41,
                   0u, 0u, 0) == 0);
        assert(kernel_io_uring_pending_cancel(
                   second_ring_id, 0x57414943u) == 0);
        test_page_release(0, &wait_cq);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params read_parameters = {0};
        kernel_io_uring_page_t read_cq;
        struct edge_linux_io_uring_cqe *read_completion;
        uint8_t buffers[2][32] = {{0}};
        const uint8_t first[] = {'o', 'n', 'e'};
        const uint8_t second[] = {'t', 'w', 'o'};
        uint32_t references = g_fixed_file_references;

        assert(kernel_io_uring_create(
                   4u, &read_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &read_cq) == 0);
        read_completion = (struct edge_linux_io_uring_cqe *)(
            (uint8_t *)read_cq.address + read_parameters.cq_off.cqes);
        assert(kernel_io_uring_provided_buffers_add(
                   second_ring_id, 9u, 7u,
                   (uint64_t)(uintptr_t)&buffers[0][0],
                   sizeof(buffers[0]), 2u) == 0);
        g_ready_descriptor = 20;
        g_ready_generation = g_descriptor_generation[20];
        assert(kernel_io_uring_read_multishot_add(
                   second_ring_id, 0x4d53484fu, 20, 9u, 1u) == 0);
        assert(g_fixed_file_references == references + 1u);

        memcpy(g_multishot_read_data, first, sizeof(first));
        g_multishot_read_length = sizeof(first);
        g_multishot_read_result = (int32_t)sizeof(first);
        assert(kernel_io_uring_collect(second_ring_id, 0u) == 1u);
        assert(read_completion[0].result == (int32_t)sizeof(first));
        assert((read_completion[0].flags & 3u) == 3u);
        assert((read_completion[0].flags >> 16) == 7u);
        assert(memcmp(buffers[0], first, sizeof(first)) == 0);

        memcpy(g_multishot_read_data, second, sizeof(second));
        g_multishot_read_length = sizeof(second);
        g_multishot_read_result = (int32_t)sizeof(second);
        assert(kernel_io_uring_collect(second_ring_id, 0u) == 1u);
        assert(read_completion[1].result == (int32_t)sizeof(second));
        assert((read_completion[1].flags & 3u) == 3u);
        assert((read_completion[1].flags >> 16) == 8u);
        assert(memcmp(buffers[1], second, sizeof(second)) == 0);

        assert(kernel_io_uring_collect(second_ring_id, 0u) == 1u);
        assert(read_completion[2].result == -EDGE_LINUX_ENOBUFS);
        assert(read_completion[2].flags == 0u);
        assert(g_fixed_file_references == references);

        {
            kernel_io_uring_page_t pbuf_page;
            kernel_io_uring_pbuf_ring_t pbuf_snapshot;
            struct edge_linux_io_uring_buf pbuf_entry = {0};
            uint8_t pbuf_buffers[2][32] = {{0}};
            uint16_t pbuf_tail = 2u;

            assert(kernel_io_uring_pbuf_ring_register(
                       second_ring_id, 11u, 0u, 0u, 8u,
                       1, 0, 0u) == 0);
            assert(kernel_io_uring_mmap_page(
                       second_ring_id,
                       KERNEL_IO_URING_OFF_PBUF_RING |
                           (11ull << KERNEL_IO_URING_OFF_PBUF_SHIFT),
                       0u, &pbuf_page) == 0);
            pbuf_entry.address =
                (uint64_t)(uintptr_t)&pbuf_buffers[0][0];
            pbuf_entry.length = sizeof(pbuf_buffers[0]);
            pbuf_entry.id = 21u;
            memcpy(pbuf_page.address, &pbuf_entry, sizeof(pbuf_entry));
            pbuf_entry.address =
                (uint64_t)(uintptr_t)&pbuf_buffers[1][0];
            pbuf_entry.id = 22u;
            memcpy((uint8_t *)pbuf_page.address + sizeof(pbuf_entry),
                   &pbuf_entry, sizeof(pbuf_entry));
            memcpy((uint8_t *)pbuf_page.address + 14u,
                   &pbuf_tail, sizeof(pbuf_tail));

            assert(kernel_io_uring_read_multishot_add(
                       second_ring_id, 0x50425546u, 20, 11u, 1u) == 0);
            memcpy(g_multishot_read_data, first, sizeof(first));
            g_multishot_read_length = sizeof(first);
            g_multishot_read_result = (int32_t)sizeof(first);
            assert(kernel_io_uring_collect(second_ring_id, 0u) == 1u);
            assert(read_completion[3].result == (int32_t)sizeof(first));
            assert((read_completion[3].flags & 3u) == 3u);
            assert((read_completion[3].flags >> 16) == 21u);
            assert(memcmp(pbuf_buffers[0], first, sizeof(first)) == 0);

            memcpy(g_multishot_read_data, second, sizeof(second));
            g_multishot_read_length = sizeof(second);
            g_multishot_read_result = (int32_t)sizeof(second);
            assert(kernel_io_uring_collect(second_ring_id, 0u) == 1u);
            assert(read_completion[4].result == (int32_t)sizeof(second));
            assert((read_completion[4].flags & 3u) == 3u);
            assert((read_completion[4].flags >> 16) == 22u);
            assert(memcmp(pbuf_buffers[1], second, sizeof(second)) == 0);

            assert(kernel_io_uring_collect(second_ring_id, 0u) == 1u);
            assert(read_completion[5].result == -EDGE_LINUX_ENOBUFS);
            assert(read_completion[5].flags == 0u);
            assert(kernel_io_uring_pbuf_ring_snapshot(
                       second_ring_id, 11u, &pbuf_snapshot) == 0);
            assert(pbuf_snapshot.head == 2u);
            assert(g_fixed_file_references == references);
            test_page_release(0, &pbuf_page);
            assert(kernel_io_uring_pbuf_ring_unregister(
                       second_ring_id, 11u) == 0);
        }

        assert(kernel_io_uring_provided_buffers_add(
                   second_ring_id, 10u, 3u,
                   (uint64_t)(uintptr_t)&buffers[0][0],
                   sizeof(buffers[0]), 1u) == 0);
        assert(kernel_io_uring_read_multishot_add(
                   second_ring_id, 0x4d534843u, 20, 10u, 1u) == 0);
        assert(kernel_io_uring_pending_cancel(
                   second_ring_id, 0x4d534843u) == 0);
        assert(g_fixed_file_references == references);
        g_ready_descriptor = -1;
        test_page_release(0, &read_cq);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params buffer_parameters = {0};
        const struct edge_linux_iovec buffers[] = {
            {.iov_base = 0x1000u, .iov_len = 0x100u},
            {.iov_base = 0u, .iov_len = 0u},
            {.iov_base = 0x3000u, .iov_len = 0x200u},
        };
        const uint64_t tags[] = {
            0x42554641u, 0u, 0x42554642u,
        };
        const struct edge_linux_iovec replacement = {
            .iov_base = 0x5000u,
            .iov_len = 0x80u,
        };
        const uint64_t replacement_tag = 0x42554643u;
        const struct edge_linux_iovec partial[] = {
            {.iov_base = 0x6000u, .iov_len = 0x40u},
            {.iov_base = 0u, .iov_len = 0u},
        };
        const uint64_t partial_tags[] = {
            0x42554644u, 0x42554645u,
        };
        const struct edge_linux_iovec invalid = {
            .iov_base = 0u,
            .iov_len = 1u,
        };
        kernel_io_uring_page_t buffer_cq;
        struct edge_linux_io_uring_cqe *buffer_completion;

        assert(kernel_io_uring_create(
                   4u, &buffer_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &buffer_cq) == 0);
        buffer_completion = (struct edge_linux_io_uring_cqe *)(
            (uint8_t *)buffer_cq.address +
            buffer_parameters.cq_off.cqes);
        assert(kernel_io_uring_buffers_unregister(second_ring_id) ==
               -EDGE_LINUX_ENXIO);
        assert(kernel_io_uring_buffers_register(
                   second_ring_id, &invalid, 0, 1u) ==
               -EDGE_LINUX_EFAULT);
        assert(kernel_io_uring_buffers_register(
                   second_ring_id, buffers, tags, 3u) == 0);
        assert(kernel_io_uring_buffers_register(
                   second_ring_id, buffers, tags, 3u) ==
               -EDGE_LINUX_EBUSY);
        assert(kernel_io_uring_fixed_buffer_validate(
                   second_ring_id, 0u, 0x1000u, 0x100u) == 0);
        assert(kernel_io_uring_fixed_buffer_validate(
                   second_ring_id, 0u, 0x1080u, 0x40u) == 0);
        assert(kernel_io_uring_fixed_buffer_validate(
                   second_ring_id, 0u, 0x0fffu, 1u) ==
               -EDGE_LINUX_EFAULT);
        assert(kernel_io_uring_fixed_buffer_validate(
                   second_ring_id, 0u, 0x10f0u, 0x20u) ==
               -EDGE_LINUX_EFAULT);
        assert(kernel_io_uring_fixed_buffer_validate(
                   second_ring_id, 1u, 0u, 0u) ==
               -EDGE_LINUX_EFAULT);
        assert(kernel_io_uring_fixed_buffer_validate(
                   second_ring_id, 3u, 0x1000u, 1u) ==
               -EDGE_LINUX_EFAULT);
        assert(kernel_io_uring_buffers_update(
                   second_ring_id, 0u, &replacement,
                   &replacement_tag, 1u) == 1);
        assert(buffer_completion[0].user_data == tags[0]);
        assert(buffer_completion[0].result == 0 &&
               buffer_completion[0].flags == 0u);
        assert(kernel_io_uring_fixed_buffer_validate(
                   second_ring_id, 0u, 0x5000u, 0x80u) == 0);
        assert(kernel_io_uring_buffers_update(
                   second_ring_id, 1u, partial,
                   partial_tags, 2u) == 1);
        assert(kernel_io_uring_fixed_buffer_validate(
                   second_ring_id, 1u, 0x6000u, 0x40u) == 0);
        assert(kernel_io_uring_fixed_buffer_validate(
                   second_ring_id, 2u, 0x3000u, 0x200u) == 0);
        assert(kernel_io_uring_buffers_unregister(second_ring_id) == 0);
        assert(buffer_completion[1].user_data == replacement_tag);
        assert(buffer_completion[2].user_data == partial_tags[0]);
        assert(buffer_completion[3].user_data == tags[2]);
        assert(kernel_io_uring_buffers_unregister(second_ring_id) ==
               -EDGE_LINUX_ENXIO);
        test_page_release(0, &buffer_cq);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params provided_parameters = {0};
        kernel_io_uring_selected_buffer_t selected;

        assert(kernel_io_uring_create(
                   4u, &provided_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_provided_buffers_remove(
                   second_ring_id, 7u, 1u) == -EDGE_LINUX_ENOENT);
        assert(kernel_io_uring_provided_buffers_add(
                   second_ring_id, 7u, 40u,
                   0x1000u, 0x100u, 3u) == 0);
        assert(kernel_io_uring_provided_buffer_select(
                   second_ring_id, 7u, 0u, &selected) == 0);
        assert(selected.address == 0x1000u &&
               selected.length == 0x100u &&
               selected.capacity == 0x100u && selected.id == 40u);
        assert(kernel_io_uring_provided_buffer_select(
                   second_ring_id, 7u, 0x40u, &selected) == 0);
        assert(selected.address == 0x1100u &&
               selected.length == 0x40u && selected.id == 41u);
        assert(kernel_io_uring_provided_buffers_remove(
                   second_ring_id, 7u, 8u) == 1);
        assert(kernel_io_uring_provided_buffers_remove(
                   second_ring_id, 7u, 8u) == 0);
        assert(kernel_io_uring_provided_buffer_select(
                   second_ring_id, 7u, 1u, &selected) ==
               -EDGE_LINUX_ENOBUFS);
        assert(kernel_io_uring_provided_buffers_add(
                   second_ring_id, 8u, UINT16_MAX,
                   0x2000u, 0x20u, 2u) == -EDGE_LINUX_EINVAL);
        assert(kernel_io_uring_provided_buffers_add(
                   second_ring_id, 8u, 4u,
                   UINT64_MAX - 0x10u, 0x20u, 1u) ==
               -EDGE_LINUX_EOVERFLOW);
        assert(kernel_io_uring_pbuf_ring_register(
                   second_ring_id, 9u, 0x4000u, 1u, 8u,
                   0, 0, 0u) == 0);
        {
            kernel_io_uring_pbuf_ring_t snapshot;

            assert(kernel_io_uring_pbuf_ring_snapshot(
                       second_ring_id, 9u, &snapshot) == 0);
            assert(snapshot.address == 0x4000u &&
                   snapshot.address_space == 1u &&
                   snapshot.entries == 8u && snapshot.head == 0u &&
                   !snapshot.kernel_allocated);
            assert(kernel_io_uring_pbuf_ring_commit(
                       second_ring_id, 9u, 1u) ==
                   -EDGE_LINUX_EAGAIN);
            assert(kernel_io_uring_pbuf_ring_commit(
                       second_ring_id, 9u, 0u) == 0);
            assert(kernel_io_uring_pbuf_ring_snapshot(
                       second_ring_id, 9u, &snapshot) == 0);
            assert(snapshot.head == 1u);
            for (uint32_t head = 1u; head <= UINT16_MAX; ++head)
                assert(kernel_io_uring_pbuf_ring_commit(
                           second_ring_id, 9u, head) == 0);
            assert(kernel_io_uring_pbuf_ring_snapshot(
                       second_ring_id, 9u, &snapshot) == 0);
            assert(snapshot.head == 0u);
        }
        assert(kernel_io_uring_provided_buffers_add(
                   second_ring_id, 9u, 1u,
                   0x5000u, 0x20u, 1u) ==
               -EDGE_LINUX_EEXIST);
        assert(kernel_io_uring_provided_buffers_remove(
                   second_ring_id, 9u, 1u) ==
               -EDGE_LINUX_EINVAL);
        assert(kernel_io_uring_pbuf_ring_unregister(
                   second_ring_id, 9u) == 0);
        assert(kernel_io_uring_pbuf_ring_unregister(
                   second_ring_id, 9u) == -EDGE_LINUX_ENOENT);
        assert(kernel_io_uring_pbuf_ring_register(
                   second_ring_id, 10u, 0u, 0u, 8u,
                   1, 0, 0u) == 0);
        {
            struct edge_linux_io_uring_buf buffer = {0};
            struct edge_linux_io_uring_buf selected_buffer;
            kernel_io_uring_pbuf_ring_t snapshot;
            kernel_io_uring_page_t buffer_page;
            uint16_t tail = 1u;

            assert(kernel_io_uring_pbuf_ring_snapshot(
                       second_ring_id, 10u, &snapshot) == 0);
            assert(!snapshot.address && snapshot.entries == 8u &&
                   snapshot.kernel_allocated);
            assert(kernel_io_uring_mmap_info(
                       second_ring_id,
                       KERNEL_IO_URING_OFF_PBUF_RING |
                           (10ull << KERNEL_IO_URING_OFF_PBUF_SHIFT),
                       KERNEL_IO_URING_PAGE_SIZE, &pages) == 0);
            assert(pages == 1u);
            assert(kernel_io_uring_mmap_page(
                       second_ring_id,
                       KERNEL_IO_URING_OFF_PBUF_RING |
                           (10ull << KERNEL_IO_URING_OFF_PBUF_SHIFT),
                       0u, &buffer_page) == 0);
            buffer.address = 0x6000u;
            buffer.length = 0x80u;
            buffer.id = 70u;
            memcpy(buffer_page.address, &buffer, sizeof(buffer));
            memcpy((uint8_t *)buffer_page.address + 14u,
                   &tail, sizeof(tail));
            memset(&selected_buffer, 0, sizeof(selected_buffer));
            tail = 0u;
            assert(kernel_io_uring_pbuf_ring_read(
                       second_ring_id, 10u, 0u,
                       &selected_buffer, &tail) == 0);
            assert(tail == 1u && selected_buffer.address == 0x6000u &&
                   selected_buffer.length == 0x80u &&
                   selected_buffer.id == 70u);
            test_page_release(0, &buffer_page);
        }
        assert(kernel_io_uring_pbuf_ring_unregister(
                   second_ring_id, 10u) == 0);
        assert(kernel_io_uring_pbuf_ring_register(
                   second_ring_id, 12u, 0u, 0u, 8u,
                   1, 1, 4u) == 0);
        {
            struct edge_linux_io_uring_buf buffer = {0};
            struct edge_linux_io_uring_buf selected_buffer;
            kernel_io_uring_pbuf_ring_t snapshot;
            kernel_io_uring_page_t buffer_page;
            uint16_t tail = 1u;
            int buffer_more = 0;

            assert(kernel_io_uring_mmap_page(
                       second_ring_id,
                       KERNEL_IO_URING_OFF_PBUF_RING |
                           (12ull << KERNEL_IO_URING_OFF_PBUF_SHIFT),
                       0u, &buffer_page) == 0);
            buffer.address = 0x7000u;
            buffer.length = 8u;
            buffer.id = 80u;
            memcpy(buffer_page.address, &buffer, sizeof(buffer));
            memcpy((uint8_t *)buffer_page.address + 14u,
                   &tail, sizeof(tail));
            assert(kernel_io_uring_pbuf_ring_complete(
                       second_ring_id, 12u, 0u,
                       3u, &buffer_more) == 0);
            assert(buffer_more == 1);
            assert(kernel_io_uring_pbuf_ring_snapshot(
                       second_ring_id, 12u, &snapshot) == 0);
            assert(snapshot.head == 0u && snapshot.incremental &&
                   snapshot.minimum_left == 4u);
            assert(kernel_io_uring_pbuf_ring_read(
                       second_ring_id, 12u, 0u,
                       &selected_buffer, &tail) == 0);
            assert(selected_buffer.address == 0x7003u &&
                   selected_buffer.length == 5u);
            assert(kernel_io_uring_pbuf_ring_complete(
                       second_ring_id, 12u, 0u,
                       3u, &buffer_more) == 0);
            assert(buffer_more == 0);
            assert(kernel_io_uring_pbuf_ring_snapshot(
                       second_ring_id, 12u, &snapshot) == 0);
            assert(snapshot.head == 1u);
            memcpy(&buffer, buffer_page.address, sizeof(buffer));
            assert(buffer.address == 0x7003u && buffer.length == 0u);
            test_page_release(0, &buffer_page);
        }
        assert(kernel_io_uring_pbuf_ring_unregister(
                   second_ring_id, 12u) == 0);
        kernel_io_uring_release(second_ring_id);
    }
    {
        struct edge_linux_io_uring_params overflow_parameters = {0};
        kernel_io_uring_page_t overflow_cq;
        kernel_io_uring_page_t overflow_sq;
        struct edge_linux_io_uring_cqe *overflow_completion;
        volatile uint32_t *overflow_head;
        volatile uint32_t *overflow_tail;

        assert(kernel_io_uring_create(
                   4u, &overflow_parameters, &second_ring_id) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_CQ_RING,
                   0u, &overflow_cq) == 0);
        assert(kernel_io_uring_mmap_page(
                   second_ring_id, KERNEL_IO_URING_OFF_SQ_RING,
                   0u, &overflow_sq) == 0);
        overflow_completion = (struct edge_linux_io_uring_cqe *)(
            (uint8_t *)overflow_cq.address +
            overflow_parameters.cq_off.cqes);
        overflow_head = page_u32(
            &overflow_cq, overflow_parameters.cq_off.head);
        overflow_tail = page_u32(
            &overflow_cq, overflow_parameters.cq_off.tail);
        for (uint32_t index = 0;
             index < overflow_parameters.cq_entries; ++index)
            assert(kernel_io_uring_completion_add(
                       second_ring_id, 0x4f5646520000u + index,
                       0, 0) == 0);
        assert(kernel_io_uring_completion_add(
                   second_ring_id, 0x4155584f56455246ull,
                   77, 0x1234u) == 0);
        assert(kernel_io_uring_completion_add(
                   second_ring_id, 0x4f52444552454432ull,
                   88, 0x5678u) == 0);
        assert(kernel_io_uring_completion_count(second_ring_id) ==
               overflow_parameters.cq_entries);
        assert(*page_u32(
                   &overflow_cq,
                   overflow_parameters.cq_off.overflow) == 0u);
        assert((*page_u32(
                   &overflow_sq,
                   overflow_parameters.sq_off.flags) & (1u << 1)) != 0u);
        *overflow_head = *overflow_tail;
        assert(kernel_io_uring_completion_flush(second_ring_id) == 2);
        assert(kernel_io_uring_completion_count(second_ring_id) == 2u);
        assert(overflow_completion[0].user_data ==
               0x4155584f56455246ull);
        assert(overflow_completion[0].result == 77 &&
               overflow_completion[0].flags == 0x1234u);
        assert(overflow_completion[1].user_data ==
               0x4f52444552454432ull);
        assert(overflow_completion[1].result == 88 &&
               overflow_completion[1].flags == 0x5678u);
        assert((*page_u32(
                   &overflow_sq,
                   overflow_parameters.sq_off.flags) & (1u << 1)) == 0u);
        test_page_release(0, &overflow_cq);
        test_page_release(0, &overflow_sq);
        kernel_io_uring_release(second_ring_id);
    }
    for (uint32_t index = 0; index < TEST_PAGE_COUNT; ++index)
        assert(g_references[index] == 0);

    puts("io_uring_runtime_unit: PASS");
    return 0;
}
