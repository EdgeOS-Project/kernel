/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for the architecture-independent io_uring core. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/io_uring_runtime.h"
#include "kernel/anonymous_fd.h"
#include "kernel/fd_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"

#define TEST_PAGE_COUNT 16u

static uint8_t g_pages[TEST_PAGE_COUNT][KERNEL_IO_URING_PAGE_SIZE]
    __attribute__((aligned(KERNEL_IO_URING_PAGE_SIZE)));
static uint32_t g_references[TEST_PAGE_COUNT];
static int32_t g_ready_descriptor = -1;
static uint32_t g_fixed_file_references;
static uint32_t g_materialize_flags;

int kernel_anonymous_fd_descriptor_object_id(
        int32_t descriptor, kernel_anonymous_fd_kind_t kind) {
    return kind == KERNEL_ANONYMOUS_FD_IO_URING && descriptor == 98 ? 1 : -1;
}

int kernel_fd_operation_acquire(
        int32_t descriptor, kernel_fd_operation_lease_t *lease) {
    if (!lease || descriptor < 0 || descriptor == 99)
        return -EDGE_LINUX_EBADF;
    *(int32_t *)(void *)lease = descriptor + 1;
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
    ++g_fixed_file_references;
    return 0;
}

const void *kernel_fd_operation_view(
        const kernel_fd_operation_lease_t *lease) {
    return lease && *(const int32_t *)(const void *)lease > 0 ?
        (const void *)lease : 0;
}

int kernel_fd_operation_move(
        kernel_fd_operation_lease_t *destination,
        kernel_fd_operation_lease_t *source) {
    if (!destination || !source || destination == source ||
        *(int32_t *)(void *)destination != 0 ||
        *(int32_t *)(void *)source <= 0)
        return -EDGE_LINUX_EINVAL;
    *(int32_t *)(void *)destination = *(int32_t *)(void *)source;
    *(int32_t *)(void *)source = 0;
    return 0;
}

int kernel_fd_operation_release(kernel_fd_operation_lease_t *lease) {
    if (!lease || *(int32_t *)(void *)lease <= 0)
        return -EDGE_LINUX_EBADF;
    *(int32_t *)(void *)lease = 0;
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
    assert(kernel_io_uring_take_submission(ring_id, &submission) == 0);
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

    assert(kernel_io_uring_timeout_add(
               ring_id, 0x55504454u, UINT64_MAX, 7u,
               -EDGE_LINUX_ETIME, 0, 0u, 0u, 0) == 0);
    assert(kernel_io_uring_timeout_update(
               ring_id, 0x55504454u, 20u, 0, 100u, 1000u) == 0);
    assert(kernel_io_uring_collect(ring_id, 119u) == 0);
    assert(kernel_io_uring_collect(ring_id, 120u) == 1);
    assert(kernel_io_uring_completion_count(ring_id) == 4);
    assert(completion[3].user_data == 0x55504454u);
    assert(completion[3].result == -EDGE_LINUX_ETIME);
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
    assert(completion[4].user_data == 0x54414741u);
    assert(completion[4].result == 0 && completion[4].flags == 0);
    assert(kernel_io_uring_files_unregister(ring_id) == 0);
    assert(completion[5].user_data == 0x54414743u);
    assert(completion[5].result == 0 && completion[5].flags == 0);
    assert(completion[6].user_data == 0x54414742u);
    assert(completion[6].result == 0 && completion[6].flags == 0);
    assert(g_fixed_file_references == 0u);

    g_ready_descriptor = -1;
    assert(kernel_io_uring_poll_add(
               ring_id, 0x4d554c54u, 9, 1u, 1) == 0);
    assert(kernel_io_uring_collect(ring_id, 121u) == 0);
    g_ready_descriptor = 9;
    assert(kernel_io_uring_collect(ring_id, 122u) == 1);
    assert(completion[7].user_data == 0x4d554c54u);
    assert(completion[7].result == 1 && completion[7].flags == 2u);
    assert(kernel_io_uring_collect(ring_id, 123u) == 0);
    g_ready_descriptor = -1;
    assert(kernel_io_uring_collect(ring_id, 124u) == 0);
    assert(kernel_io_uring_poll_update(
               ring_id, 0x4d554c54u, 1, 1u, 1,
               0x4e455755u, 1) == 0);
    g_ready_descriptor = 9;
    assert(kernel_io_uring_collect(ring_id, 125u) == 1);
    assert(completion[8].user_data == 0x4e455755u);
    assert(completion[8].result == 1 && completion[8].flags == 2u);
    assert(kernel_io_uring_pending_cancel(ring_id, 0x4e455755u) == 0);
    assert(kernel_io_uring_poll_update(
               ring_id, 0x4e455755u, 0, 0u, 1,
               0x4d495353u, 0) == -EDGE_LINUX_ENOENT);

    g_ready_descriptor = -1;
    assert(kernel_io_uring_poll_add(
               ring_id, 0x52455452u, 9, 1u, 1) == 0);
    for (uint32_t index = 0; index < 7u; ++index)
        assert(kernel_io_uring_completion_add(
                   ring_id, 0x46494c4cu + index, 0, 0) == 0);
    g_ready_descriptor = 9;
    assert(kernel_io_uring_collect(ring_id, 126u) == 0);
    *page_u32(&cq_ring, parameters.cq_off.head) = 1u;
    assert(kernel_io_uring_collect(ring_id, 127u) == 1);
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
        assert(kernel_io_uring_collect(second_ring_id, 300u) == 0);
        *page_u32(&timeout_cq, timeout_parameters.cq_off.head) = 1u;
        assert(kernel_io_uring_collect(second_ring_id, 300u) == 1);
        assert(timeout_completion[0].user_data == 0x52455454u);
        assert(timeout_completion[0].result == -EDGE_LINUX_ETIME &&
               timeout_completion[0].flags == 2u);
        assert(kernel_io_uring_pending_cancel(
                   second_ring_id, 0x52455454u) == 0);

        test_page_release(0, &timeout_cq);
        kernel_io_uring_release(second_ring_id);
    }
    for (uint32_t index = 0; index < TEST_PAGE_COUNT; ++index)
        assert(g_references[index] == 0);

    puts("io_uring_runtime_unit: PASS");
    return 0;
}
