/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for the architecture-independent io_uring core. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "kernel/io_uring_runtime.h"
#include "kernel/fd_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"

#define TEST_PAGE_COUNT 16u

static uint8_t g_pages[TEST_PAGE_COUNT][KERNEL_IO_URING_PAGE_SIZE]
    __attribute__((aligned(KERNEL_IO_URING_PAGE_SIZE)));
static uint32_t g_references[TEST_PAGE_COUNT];
static int32_t g_ready_descriptor = -1;
static uint32_t g_fixed_file_references;

int kernel_fd_operation_acquire(
        int32_t descriptor, kernel_fd_operation_lease_t *lease) {
    if (!lease || descriptor < 0 || descriptor == 99)
        return -EDGE_LINUX_EBADF;
    *(int32_t *)(void *)lease = descriptor + 1;
    ++g_fixed_file_references;
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
    assert(descriptor_flags == KERNEL_FD_CLOEXEC);
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
    uint32_t pages;
    const int32_t fixed_files[] = {4, -1, 7};
    int32_t materialized = -1;
    int32_t ring_id;

    assert(kernel_io_uring_page_allocator_register(&allocator) == 0);
    assert(kernel_io_uring_create(8, &parameters, &ring_id) == 0);
    assert(parameters.sq_entries == 8);
    assert(parameters.cq_entries == 16);
    assert(parameters.sq_off.array == 64);
    assert(parameters.cq_off.cqes == 64);
    assert(kernel_io_uring_files_register(
               ring_id, fixed_files, 3u) == 0);
    assert(g_fixed_file_references == 2u);
    assert(kernel_io_uring_files_register(
               ring_id, fixed_files, 3u) == -EDGE_LINUX_EBUSY);
    assert(kernel_io_uring_fixed_file_materialize(
               ring_id, 0u, &materialized) == 0 && materialized == 4);
    assert(kernel_io_uring_fixed_file_materialize(
               ring_id, 1u, &materialized) == -EDGE_LINUX_EBADF);
    assert(kernel_io_uring_fixed_file_materialize(
               ring_id, 2u, &materialized) == 0 && materialized == 7);
    assert(kernel_io_uring_files_unregister(ring_id) == 0);
    assert(g_fixed_file_references == 0u);
    assert(kernel_io_uring_files_unregister(ring_id) ==
           -EDGE_LINUX_ENXIO);
    assert(kernel_io_uring_files_register(
               ring_id, fixed_files, 3u) == 0);
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
               ring_id, 0x54494d45u, 100u, 0, -EDGE_LINUX_ETIME) == 0);
    assert(kernel_io_uring_collect(ring_id, 99u) == 0);
    assert(kernel_io_uring_collect(ring_id, 100u) == 1);
    assert(kernel_io_uring_completion_count(ring_id) == 2);
    assert(completion[1].user_data == 0x54494d45u);
    assert(completion[1].result == -EDGE_LINUX_ETIME);

    assert(kernel_io_uring_poll_add(ring_id, 0x504f4c4cu, 9, 1u) == 0);
    assert(kernel_io_uring_collect(ring_id, 101u) == 0);
    g_ready_descriptor = 9;
    assert(kernel_io_uring_collect(ring_id, 102u) == 1);
    assert(kernel_io_uring_completion_count(ring_id) == 3);
    assert(completion[2].user_data == 0x504f4c4cu);
    assert(completion[2].result == 1);

    assert(kernel_io_uring_timeout_add(
               ring_id, 0x43414e43u, UINT64_MAX, 0,
               -EDGE_LINUX_ETIME) == 0);
    assert(kernel_io_uring_pending_cancel(ring_id, 0x43414e43u) == 0);
    assert(kernel_io_uring_pending_cancel(ring_id, 0x43414e43u) ==
           -EDGE_LINUX_ENOENT);

    test_page_release(0, &sq_ring);
    test_page_release(0, &cq_ring);
    test_page_release(0, &sqes);
    kernel_io_uring_release(ring_id);
    assert(g_fixed_file_references == 0u);
    for (uint32_t index = 0; index < TEST_PAGE_COUNT; ++index)
        assert(g_references[index] == 0);

    puts("io_uring_runtime_unit: PASS");
    return 0;
}
