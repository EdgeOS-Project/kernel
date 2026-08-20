/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for the architecture-independent io_uring core. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "kernel/io_uring_runtime.h"
#include "kernel/linux_errno.h"

#define TEST_PAGE_COUNT 16u

static uint8_t g_pages[TEST_PAGE_COUNT][KERNEL_IO_URING_PAGE_SIZE]
    __attribute__((aligned(KERNEL_IO_URING_PAGE_SIZE)));
static uint32_t g_references[TEST_PAGE_COUNT];

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
    int32_t ring_id;

    assert(kernel_io_uring_page_allocator_register(&allocator) == 0);
    assert(kernel_io_uring_create(8, &parameters, &ring_id) == 0);
    assert(parameters.sq_entries == 8);
    assert(parameters.cq_entries == 16);
    assert(parameters.sq_off.array == 64);
    assert(parameters.cq_off.cqes == 64);
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

    test_page_release(0, &sq_ring);
    test_page_release(0, &cq_ring);
    test_page_release(0, &sqes);
    kernel_io_uring_release(ring_id);
    for (uint32_t index = 0; index < TEST_PAGE_COUNT; ++index)
        assert(g_references[index] == 0);

    puts("io_uring_runtime_unit: PASS");
    return 0;
}
