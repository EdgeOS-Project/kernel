/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for shared kexec image staging. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/kexec_runtime.h"
#include "kernel/linux_errno.h"

#define TEST_PAGE_SIZE 4096u
#define TEST_PAGE_COUNT 32u

typedef struct test_context {
    uint8_t pages[TEST_PAGE_COUNT][TEST_PAGE_SIZE];
    uint32_t next_page;
    uint32_t freed_pages;
    uint32_t fail_allocation;
    uint32_t fail_copy;
} test_context_t;

static int test_copy(void *opaque, void *destination, uint64_t source,
                     uint64_t length) {
    test_context_t *context = opaque;
    if (context->fail_copy) return -1;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)length);
    return 0;
}

static void *test_allocate(void *opaque, uint32_t page_count) {
    test_context_t *context = opaque;
    uint32_t first = context->next_page;

    if (context->fail_allocation ||
        page_count > TEST_PAGE_COUNT - context->next_page)
        return 0;
    context->next_page += page_count;
    return context->pages[first];
}

static void test_free(void *opaque, void *page) {
    test_context_t *context = opaque;
    (void)page;
    ++context->freed_pages;
}

static uint64_t test_total_memory(void *opaque) {
    (void)opaque;
    return 64u * 1024u * 1024u;
}

int main(void) {
    uint8_t first_payload[5000];
    uint8_t second_payload[100];
    test_context_t context;
    kernel_kexec_access_t access;
    kernel_kexec_snapshot_t snapshot;
    kernel_kexec_segment_t segments[2];
    uint32_t first_generation;

    memset(&context, 0, sizeof(context));
    memset(first_payload, 0xa5, sizeof(first_payload));
    memset(second_payload, 0x5a, sizeof(second_payload));
    access.context = &context;
    access.copy_from_user = test_copy;
    access.allocate_pages = test_allocate;
    access.free_page = test_free;
    access.memory_total_bytes = test_total_memory;

    segments[0] = (kernel_kexec_segment_t) {
        .buffer = (uint64_t)(uintptr_t)first_payload,
        .buffer_size = sizeof(first_payload),
        .memory = 0x200000,
        .memory_size = 0x2000,
    };
    segments[1] = (kernel_kexec_segment_t) {
        .buffer = (uint64_t)(uintptr_t)second_payload,
        .buffer_size = sizeof(second_payload),
        .memory = 0x300000,
        .memory_size = 0x1000,
    };

    assert(kernel_kexec_stage(
               0x200000, 2, segments, 0, &access) == 0);
    assert(kernel_kexec_snapshot(0, &snapshot) == 0);
    assert(snapshot.loaded && !snapshot.crash_image);
    assert(snapshot.segment_count == 2 && snapshot.entry == 0x200000);
    assert(snapshot.source_bytes == sizeof(first_payload) +
                                      sizeof(second_payload));
    assert(snapshot.destination_bytes == 0x3000);
    assert(!memcmp(context.pages[0], first_payload, TEST_PAGE_SIZE));
    assert(!memcmp(context.pages[2], second_payload, sizeof(second_payload)));
    first_generation = snapshot.generation;

    assert(kernel_kexec_stage(
               0x400000, 1, &segments[1],
               KERNEL_KEXEC_ON_CRASH, &access) == 0);
    assert(kernel_kexec_snapshot(1, &snapshot) == 0);
    assert(snapshot.loaded && snapshot.crash_image);
    assert(snapshot.generation != first_generation);
    assert(kernel_kexec_snapshot(0, &snapshot) == 0 && snapshot.loaded);

    segments[1].memory = 0x200000;
    assert(kernel_kexec_stage(0, 2, segments, 0, &access) ==
           -EDGE_LINUX_EINVAL);
    segments[1].memory = 0x300001;
    assert(kernel_kexec_stage(0, 1, &segments[1], 0, &access) ==
           -EDGE_LINUX_EADDRNOTAVAIL);
    segments[1].memory = 0x300000;
    segments[1].memory_size = 0;
    assert(kernel_kexec_stage(0, 1, &segments[1], 0, &access) ==
           -EDGE_LINUX_EINVAL);
    segments[1].memory_size = 0x1000;

    context.fail_copy = 1;
    assert(kernel_kexec_stage(0, 1, &segments[1], 0, &access) ==
           -EDGE_LINUX_EFAULT);
    context.fail_copy = 0;
    context.fail_allocation = 1;
    assert(kernel_kexec_stage(0, 1, &segments[1], 0, &access) ==
           -EDGE_LINUX_ENOMEM);
    context.fail_allocation = 0;

    assert(kernel_kexec_stage(0, 0, 0, 0, &access) == 0);
    assert(kernel_kexec_snapshot(0, &snapshot) == 0 && !snapshot.loaded);
    assert(kernel_kexec_snapshot(1, &snapshot) == 0 && snapshot.loaded);
    assert(context.freed_pages == 4);

    puts("kexec_runtime_unit: PASS");
    return 0;
}
