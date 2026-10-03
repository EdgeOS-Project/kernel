/* SPDX-License-Identifier: MPL-2.0 */
/* Run with -DEDGEOS_HOST_TEST -iquote include to use host libc headers. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define STRING_H
#ifndef EDGE_EXEC_PAYLOAD_SOURCE
#define EDGE_EXEC_PAYLOAD_SOURCE "../../src/kernel/exec_payload.c"
#endif
#include EDGE_EXEC_PAYLOAD_SOURCE

static struct {
    uint8_t *base;
    uint64_t pages;
    uint64_t released;
} allocations[KERNEL_EXEC_PAYLOAD_SLOT_COUNT];
static int fail_allocation;
static int fail_mapped_allocation;
static uint64_t live_pages;
static uint64_t mapped_allocations;

void *arch_vm_alloc_pages(uint64_t pages) {
    assert(!g_exec_payload_lock.v);
    if (fail_allocation) return 0;
    for (uint32_t i = 0; i < KERNEL_EXEC_PAYLOAD_SLOT_COUNT; ++i) {
        if (allocations[i].base) continue;
        allocations[i].base = calloc(pages, EDGE_PAGE_SIZE);
        assert(allocations[i].base);
        allocations[i].pages = pages;
        allocations[i].released = 0;
        live_pages += pages;
        return allocations[i].base;
    }
    abort();
}

void arch_vm_free_page(void *page) {
    assert(!g_exec_payload_lock.v);
    for (uint32_t i = 0; i < KERNEL_EXEC_PAYLOAD_SLOT_COUNT; ++i) {
        if (!allocations[i].base) continue;
        uintptr_t base = (uintptr_t)allocations[i].base;
        uintptr_t address = (uintptr_t)page;
        if (address < base || address >= base + allocations[i].pages * EDGE_PAGE_SIZE)
            continue;
        assert(address == base + allocations[i].released * EDGE_PAGE_SIZE);
        ++allocations[i].released;
        --live_pages;
        if (allocations[i].released == allocations[i].pages) {
            free(allocations[i].base);
            allocations[i].base = 0;
        }
        return;
    }
    abort();
}

void *arch_vm_alloc_mapped_pages(uint64_t pages) {
    assert(!g_exec_payload_lock.v);
    if (fail_mapped_allocation) return 0;
    for (uint32_t i = 0; i < KERNEL_EXEC_PAYLOAD_SLOT_COUNT; ++i) {
        if (allocations[i].base) continue;
        allocations[i].base = calloc(pages, EDGE_PAGE_SIZE);
        assert(allocations[i].base);
        allocations[i].pages = pages;
        allocations[i].released = 0;
        live_pages += pages;
        ++mapped_allocations;
        return allocations[i].base;
    }
    abort();
}

void arch_vm_free_mapped_pages(void *address, uint64_t pages) {
    assert(!g_exec_payload_lock.v);
    for (uint32_t i = 0; i < KERNEL_EXEC_PAYLOAD_SLOT_COUNT; ++i) {
        if (allocations[i].base != address) continue;
        assert(allocations[i].pages == pages && allocations[i].released == 0);
        free(allocations[i].base);
        allocations[i].base = 0;
        live_pages -= pages;
        return;
    }
    abort();
}

static uint8_t user_bytes[LINUX_EXEC_STRING_MAX + 8192u];
static uint64_t user_limit;
static uint32_t user_reads;

static int capture_copy(void *context, void *destination,
                        uint64_t source, uint64_t size) {
    (void)context;
    ++user_reads;
    if (source < 0x10000u || source - 0x10000u > user_limit ||
        size > user_limit - (source - 0x10000u))
        return -1;
    memcpy(destination, user_bytes + (source - 0x10000u), size);
    return 0;
}

static int wrapping_copy(void *context, void *destination,
                         uint64_t source, uint64_t size) {
    (void)context;
    ++user_reads;
    memset(destination, source == UINT64_MAX ? 'x' : 0, size);
    return 0;
}

static void test_capture_boundaries(void) {
    linux_exec_payload_t *payload = calloc(1, sizeof(*payload));
    assert(payload);
    for (uint8_t width = 4; width <= 8; width += 4) {
        uint64_t address = 0x11000u;
        memset(user_bytes, 0, sizeof(user_bytes));
        memcpy(user_bytes, &address, width);
        memcpy(user_bytes + 4096, "argument", 9);
        user_limit = 8192;
        linux_exec_payload_reset(payload);
        assert(linux_exec_payload_capture_vector_with(
            payload, 0, capture_copy, 0x10000u, width, 0) == 0);
        assert(payload->argc == 1 && payload->envc == 0);
        assert(strcmp(linux_exec_payload_argument(payload, 0), "argument") == 0);
    }
    linux_exec_payload_reset(payload);
    user_limit = 4096;
    user_bytes[4095] = 0;
    assert(payload_append_user_string(payload, 0, capture_copy,
                                      0x10fffu, 0) == 0);
    assert(payload->bytes_used == 1);
    linux_exec_payload_reset(payload);
    user_bytes[4095] = 'x';
    assert(payload_append_user_string(payload, 0, capture_copy,
                                      0x10fffu, 0) == -EDGE_LINUX_EFAULT);
    assert(payload->argc == 0 && payload->bytes_used == 0);

    user_limit = sizeof(user_bytes);
    memset(user_bytes, 'x', sizeof(user_bytes));
    user_bytes[LINUX_EXEC_STRING_MAX - 1] = 0;
    assert(payload_append_user_string(payload, 0, capture_copy,
                                      0x10000u, 0) == 0);
    assert(payload->bytes_used == LINUX_EXEC_STRING_MAX);
    linux_exec_payload_reset(payload);
    user_bytes[LINUX_EXEC_STRING_MAX - 1] = 'x';
    assert(payload_append_user_string(payload, 0, capture_copy,
                                      0x10000u, 0) == -EDGE_LINUX_E2BIG);
    assert(payload->argc == 0 && payload->bytes_used == 0);

    /* Leave exactly four string bytes after the new pointer and sentinels. */
    payload->bytes_used = LINUX_EXEC_BYTES_MAX - 24u - 4u;
    memcpy(user_bytes, "abc", 4);
    assert(payload_append_user_string(payload, 0, capture_copy,
                                      0x10000u, 1) == 0);
    assert(payload->envc == 1 && payload->argc == 0);
    linux_exec_payload_reset(payload);
    payload->bytes_used = LINUX_EXEC_BYTES_MAX - 24u - 3u;
    assert(payload_append_user_string(payload, 0, capture_copy,
                                      0x10000u, 0) == -EDGE_LINUX_E2BIG);
    assert(payload->argc == 0);
    linux_exec_payload_reset(payload);
    assert(payload_append_user_string(payload, 0, capture_copy,
                                      UINT64_MAX, 0) == -EDGE_LINUX_EFAULT);
    user_reads = 0;
    assert(payload_append_user_string(payload, 0, wrapping_copy,
                                      UINT64_MAX, 0) == -EDGE_LINUX_EFAULT);
    assert(user_reads == 1 && payload->argc == 0);
    free(payload);
    puts("exec_payload_capture_boundaries: PASS");
}

int main(void) {
    test_capture_boundaries();
    kernel_exec_payload_slot_t slots[2];
    kernel_exec_payload_handle_t first, second, stale, extra;
    linux_exec_payload_t *one, *two, *unused;
    void *cache;
    assert(kernel_exec_payload_pool_bytes() <= EDGE_PAGE_SIZE);
    assert(kernel_exec_payload_pool_bytes_for_slots(0) == 0);
    assert(kernel_exec_payload_pool_initialize(slots, sizeof(slots) - 1, 2) < 0);
    assert(kernel_exec_payload_pool_initialize(slots, sizeof(slots), 2) == 0);
    assert(live_pages == 0);
    fail_allocation = 1;
    assert(kernel_exec_payload_acquire(1, &first, &one) == -EDGE_LINUX_ENOMEM);
    assert(!first.slot && !one && live_pages == 0);
    fail_allocation = 0;
    cache = calloc(1, kernel_exec_payload_cache_bytes(1));
    assert(cache);
    assert(kernel_exec_payload_cache_initialize(
        cache, kernel_exec_payload_cache_bytes(1), 1) == 0);
    assert(kernel_exec_payload_acquire(1, &first, &one) == 0);
    assert(kernel_exec_payload_acquire(2, &second, &two) == 0);
    assert(one != two && live_pages == EXEC_PAYLOAD_PAGES);
    assert(kernel_exec_payload_acquire(3, &extra, &unused) == -EDGE_LINUX_ENOMEM);
    assert(linux_exec_payload_append(one, "first", 0, 0) == 0);
    assert(linux_exec_payload_append(two, "second", 0, 0) == 0);
    assert(strcmp(linux_exec_payload_argument(one, 0), "first") == 0);
    stale = first;
    kernel_exec_payload_release(&first);
    kernel_exec_payload_release(&first);
    assert(live_pages == EXEC_PAYLOAD_PAGES);
    assert(kernel_exec_payload_acquire(3, &first, &one) == 0);
    assert(one->argc == 0 && one->envc == 0 && one->bytes_used == 0);
    kernel_exec_payload_release(&stale);
    assert(live_pages == EXEC_PAYLOAD_PAGES);
    kernel_exec_payload_release(&first);
    assert(strcmp(linux_exec_payload_argument(two, 0), "second") == 0);
    kernel_exec_payload_release(&second);
    assert(live_pages == 0);
    for (uint32_t iteration = 0; iteration < 100; ++iteration) {
        assert(kernel_exec_payload_acquire(4, &first, &one) == 0);
        kernel_exec_payload_release(&first);
        assert(live_pages == 0);
    }
    free(cache);
    puts("exec_payload_lifetime_unit: PASS");
    kernel_exec_record_t *records[2];
    assert(kernel_exec_record_pool_bytes(2) == sizeof(records));
    assert(kernel_exec_record_pool_initialize(records, sizeof(records) - 1, 2) < 0);
    assert(kernel_exec_record_pool_initialize(records, sizeof(records), 2) == 0);
    assert(!kernel_exec_record_space(0) && !kernel_exec_record_acquire(2));
    assert(live_pages == 0);
    fail_mapped_allocation = 1;
    assert(!kernel_exec_record_acquire(0));
    assert(!kernel_exec_record_space(0) && live_pages == 0);
    fail_mapped_allocation = 0;
    fail_allocation = 1;
    for (unsigned round = 0; round < 100; ++round) {
        kernel_exec_record_t *parent = kernel_exec_record_acquire(0);
        kernel_exec_record_t *child = kernel_exec_record_acquire(1);
        assert(parent && child && parent != child);
        assert(kernel_exec_record_acquire(0) == parent);
        assert(parent->argc == 0 && parent->envc == 0 && parent->bytes_used == 0);
        assert(kernel_exec_record_append(parent, "/bin/busybox", 0, 0) == 0);
        assert(kernel_exec_record_append(parent, "PATH=/bin", 1, 0) == 0);
        assert(kernel_exec_record_copy(child, parent) == 0);
        assert(child->arguments[0] != parent->arguments[0]);
        assert(kernel_exec_record_contains(child, child->arguments[0]));
        assert(!kernel_exec_record_contains(parent, child->arguments[0]));
        kernel_exec_record_release(0);
        kernel_exec_record_release(0);
        assert(!kernel_exec_record_space(0));
        assert(strcmp(child->arguments[0], "/bin/busybox") == 0);
        assert(strcmp(child->environment[0], "PATH=/bin") == 0);
        kernel_exec_record_reset(child);
        assert(child->argc == 0 && child->envc == 0 && child->bytes_used == 0);
        kernel_exec_record_release(1);
        kernel_exec_record_release(2);
        assert(live_pages == 0);
    }
    assert(mapped_allocations == 200);
    puts("exec_record_lifetime_unit: PASS");
    return 0;
}
