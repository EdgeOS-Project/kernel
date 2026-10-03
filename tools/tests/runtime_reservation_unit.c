/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define USER_PAGE_SIZE 4096u
static int g_mmap_backing_indices_frozen;
static uint32_t g_user_mmap_backing_ready_pages;
static uint64_t g_user_mmap_backing_phys[8];
static uint8_t memory[8 * USER_PAGE_SIZE];
static unsigned allocation_calls;
static int allocation_failure;

static uintptr_t edge_mmio_low_alias(uint64_t physical) {
    return (uintptr_t)memory + physical;
}

static uint64_t fixed_user_pt_phys_from_ptr(const uint64_t *pointer) {
    return (uintptr_t)pointer - (uintptr_t)memory;
}

static void *process_user_mmap_alloc_contiguous_backing_pages(uint32_t pages) {
    ++allocation_calls;
    assert(pages == 1);
    return allocation_failure ? 0 : memory + 6 * USER_PAGE_SIZE;
}

/* Generated from the production functions by run_memory_units.sh. */
#include "runtime_reservation.inc"

int main(void) {
    void *result = (void *)1;
    uint64_t physical = 1;
    uint64_t identities[8];
    for (unsigned i = 0; i < 8; ++i)
        g_user_mmap_backing_phys[i] = (i + 1) * USER_PAGE_SIZE;
    g_user_mmap_backing_ready_pages = 8;
    assert(process_kernel_runtime_reserve_pages(1, &result, &physical) == 0);
    assert(physical == 8 * USER_PAGE_SIZE);
    assert(g_user_mmap_backing_ready_pages == 7 && allocation_calls == 0);

    g_mmap_backing_indices_frozen = 1;
    memcpy(identities, g_user_mmap_backing_phys, sizeof(identities));
    memset(memory, 0x5a, sizeof(memory));
    assert(process_kernel_runtime_reserve_pages(1, &result, &physical) == 0);
    assert(result == memory + 6 * USER_PAGE_SIZE && allocation_calls == 1);
    assert(physical == 6 * USER_PAGE_SIZE);
    assert(g_user_mmap_backing_ready_pages == 7);
    assert(memcmp(identities, g_user_mmap_backing_phys, sizeof(identities)) == 0);
    assert(memory[0] == 0x5a && memory[5 * USER_PAGE_SIZE] == 0x5a);
    assert(mmap_backing_carve_contiguous_tail_pages(1, &physical) < 0);
    assert(physical == 0 && g_user_mmap_backing_ready_pages == 7);

    allocation_failure = 1;
    result = (void *)1;
    physical = 1;
    assert(process_kernel_runtime_reserve_pages(1, &result, &physical) < 0);
    assert(!result && physical == 0);
    assert(process_kernel_runtime_reserve_pages(0, &result, &physical) < 0);
    assert(memcmp(identities, g_user_mmap_backing_phys, sizeof(identities)) == 0);
    puts("runtime_reservation_unit: PASS");
    return 0;
}
