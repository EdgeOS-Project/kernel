/* SPDX-License-Identifier: MPL-2.0 */
/* Host tests for the FreeBSD-compatible linear address allocator. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/sync.h"
#include <sys/vmem.h>

#define TEST_PAGE_SIZE 4096u

typedef struct import_context {
    vmem_addr_t next_address;
    vmem_addr_t released_address;
    vmem_size_t imported_size;
    vmem_size_t released_size;
    unsigned int import_calls;
    unsigned int release_calls;
} import_context_t;

static uintptr_t g_thread_token;
static vmem_addr_t g_reclaim_address;
static vmem_size_t g_reclaim_size;
static unsigned int g_reclaim_calls;

void
bsd_kthread_wakeup(const void *channel, int one)
{
    (void)channel;
    (void)one;
}

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)page_count * TEST_PAGE_SIZE) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    (free)(base);
}

static void *
test_current_thread(void *context)
{
    (void)context;
    return &g_thread_token;
}

static int
test_can_block(void *thread, void *context)
{
    (void)thread;
    (void)context;
    return 0;
}

static void
test_unexpected_block(void *thread, void *context)
{
    (void)thread;
    (void)context;
    abort();
}

static void
test_wake(void *thread, void *context)
{
    (void)thread;
    (void)context;
}

static void
test_yield(void *context)
{
    (void)context;
}

static void
test_fatal(const char *message, void *context)
{
    (void)message;
    (void)context;
    abort();
}

static int
test_import(void *argument, vmem_size_t size, int flags,
    vmem_addr_t *address)
{
    import_context_t *context = argument;

    (void)flags;
    assert(context != 0);
    assert(address != 0);
    context->import_calls++;
    context->imported_size = size;
    *address = context->next_address;
    context->next_address += size + 0x100u;
    return 0;
}

static void
test_release(void *argument, vmem_addr_t address, vmem_size_t size)
{
    import_context_t *context = argument;

    assert(context != 0);
    context->release_calls++;
    context->released_address = address;
    context->released_size = size;
}

static void
test_reclaim(vmem_t *arena, int flags)
{
    (void)flags;
    g_reclaim_calls++;
    vmem_free(arena, g_reclaim_address, g_reclaim_size);
}

static void
test_fit_policies(void)
{
    vmem_t *arena;
    vmem_addr_t address;
    vmem_addr_t first;
    vmem_addr_t second;
    vmem_addr_t third;
    vmem_addr_t fourth;
    vmem_addr_t fifth;

    arena = vmem_create("best", 0, 100, 1, 0, M_WAITOK);
    assert(arena != 0);
    assert(vmem_alloc(arena, 10, M_FIRSTFIT, &first) == 0 && first == 0);
    assert(vmem_alloc(arena, 30, M_FIRSTFIT, &second) == 0 && second == 10);
    assert(vmem_alloc(arena, 10, M_FIRSTFIT, &third) == 0 && third == 40);
    assert(vmem_alloc(arena, 20, M_FIRSTFIT, &fourth) == 0 && fourth == 50);
    assert(vmem_alloc(arena, 30, M_FIRSTFIT, &fifth) == 0 && fifth == 70);
    vmem_free(arena, second, 30);
    vmem_free(arena, fourth, 20);
    assert(vmem_alloc(arena, 15, M_BESTFIT, &address) == 0);
    assert(address == 50);
    assert(vmem_size(arena, VMEM_ALLOC) == 65);
    assert(vmem_size(arena, VMEM_FREE) == 35);
    assert(vmem_size(arena, VMEM_MAXFREE) == 30);
    vmem_destroy(arena);

    arena = vmem_create("next", 0, 64, 1, 0, M_WAITOK);
    assert(arena != 0);
    assert(vmem_alloc(arena, 16, M_NEXTFIT, &address) == 0);
    assert(address == 0);
    vmem_free(arena, address, 16);
    assert(vmem_alloc(arena, 8, M_NEXTFIT, &address) == 0);
    assert(address == 16);
    assert(vmem_alloc(arena, 40, M_NEXTFIT, &address) == 0);
    assert(address == 24);
    vmem_free(arena, address, 40);
    assert(vmem_alloc(arena, 8, M_NEXTFIT, &address) == 0);
    assert(address == 0);
    vmem_destroy(arena);
}

static void
test_constraints_and_limits(void)
{
    vmem_t *arena;
    vmem_addr_t address;

    arena = vmem_create("constraints", 0, 256, 1, 0, M_WAITOK);
    assert(arena != 0);
    assert(vmem_xalloc(arena, 16, 64, 8, 128, 0, 255,
        M_FIRSTFIT, &address) == 0);
    assert(address == 8);
    assert(vmem_xalloc(arena, 80, 64, 0, 128, 0, 255,
        M_FIRSTFIT, &address) == 0);
    assert(address == 128);
    assert(vmem_xalloc(arena, 1, 16, 16, 0, 0, 255,
        M_FIRSTFIT, &address) == 22);
    vmem_destroy(arena);

    arena = vmem_create("limit", 0, 0, 8, 0, M_WAITOK);
    assert(arena != 0);
    vmem_set_limit(arena, 16);
    assert(vmem_add(arena, 0, 24, M_WAITOK) == 28);
    assert(vmem_add(arena, 0, 16, M_WAITOK) == 0);
    assert(vmem_add(arena, 32, SIZE_MAX, M_WAITOK) == 28);
    assert(vmem_roundup_size(arena, 9) == 16);
    vmem_destroy(arena);
}

static void
test_import_and_reclaim(void)
{
    import_context_t context = {
        .next_address = 0x1000u,
    };
    vmem_t *arena;
    vmem_addr_t address;

    arena = vmem_create("import", 0, 0, 8, 0, M_WAITOK);
    assert(arena != 0);
    vmem_set_import(arena, test_import, test_release, &context, 64);
    assert(vmem_alloc(arena, 16, M_FIRSTFIT, &address) == 0);
    assert(address == 0x1000u);
    assert(context.import_calls == 1);
    assert(context.imported_size == 64);
    assert(vmem_size(arena, VMEM_ALLOC) == 16);
    assert(vmem_size(arena, VMEM_FREE) == 48);
    vmem_destroy(arena);
    assert(context.release_calls == 1);
    assert(context.released_address == 0x1000u);
    assert(context.released_size == 64);

    arena = vmem_create("reclaim", 0, 16, 1, 0, M_WAITOK);
    assert(arena != 0);
    assert(vmem_alloc(arena, 16, M_FIRSTFIT, &g_reclaim_address) == 0);
    g_reclaim_size = 16;
    g_reclaim_calls = 0;
    vmem_set_reclaim(arena, test_reclaim);
    assert(vmem_alloc(arena, 8, M_FIRSTFIT, &address) == 0);
    assert(address == 0);
    assert(g_reclaim_calls == 1);
    vmem_destroy(arena);
}

int
main(void)
{
    bsd_allocator_ops_t allocator = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    bsd_sync_ops_t synchronization = {
        .current_thread = test_current_thread,
        .can_block = test_can_block,
        .prepare_block = test_unexpected_block,
        .block_current = test_unexpected_block,
        .wake_thread = test_wake,
        .yield_thread = test_yield,
        .fatal = test_fatal,
    };

    assert(bsd_allocator_initialize(&allocator) == 0);
    assert(bsd_sync_initialize(&synchronization) == 0);
    test_fit_policies();
    test_constraints_and_limits();
    test_import_and_reclaim();
    printf("bsd_bridge_vmem_unit: PASS\n");
    return 0;
}
