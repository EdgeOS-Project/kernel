/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent OverlayFS dynamic-capacity test. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "kernel/task_scratch.h"
#include "mm/arch_vm.h"
#include "vfs/vfs.h"

static kernel_task_scratch_t g_scratch_owner;
static uint64_t g_allocated_pages;
static uint64_t g_released_pages;
static uint32_t g_upper_sync_calls;
static uint32_t g_scheduler_yield_calls;
static void *g_lock_to_release;

static int test_upper_sync(vfs_superblock_t *superblock) {
    assert(superblock != 0);
    ++g_upper_sync_calls;
    return 0;
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    g_allocated_pages += page_count;
    return calloc((size_t)page_count, 4096u);
}

void arch_vm_free_page(void *page) {
    (void)page;
    ++g_released_pages;
}

kernel_task_scratch_t *arch_task_scratch_current(void) {
    return &g_scratch_owner;
}

void vfs_superblock_release(vfs_superblock_t *superblock) {
    (void)superblock;
}

#include "../../src/fs/overlayfs.c"

void scheduler_yield(void) {
    overlay_state_t *state = (overlay_state_t *)g_lock_to_release;

    ++g_scheduler_yield_calls;
    if (state)
        __atomic_store_n(&state->operation_lock, 0u, __ATOMIC_RELEASE);
}

int main(void) {
    overlay_state_t *state;
    overlay_path_stack_t stack;
    overlay_scratch_context_t *contexts[17];
    overlay_state_t *context_states[17];
    vfs_superblock_t upper_superblock;
    filesystem_ops_t upper_operations;

    state = overlay_state_allocate();
    assert(state != 0);
    assert(overlay_node_reserve(state, 1u) == 0);
    assert(state->node_capacity == OVERLAY_INITIAL_NODES);
    state->nodes[1].used = 1u;
    strcpy(state->nodes[1].rel, "preserved");
    assert(overlay_node_reserve(state, 700u) == 0);
    assert(state->node_capacity >= 700u);
    assert(state->nodes[1].used == 1u);
    assert(strcmp(state->nodes[1].rel, "preserved") == 0);

    state->lower_count = 300u;
    assert(overlay_lower_backends_allocate(state) == 0);
    assert(state->lower_backends != 0);
    state->lower_backends[299].superblock = &state->superblock;
    assert(state->lower_backends[299].superblock == &state->superblock);

    memset(&upper_superblock, 0, sizeof(upper_superblock));
    memset(&upper_operations, 0, sizeof(upper_operations));
    upper_operations.sync = test_upper_sync;
    upper_superblock.ops = &upper_operations;
    state->superblock.fs_private = state;
    state->upper_backend.superblock = &upper_superblock;
    assert(overlay_sync_op(&state->superblock) == 0);
    assert(g_upper_sync_calls == 1u);
    assert(state->operation_lock == 0u);

    state->operation_lock = 1u;
    g_lock_to_release = state;
    overlay_operation_lock(state);
    g_lock_to_release = 0;
    assert(g_scheduler_yield_calls == 1u);
    assert(state->operation_lock == 1u);
    overlay_operation_unlock(state);

    memset(&stack, 0, sizeof(stack));
    assert(overlay_path_stack_reserve(&stack, 1u) == 0);
    strcpy(overlay_path_stack_at(&stack, 0u), "preserved");
    assert(overlay_path_stack_reserve(&stack, 700u) == 0);
    assert(stack.capacity >= 700u);
    assert(strcmp(overlay_path_stack_at(&stack, 0u), "preserved") == 0);
    strcpy(overlay_path_stack_at(&stack, 699u), "last");
    assert(strcmp(overlay_path_stack_at(&stack, 699u), "last") == 0);
    overlay_path_stack_release(&stack);

    for (uint32_t index = 0; index < 17u; ++index) {
        context_states[index] = overlay_state_allocate();
        assert(context_states[index] != 0);
        contexts[index] = overlay_scratch_acquire(context_states[index]);
        assert(contexts[index] != 0);
    }
    assert(g_overlay_dynamic_scratch_contexts != 0);
    for (uint32_t index = 0; index < 17u; ++index) {
        overlay_scratch_release(context_states[index], contexts[index]);
        overlay_state_destroy(context_states[index]);
    }

    overlay_state_destroy(state);
    assert(g_allocated_pages > 700u);
    assert(g_released_pages > 700u);
    printf("overlayfs_capacity_unit: PASS\n");
    return 0;
}
