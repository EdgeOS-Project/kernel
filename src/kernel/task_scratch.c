/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral task syscall scratch storage.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include "kernel/futex_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/task_scratch.h"
#include "mm/arch_vm.h"
#include "string.h"

static kernel_task_scratch_t **g_task_scratch;
static uint32_t g_task_scratch_count;
static kernel_task_wait_scratch_t **g_task_wait_scratch;
static uint32_t g_task_wait_scratch_count;

static uint64_t checked_pool_bytes(uint32_t count, uint64_t element_size) {
    if (!count || !element_size ||
        (uint64_t)count > UINT64_MAX / element_size)
        return 0;
    return (uint64_t)count * element_size;
}

uint64_t kernel_task_scratch_pool_bytes(uint32_t task_count) {
    return checked_pool_bytes(task_count, sizeof(g_task_scratch[0]));
}

int kernel_task_scratch_pool_initialize(void *memory, uint64_t size,
                                        uint32_t task_count) {
    uint64_t required = kernel_task_scratch_pool_bytes(task_count);
    if (!memory || !required || size < required || required > UINT32_MAX)
        return -EDGE_LINUX_ENOMEM;
    g_task_scratch = (kernel_task_scratch_t **)memory;
    g_task_scratch_count = task_count;
    memset(g_task_scratch, 0, (uint32_t)required);
    return 0;
}

kernel_task_scratch_t *kernel_task_scratch_space(uint32_t task_index) {
    if (!g_task_scratch || task_index >= g_task_scratch_count) return 0;
    if (!g_task_scratch[task_index]) {
        uint64_t pages = (sizeof(kernel_task_scratch_t) + EDGE_PAGE_SIZE - 1u) /
                         EDGE_PAGE_SIZE;
        void *memory = arch_vm_alloc_mapped_pages(pages);
        if (!memory) return 0;
        memset(memory, 0, pages * EDGE_PAGE_SIZE);
        g_task_scratch[task_index] = memory;
    }
    return g_task_scratch[task_index];
}

uint64_t kernel_task_wait_scratch_pool_bytes(uint32_t task_count) {
    return checked_pool_bytes(task_count,
                              sizeof(g_task_wait_scratch[0]));
}

int kernel_task_wait_scratch_pool_initialize(void *memory, uint64_t size,
                                             uint32_t task_count) {
    uint64_t required = kernel_task_wait_scratch_pool_bytes(task_count);
    if (!memory || !required || size < required || required > UINT32_MAX)
        return -EDGE_LINUX_ENOMEM;
    g_task_wait_scratch = (kernel_task_wait_scratch_t **)memory;
    g_task_wait_scratch_count = task_count;
    memset(g_task_wait_scratch, 0, (uint32_t)required);
    return 0;
}

kernel_task_wait_scratch_t *kernel_task_wait_scratch_space(
    uint32_t task_index) {
    if (!g_task_wait_scratch || task_index >= g_task_wait_scratch_count)
        return 0;
    if (!g_task_wait_scratch[task_index]) {
        uint64_t pages = (sizeof(kernel_task_wait_scratch_t) + EDGE_PAGE_SIZE - 1u) /
                         EDGE_PAGE_SIZE;
        void *memory = arch_vm_alloc_mapped_pages(pages);
        if (!memory) return 0;
        memset(memory, 0, pages * EDGE_PAGE_SIZE);
        g_task_wait_scratch[task_index] = memory;
    }
    return g_task_wait_scratch[task_index];
}

static void scratch_pages_release(void *memory, uint64_t bytes) {
    if (!memory) return;
    uint64_t pages = (bytes + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE;
    for (uint64_t page = 0; page < pages; ++page)
        arch_vm_free_page((uint8_t *)memory + page * EDGE_PAGE_SIZE);
}

void kernel_task_scratch_release(uint32_t task_index) {
    if (g_task_scratch && task_index < g_task_scratch_count) {
        kernel_task_scratch_t *memory = g_task_scratch[task_index];
        g_task_scratch[task_index] = 0;
        if (memory && memory->block_io_scratch)
            scratch_pages_release(
                memory->block_io_scratch,
                memory->block_io_scratch_capacity);
        if (memory && memory->block_readahead_scratch)
            scratch_pages_release(
                memory->block_readahead_scratch,
                memory->block_readahead_scratch_capacity);
        if (memory && memory->loop_io_scratch)
            scratch_pages_release(
                memory->loop_io_scratch,
                memory->loop_io_scratch_capacity);
        if (memory && memory->filesystem_io_scratch)
            scratch_pages_release(
                memory->filesystem_io_scratch,
                memory->filesystem_io_scratch_capacity);
        arch_vm_free_mapped_pages(
            memory, (sizeof(*memory) + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE);
    }
    if (g_task_wait_scratch && task_index < g_task_wait_scratch_count) {
        kernel_task_wait_scratch_t *memory = g_task_wait_scratch[task_index];
        g_task_wait_scratch[task_index] = 0;
        arch_vm_free_mapped_pages(
            memory, (sizeof(*memory) + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE);
    }
}

void *kernel_task_block_scratch_acquire(uint32_t capacity) {
    kernel_task_scratch_t *scratch = arch_task_scratch_current();
    uint64_t pages;
    void *memory;

    if (!scratch || !capacity) return 0;
    if (scratch->block_io_scratch_capacity >= capacity)
        return scratch->block_io_scratch;
    pages = ((uint64_t)capacity + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE;
    memory = arch_vm_alloc_pages(pages);
    if (!memory) return 0;
    memset(memory, 0, pages * EDGE_PAGE_SIZE);
    if (scratch->block_io_scratch)
        scratch_pages_release(
            scratch->block_io_scratch,
            scratch->block_io_scratch_capacity);
    scratch->block_io_scratch = memory;
    scratch->block_io_scratch_capacity = (uint32_t)(pages * EDGE_PAGE_SIZE);
    return memory;
}

void *kernel_task_block_readahead_scratch_acquire(uint32_t capacity) {
    kernel_task_scratch_t *scratch = arch_task_scratch_current();
    uint64_t pages;
    void *memory;

    if (!scratch || !capacity) return 0;
    if (scratch->block_readahead_scratch_capacity >= capacity)
        return scratch->block_readahead_scratch;
    pages = ((uint64_t)capacity + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE;
    memory = arch_vm_alloc_pages(pages);
    if (!memory) return 0;
    memset(memory, 0, pages * EDGE_PAGE_SIZE);
    if (scratch->block_readahead_scratch)
        scratch_pages_release(
            scratch->block_readahead_scratch,
            scratch->block_readahead_scratch_capacity);
    scratch->block_readahead_scratch = memory;
    scratch->block_readahead_scratch_capacity =
        (uint32_t)(pages * EDGE_PAGE_SIZE);
    return memory;
}

void *kernel_task_loop_io_scratch_acquire(uint32_t capacity) {
    kernel_task_scratch_t *scratch = arch_task_scratch_current();
    uint64_t pages;
    void *memory;

    if (!scratch || !capacity) return 0;
    if (scratch->loop_io_scratch_capacity >= capacity)
        return scratch->loop_io_scratch;
    pages = ((uint64_t)capacity + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE;
    memory = arch_vm_alloc_pages(pages);
    if (!memory) return 0;
    memset(memory, 0, pages * EDGE_PAGE_SIZE);
    if (scratch->loop_io_scratch)
        scratch_pages_release(
            scratch->loop_io_scratch,
            scratch->loop_io_scratch_capacity);
    scratch->loop_io_scratch = memory;
    scratch->loop_io_scratch_capacity = (uint32_t)(pages * EDGE_PAGE_SIZE);
    return memory;
}

void *kernel_task_filesystem_scratch_acquire(uint32_t capacity) {
    kernel_task_scratch_t *scratch = arch_task_scratch_current();
    uint64_t pages;
    void *memory;

    if (!scratch || !capacity) return 0;
    if (scratch->filesystem_io_scratch_capacity >= capacity)
        return scratch->filesystem_io_scratch;
    pages = ((uint64_t)capacity + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE;
    memory = arch_vm_alloc_pages(pages);
    if (!memory) return 0;
    memset(memory, 0, pages * EDGE_PAGE_SIZE);
    if (scratch->filesystem_io_scratch)
        scratch_pages_release(
            scratch->filesystem_io_scratch,
            scratch->filesystem_io_scratch_capacity);
    scratch->filesystem_io_scratch = memory;
    scratch->filesystem_io_scratch_capacity =
        (uint32_t)(pages * EDGE_PAGE_SIZE);
    return memory;
}

void *kernel_task_filesystem_metadata_scratch(void) {
    kernel_task_scratch_t *scratch = arch_task_scratch_current();

    return scratch ? scratch->filesystem_metadata_scratch : 0;
}

int kernel_io_current_vector_scratch(kernel_io_vector_scratch_t *scratch) {
    kernel_task_scratch_t *task_scratch = arch_task_scratch_current();

    if (!task_scratch || !scratch) return -EDGE_LINUX_EINVAL;
    scratch->vectors =
        (struct edge_linux_iovec *)(void *)task_scratch->xattr_scratch;
    scratch->capacity = sizeof(task_scratch->xattr_scratch) /
                        sizeof(scratch->vectors[0]);
    return 0;
}

int kernel_io_file_range_current_scratch(
    kernel_io_file_range_scratch_t *scratch) {
    kernel_task_scratch_t *task_scratch = arch_task_scratch_current();

    if (!task_scratch || !scratch) return -EDGE_LINUX_EINVAL;
    scratch->buffer = task_scratch->path_scratch[2];
    scratch->capacity = sizeof(task_scratch->path_scratch[2]);
    return 0;
}

int kernel_process_vm_current_scratch(kernel_process_vm_scratch_t *scratch) {
    kernel_task_scratch_t *task_scratch = arch_task_scratch_current();

    if (!task_scratch || !scratch) return -EDGE_LINUX_EINVAL;
    scratch->buffer = task_scratch->path_scratch[2];
    scratch->capacity = sizeof(task_scratch->path_scratch[2]);
    return 0;
}

int kernel_futex_current_scratch(kernel_futex_scratch_t *scratch) {
    kernel_task_scratch_t *task_scratch = arch_task_scratch_current();
    uintptr_t base;
    uintptr_t aligned;
    uintptr_t end;

    if (!task_scratch || !scratch) return -EDGE_LINUX_EINVAL;
    base = (uintptr_t)task_scratch->xattr_scratch;
    end = base + sizeof(task_scratch->xattr_scratch);
    aligned = (base + 7u) & ~(uintptr_t)7u;
    scratch->memory = (void *)aligned;
    scratch->capacity = (uint32_t)(end - aligned);
    return 0;
}
