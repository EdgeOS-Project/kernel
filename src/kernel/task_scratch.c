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
#include "string.h"

static kernel_task_scratch_t *g_task_scratch;
static uint32_t g_task_scratch_count;
static kernel_task_wait_scratch_t *g_task_wait_scratch;
static uint32_t g_task_wait_scratch_count;

static uint64_t checked_pool_bytes(uint32_t count, uint64_t element_size) {
    if (!count || !element_size ||
        (uint64_t)count > UINT64_MAX / element_size)
        return 0;
    return (uint64_t)count * element_size;
}

uint64_t kernel_task_scratch_pool_bytes(uint32_t task_count) {
    return checked_pool_bytes(task_count, sizeof(kernel_task_scratch_t));
}

int kernel_task_scratch_pool_initialize(void *memory, uint64_t size,
                                        uint32_t task_count) {
    uint64_t required = kernel_task_scratch_pool_bytes(task_count);
    if (!memory || !required || size < required || required > UINT32_MAX)
        return -EDGE_LINUX_ENOMEM;
    g_task_scratch = (kernel_task_scratch_t *)memory;
    g_task_scratch_count = task_count;
    memset(g_task_scratch, 0, (uint32_t)required);
    return 0;
}

kernel_task_scratch_t *kernel_task_scratch_space(uint32_t task_index) {
    if (!g_task_scratch || task_index >= g_task_scratch_count) return 0;
    return &g_task_scratch[task_index];
}

uint64_t kernel_task_wait_scratch_pool_bytes(uint32_t task_count) {
    return checked_pool_bytes(task_count,
                              sizeof(kernel_task_wait_scratch_t));
}

int kernel_task_wait_scratch_pool_initialize(void *memory, uint64_t size,
                                             uint32_t task_count) {
    uint64_t required = kernel_task_wait_scratch_pool_bytes(task_count);
    if (!memory || !required || size < required || required > UINT32_MAX)
        return -EDGE_LINUX_ENOMEM;
    g_task_wait_scratch = (kernel_task_wait_scratch_t *)memory;
    g_task_wait_scratch_count = task_count;
    memset(g_task_wait_scratch, 0, (uint32_t)required);
    return 0;
}

kernel_task_wait_scratch_t *kernel_task_wait_scratch_space(
    uint32_t task_index) {
    if (!g_task_wait_scratch || task_index >= g_task_wait_scratch_count)
        return 0;
    return &g_task_wait_scratch[task_index];
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
