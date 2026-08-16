/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS current-task scratch policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>

#include "kernel/futex_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/task_scratch.h"

static int g_failures;
static int g_current_available = 1;
static kernel_task_scratch_t g_current_scratch;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

kernel_task_scratch_t *arch_task_scratch_current(void) {
    return g_current_available ? &g_current_scratch : 0;
}

static void test_current_buffers(void) {
    kernel_io_vector_scratch_t vectors;
    kernel_io_file_range_scratch_t file_range;
    kernel_process_vm_scratch_t process_vm;
    kernel_futex_scratch_t futex;
    uintptr_t futex_start;
    uintptr_t storage_start =
        (uintptr_t)g_current_scratch.xattr_scratch;
    uintptr_t storage_end =
        storage_start + sizeof(g_current_scratch.xattr_scratch);

    expect_true("vector scratch",
                kernel_io_current_vector_scratch(&vectors) == 0 &&
                (void *)vectors.vectors ==
                    (void *)g_current_scratch.xattr_scratch &&
                vectors.capacity ==
                    sizeof(g_current_scratch.xattr_scratch) /
                    sizeof(vectors.vectors[0]));
    expect_true("file range scratch",
                kernel_io_file_range_current_scratch(&file_range) == 0 &&
                file_range.buffer ==
                    g_current_scratch.path_scratch[2] &&
                file_range.capacity ==
                    sizeof(g_current_scratch.path_scratch[2]));
    expect_true("process vm scratch",
                kernel_process_vm_current_scratch(&process_vm) == 0 &&
                process_vm.buffer ==
                    g_current_scratch.path_scratch[2] &&
                process_vm.capacity ==
                    sizeof(g_current_scratch.path_scratch[2]));
    expect_true("futex scratch",
                kernel_futex_current_scratch(&futex) == 0);
    futex_start = (uintptr_t)futex.memory;
    expect_true("futex alignment", (futex_start & 7u) == 0u);
    expect_true("futex range",
                futex_start >= storage_start &&
                futex_start + futex.capacity == storage_end);
}

static void test_missing_context(void) {
    kernel_io_vector_scratch_t vectors;
    kernel_io_file_range_scratch_t file_range;
    kernel_process_vm_scratch_t process_vm;
    kernel_futex_scratch_t futex;

    g_current_available = 0;
    expect_true("missing vector context",
                kernel_io_current_vector_scratch(&vectors) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("missing file range context",
                kernel_io_file_range_current_scratch(&file_range) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("missing process vm context",
                kernel_process_vm_current_scratch(&process_vm) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("missing futex context",
                kernel_futex_current_scratch(&futex) ==
                    -EDGE_LINUX_EINVAL);
}

int main(void) {
    test_current_buffers();
    test_missing_context();
    if (g_failures) return 1;
    puts("task_scratch_current_unit: PASS");
    return 0;
}
