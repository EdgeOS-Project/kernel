/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Shared bounded bounce buffers for architecture-neutral kernel I/O.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/io_buffer.h"
#include "kernel/process_runtime.h"
#include "mm/arch_vm.h"

#define KERNEL_IO_BUFFER_SLOTS 32u
#define KERNEL_IO_BUFFER_PAGE_SIZE 4096u

static uint8_t *g_io_buffer_storage;
static volatile int32_t g_io_buffer_state;
static volatile uint32_t g_io_buffer_busy;
static volatile uint32_t g_io_buffer_cursor;

static int kernel_io_buffer_prepare(void) {
    int32_t state = __atomic_load_n(&g_io_buffer_state, __ATOMIC_ACQUIRE);

    if (state == 2) return 0;
    if (state < 0) return -1;
    if (__sync_bool_compare_and_swap(&g_io_buffer_state, 0, 1)) {
        uint64_t bytes = (uint64_t)KERNEL_IO_BUFFER_SLOTS *
                         KERNEL_IO_BUFFER_SIZE;
        uint64_t pages = (bytes + KERNEL_IO_BUFFER_PAGE_SIZE - 1u) /
                         KERNEL_IO_BUFFER_PAGE_SIZE;

        g_io_buffer_storage = (uint8_t *)arch_vm_alloc_pages(pages);
        __atomic_store_n(&g_io_buffer_state,
                         g_io_buffer_storage ? 2 : -1,
                         __ATOMIC_RELEASE);
        return g_io_buffer_storage ? 0 : -1;
    }

    while ((state = __atomic_load_n(&g_io_buffer_state,
                                     __ATOMIC_ACQUIRE)) == 1) {
        if (!kernel_runtime_yield())
            __asm__ __volatile__("" ::: "memory");
    }
    return state == 2 ? 0 : -1;
}

int kernel_io_buffer_acquire(kernel_io_buffer_t *buffer) {
    if (!buffer) return -1;
    buffer->data = 0;
    buffer->slot = UINT32_MAX;
    if (kernel_io_buffer_prepare() < 0) return -1;

    for (;;) {
        uint32_t first = __atomic_fetch_add(&g_io_buffer_cursor, 1u,
                                            __ATOMIC_RELAXED) %
                         KERNEL_IO_BUFFER_SLOTS;
        for (uint32_t offset = 0; offset < KERNEL_IO_BUFFER_SLOTS;
             ++offset) {
            uint32_t slot = (first + offset) % KERNEL_IO_BUFFER_SLOTS;
            uint32_t bit = 1u << slot;
            uint32_t busy = __atomic_load_n(&g_io_buffer_busy,
                                            __ATOMIC_RELAXED);

            while (!(busy & bit)) {
                if (__atomic_compare_exchange_n(
                        &g_io_buffer_busy, &busy, busy | bit, 0,
                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                    buffer->slot = slot;
                    buffer->data = g_io_buffer_storage +
                                   (uint64_t)slot * KERNEL_IO_BUFFER_SIZE;
                    return 0;
                }
            }
        }
        if (!kernel_runtime_yield())
            __asm__ __volatile__("" ::: "memory");
    }
}

void kernel_io_buffer_release(kernel_io_buffer_t *buffer) {
    uint32_t bit;
    if (!buffer || !buffer->data ||
        buffer->slot >= KERNEL_IO_BUFFER_SLOTS)
        return;
    bit = 1u << buffer->slot;
    __atomic_fetch_and(&g_io_buffer_busy, ~bit, __ATOMIC_RELEASE);
    buffer->data = 0;
    buffer->slot = UINT32_MAX;
}
