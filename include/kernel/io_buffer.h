/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Shared bounded bounce buffers for architecture-neutral kernel I/O.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_IO_BUFFER_H
#define EDGEOS_KERNEL_IO_BUFFER_H

#include <stdint.h>

#define KERNEL_IO_BUFFER_SIZE (512u * 1024u)

typedef struct kernel_io_buffer {
    uint8_t *data;
    uint32_t slot;
} kernel_io_buffer_t;

int kernel_io_buffer_acquire(kernel_io_buffer_t *buffer);
void kernel_io_buffer_release(kernel_io_buffer_t *buffer);

#endif
