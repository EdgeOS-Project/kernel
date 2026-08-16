/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_EVENTFD_H
#define EDGEOS_KERNEL_EVENTFD_H

#include <stdint.h>

typedef struct kernel_eventfd_state {
    uint64_t counter;
    uint64_t write_sequence;
    uint32_t references;
    uint8_t semaphore;
} kernel_eventfd_state_t;

typedef int (*kernel_eventfd_copy_value_fn)(void *context, uint64_t value);
typedef int (*kernel_eventfd_load_value_fn)(void *context, uint64_t *value);

int kernel_eventfd_create(uint32_t initial_value, int semaphore);
int kernel_eventfd_retain(int event_id);
void kernel_eventfd_release(int event_id);
int kernel_eventfd_query(int event_id, kernel_eventfd_state_t *state);

/*
 * A zero result is an internal wait disposition, never a userspace-visible
 * short transfer. Architecture runtimes publish their native scheduler waiter
 * and retry the same common operation after observing this result.
 */
#define KERNEL_EVENTFD_IO_WAIT 0
#define KERNEL_EVENTFD_IO_BYTES ((int64_t)sizeof(uint64_t))

int64_t kernel_eventfd_read_io(int event_id, uint64_t buffer_length,
                               int nonblocking,
                               kernel_eventfd_copy_value_fn copy_value,
                               void *copy_context, uint64_t *value);
int64_t kernel_eventfd_write_io(int event_id, uint64_t buffer_length,
                                int nonblocking,
                                kernel_eventfd_load_value_fn load_value,
                                void *copy_context, uint64_t *value);
int64_t kernel_eventfd_write_value(int event_id, int nonblocking,
                                   uint64_t value);

#endif
