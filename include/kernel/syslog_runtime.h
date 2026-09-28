/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS kernel-log wait runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SYSLOG_RUNTIME_H
#define EDGEOS_KERNEL_SYSLOG_RUNTIME_H

#include <stdint.h>
#include "kernel/linux_seek.h"

struct edge_linux_iovec;

#define KERNEL_SYSLOG_RECORD_MAX 1024u

typedef int (*kernel_syslog_copy_from_user_fn)(
    void *context, void *destination, uint64_t source, uint64_t length);

/* One write or writev is one record; copy faults publish no partial record. */
int64_t kernel_syslog_writev(
    const struct edge_linux_iovec *vectors, uint32_t vector_count,
    uint64_t length, kernel_syslog_copy_from_user_fn copy_from_user,
    void *context);
int64_t kernel_syslog_write_user(
    uint64_t source, uint64_t length,
    kernel_syslog_copy_from_user_fn copy_from_user, void *context);

typedef struct kernel_syslog_reader_bounds {
    uint64_t first_record;
    uint64_t last_clear;
    uint64_t next_record;
} kernel_syslog_reader_bounds_t;

/*
 * Select a reader cursor without changing global log state. On success the
 * descriptor adapter commits the cursor and returns zero from lseek, rather
 * than exposing the internal byte offset as the syscall result.
 */
edge_linux_seek_result_t kernel_syslog_reader_seek(
    const kernel_syslog_reader_bounds_t *bounds, int64_t displacement,
    uint32_t whence, uint64_t *position);

/* Returns one when the caller should retry, or a negative Linux errno. */
int kernel_syslog_wait_for_data(uint64_t observed_next,
                                void *user_registers);
void kernel_syslog_notify_data(void);

int arch_syslog_wait_for_data(uint64_t observed_next,
                              void *user_registers);
void arch_syslog_notify_data(void);

#endif
