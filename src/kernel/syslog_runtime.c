/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent kernel-log wait policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "console.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/syslog_runtime.h"
#include "mm/arch_vm.h"
#include "sys/bootlog.h"

int64_t kernel_syslog_writev(
    const struct edge_linux_iovec *vectors, uint32_t vector_count,
    uint64_t length, kernel_syslog_copy_from_user_fn copy_from_user,
    void *context) {
    enum { PREFIX_CAPACITY = 64 };
    char *record;
    uint32_t copied = 0;
    uint32_t text_length;
    uint32_t record_length;
    int prefix_length;
    int64_t result;

    _Static_assert(KERNEL_SYSLOG_RECORD_MAX + PREFIX_CAPACITY + 2u <=
                       EDGE_PAGE_SIZE,
                   "A complete kernel log record must fit its staging page");

    /* Match the record size bound used by Linux devkmsg_write(). */
    if (length > KERNEL_SYSLOG_RECORD_MAX) return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if (!vectors || !vector_count || !copy_from_user)
        return -EDGE_LINUX_EINVAL;
    record = (char *)arch_vm_alloc_pages(1u);
    if (!record) return -EDGE_LINUX_ENOMEM;

    for (uint32_t index = 0; index < vector_count && copied < length;
         ++index) {
        uint64_t count = vectors[index].iov_len;
        uint64_t source = vectors[index].iov_base;

        if (count > length - copied) count = length - copied;
        if (!count) continue;
        if (!source || source > UINT64_MAX - (count - 1u) ||
            copy_from_user(context, record + PREFIX_CAPACITY + copied,
                           source, count) < 0) {
            result = -EDGE_LINUX_EFAULT;
            goto out;
        }
        copied += (uint32_t)count;
    }
    if (copied != length) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }

    /* Like Linux's "%s" emission, an embedded NUL terminates log text. */
    text_length = 0;
    while (text_length < copied && record[PREFIX_CAPACITY + text_length])
        ++text_length;
    prefix_length = bootlog_format_timestamp_prefix(record, PREFIX_CAPACITY);
    if (prefix_length < 0 || prefix_length >= PREFIX_CAPACITY) {
        result = -EDGE_LINUX_EIO;
        goto out;
    }
    for (uint32_t index = 0; index < text_length; ++index)
        record[(uint32_t)prefix_length + index] =
            record[PREFIX_CAPACITY + index];
    record_length = (uint32_t)prefix_length + text_length;
    if (!text_length || record[record_length - 1u] != '\n')
        record[record_length++] = '\n';
    record[record_length] = 0;

    /* Preserve the complete record in the ring and on the active consoles. */
    bootlog_append_raw(record, record_length);
    console_output_batch_begin();
    console_kernel_log_putstr(record);
    console_output_batch_end();
    result = (int64_t)length;
out:
    arch_vm_free_page(record);
    return result;
}

int64_t kernel_syslog_write_user(
    uint64_t source, uint64_t length,
    kernel_syslog_copy_from_user_fn copy_from_user, void *context) {
    struct edge_linux_iovec vector = {
        .iov_base = source,
        .iov_len = length
    };
    return kernel_syslog_writev(&vector, 1u, length, copy_from_user, context);
}

edge_linux_seek_result_t kernel_syslog_reader_seek(
    const kernel_syslog_reader_bounds_t *bounds, int64_t displacement,
    uint32_t whence, uint64_t *position) {
    uint64_t selected;

    if (!bounds || !position) return EDGE_LINUX_SEEK_INTERNAL;
    /* Linux rejects every nonzero displacement before checking whence. */
    if (displacement) return EDGE_LINUX_SEEK_ILLEGAL;
    switch (whence) {
        case EDGE_LINUX_SEEK_SET:
            selected = bounds->first_record;
            break;
        case EDGE_LINUX_SEEK_END:
            selected = bounds->next_record;
            break;
        case EDGE_LINUX_SEEK_DATA:
            /* A stale clear marker must allow the next read to report EPIPE. */
            selected = bounds->last_clear;
            break;
        default:
            return EDGE_LINUX_SEEK_INVALID;
    }
    *position = selected;
    return EDGE_LINUX_SEEK_OK;
}

int kernel_syslog_wait_for_data(uint64_t observed_next,
                                void *user_registers) {
    if (bootlog_next_offset() != observed_next) return 1;
    return arch_syslog_wait_for_data(observed_next, user_registers);
}

void kernel_syslog_notify_data(void) {
    arch_syslog_notify_data();
}
