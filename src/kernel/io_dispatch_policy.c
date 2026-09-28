/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent descriptor I/O dispatch policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"

static int io_operation_valid(kernel_io_operation_t operation) {
    return operation == KERNEL_IO_READ_CURRENT ||
           operation == KERNEL_IO_WRITE_CURRENT ||
           operation == KERNEL_IO_READ_POSITIONAL ||
           operation == KERNEL_IO_WRITE_POSITIONAL;
}

int kernel_io_descriptor_ready(int32_t descriptor,
                               kernel_io_operation_t operation) {
    if (descriptor < 0 || !io_operation_valid(operation))
        return 0;
    return arch_io_descriptor_ready(descriptor, operation);
}

int64_t kernel_io_user_transfer(int32_t descriptor, uint64_t user_buffer,
                                uint64_t length, uint64_t offset,
                                kernel_io_operation_t operation,
                                uint32_t flags, void *user_registers) {
    if (descriptor < 0)
        return -EDGE_LINUX_EBADF;
    if (!io_operation_valid(operation))
        return -EDGE_LINUX_EINVAL;
    return arch_io_user_transfer(
        descriptor, user_buffer, length, offset, operation,
        flags, user_registers);
}

int64_t kernel_io_user_vector_transfer(
    int32_t descriptor, const struct edge_linux_iovec *vectors,
    uint32_t vector_count, kernel_io_operation_t operation,
    uint32_t flags, void *user_registers) {
    if (descriptor < 0)
        return -EDGE_LINUX_EBADF;
    if (!io_operation_valid(operation))
        return -EDGE_LINUX_EINVAL;
    return arch_io_user_vector_transfer(
        descriptor, vectors, vector_count, operation,
        flags, user_registers);
}

int64_t kernel_io_kernel_write_current(int32_t descriptor,
                                       const void *buffer, uint32_t length,
                                       void *user_registers) {
    if (descriptor < 0)
        return -EDGE_LINUX_EBADF;
    if (!buffer && length)
        return -EDGE_LINUX_EFAULT;
    return arch_io_kernel_write_current(
        descriptor, buffer, length, user_registers);
}

int64_t kernel_io_kernel_read_current(int32_t descriptor,
                                      void *buffer, uint32_t length,
                                      void *user_registers) {
    if (descriptor < 0)
        return -EDGE_LINUX_EBADF;
    if (!buffer && length)
        return -EDGE_LINUX_EFAULT;
    return arch_io_kernel_read_current(
        descriptor, buffer, length, user_registers);
}

int64_t kernel_io_pipe_tee_current(int32_t input_descriptor,
                                   int32_t output_descriptor,
                                   uint64_t length, uint32_t flags,
                                   void *user_registers) {
    if (input_descriptor < 0 || output_descriptor < 0)
        return -EDGE_LINUX_EBADF;
    return arch_io_pipe_tee_current(
        input_descriptor, output_descriptor, length, flags,
        user_registers);
}

int64_t kernel_io_splice_current(int32_t input_descriptor,
                                 uint64_t input_offset_user,
                                 int32_t output_descriptor,
                                 uint64_t output_offset_user,
                                 uint64_t length, uint32_t flags,
                                 void *user_registers) {
    if (input_descriptor < 0 || output_descriptor < 0)
        return -EDGE_LINUX_EBADF;
    return arch_io_splice_current(
        input_descriptor, input_offset_user,
        output_descriptor, output_offset_user,
        length, flags, user_registers);
}

int64_t kernel_io_splice_values_current(int32_t input_descriptor,
                                        uint64_t input_offset,
                                        int32_t output_descriptor,
                                        uint64_t output_offset,
                                        uint64_t length, uint32_t flags,
                                        void *user_registers) {
    if (input_descriptor < 0 || output_descriptor < 0)
        return -EDGE_LINUX_EBADF;
    return arch_io_splice_values_current(
        input_descriptor, input_offset,
        output_descriptor, output_offset,
        length, flags, user_registers);
}
