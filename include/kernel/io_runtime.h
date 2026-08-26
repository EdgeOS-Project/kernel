/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS descriptor I/O runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_IO_RUNTIME_H
#define EDGEOS_KERNEL_IO_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#define KERNEL_IO_TRANSFER_APPEND   0x0001u
#define KERNEL_IO_TRANSFER_NOAPPEND 0x0002u
#define KERNEL_IO_TRANSFER_NONBLOCK 0x0004u
#define KERNEL_IO_TRANSFER_SYNC_DATA 0x0008u
#define KERNEL_IO_TRANSFER_SYNC_FILE 0x0010u
#define KERNEL_IO_TRANSFER_SCALAR_SYSCALL 0x0020u
#define KERNEL_IO_SPLICE_F_NONBLOCK 0x0002u
#define KERNEL_IO_VECTOR_SCALAR_FALLBACK INT64_MIN

typedef enum kernel_io_operation {
    KERNEL_IO_READ_CURRENT = 1,
    KERNEL_IO_WRITE_CURRENT,
    KERNEL_IO_READ_POSITIONAL,
    KERNEL_IO_WRITE_POSITIONAL,
} kernel_io_operation_t;

typedef struct kernel_io_vector_scratch {
    struct edge_linux_iovec *vectors;
    uint32_t capacity;
} kernel_io_vector_scratch_t;

typedef struct kernel_io_vector_request {
    const struct edge_linux_iovec *vectors;
    void *user_registers;
    uint64_t requested_length;
    uint64_t offset;
    int32_t descriptor;
    uint32_t vector_count;
    kernel_io_operation_t operation;
    uint32_t flags;
    uint8_t validate_only;
    uint8_t reserved[7];
} kernel_io_vector_request_t;

typedef enum kernel_io_file_kind {
    KERNEL_IO_FILE_OTHER = 0,
    KERNEL_IO_FILE_REGULAR,
    KERNEL_IO_FILE_DIRECTORY,
    KERNEL_IO_FILE_PIPE,
} kernel_io_file_kind_t;

typedef struct kernel_io_file_range_info {
    uint64_t filesystem;
    uint64_t file;
    uint64_t offset;
    uint64_t size;
    kernel_io_file_kind_t kind;
    uint8_t readable;
    uint8_t writable;
    uint8_t append;
    uint8_t reserved;
    uint16_t metadata_flags;
    uint16_t metadata_padding;
} kernel_io_file_range_info_t;

typedef enum kernel_io_file_range_operation {
    KERNEL_IO_FILE_RANGE_QUERY = 1,
    KERNEL_IO_FILE_RANGE_READ,
    KERNEL_IO_FILE_RANGE_WRITE,
    KERNEL_IO_FILE_RANGE_COMMIT_OFFSET,
    KERNEL_IO_FILE_RANGE_COMPLETE_WRITE,
    KERNEL_IO_FILE_RANGE_SYNC_DATA,
    KERNEL_IO_FILE_RANGE_SYNC_FILE,
} kernel_io_file_range_operation_t;

typedef struct kernel_io_file_range_request {
    kernel_io_file_range_operation_t operation;
    uint64_t offset;
    void *buffer;
    uint32_t length;
    kernel_io_file_range_info_t *information;
} kernel_io_file_range_request_t;

typedef struct kernel_io_file_range_scratch {
    void *buffer;
    uint32_t capacity;
} kernel_io_file_range_scratch_t;

int kernel_io_current_vector_scratch(kernel_io_vector_scratch_t *scratch);
int kernel_io_descriptor_ready(int32_t descriptor,
                               kernel_io_operation_t operation);
int64_t kernel_io_user_transfer(int32_t descriptor, uint64_t user_buffer,
                                uint64_t length, uint64_t offset,
                                kernel_io_operation_t operation,
                                uint32_t flags, void *user_registers);
int64_t kernel_io_user_vector_transfer(
    int32_t descriptor, const struct edge_linux_iovec *vectors,
    uint32_t vector_count, kernel_io_operation_t operation,
    uint32_t flags, void *user_registers);
int64_t kernel_io_kernel_write_current(int32_t descriptor,
                                       const void *buffer, uint32_t length,
                                       void *user_registers);
int64_t kernel_io_kernel_read_current(int32_t descriptor,
                                      void *buffer, uint32_t length,
                                      void *user_registers);
int64_t kernel_io_pipe_tee_current(int32_t input_descriptor,
                                   int32_t output_descriptor,
                                   uint64_t length, uint32_t flags,
                                   void *user_registers);
int64_t kernel_io_splice_current(int32_t input_descriptor,
                                 uint64_t input_offset_user,
                                 int32_t output_descriptor,
                                 uint64_t output_offset_user,
                                 uint64_t length, uint32_t flags,
                                 void *user_registers);
int64_t kernel_io_splice_values_current(int32_t input_descriptor,
                                        uint64_t input_offset,
                                        int32_t output_descriptor,
                                        uint64_t output_offset,
                                        uint64_t length, uint32_t flags,
                                        void *user_registers);
int arch_io_descriptor_ready(int32_t descriptor,
                             kernel_io_operation_t operation);
int64_t arch_io_user_transfer(int32_t descriptor, uint64_t user_buffer,
                              uint64_t length, uint64_t offset,
                              kernel_io_operation_t operation,
                              uint32_t flags, void *user_registers);
int64_t arch_io_user_vector_transfer(
    int32_t descriptor, const struct edge_linux_iovec *vectors,
    uint32_t vector_count, kernel_io_operation_t operation,
    uint32_t flags, void *user_registers);
int64_t arch_io_kernel_write_current(int32_t descriptor,
                                     const void *buffer, uint32_t length,
                                     void *user_registers);
int64_t arch_io_kernel_read_current(int32_t descriptor,
                                    void *buffer, uint32_t length,
                                    void *user_registers);
int64_t arch_io_pipe_tee_current(int32_t input_descriptor,
                                 int32_t output_descriptor,
                                 uint64_t length, uint32_t flags,
                                 void *user_registers);
int64_t arch_io_splice_current(int32_t input_descriptor,
                               uint64_t input_offset_user,
                               int32_t output_descriptor,
                               uint64_t output_offset_user,
                               uint64_t length, uint32_t flags,
                               void *user_registers);
int64_t arch_io_splice_values_current(int32_t input_descriptor,
                                      uint64_t input_offset,
                                      int32_t output_descriptor,
                                      uint64_t output_offset,
                                      uint64_t length, uint32_t flags,
                                      void *user_registers);
int kernel_io_file_range_query(int32_t descriptor,
                               kernel_io_file_range_info_t *information);
int kernel_io_file_range_current_scratch(
    kernel_io_file_range_scratch_t *scratch);
int64_t kernel_io_file_range_read(int32_t descriptor, uint64_t offset,
                                  void *buffer, uint32_t length);
int64_t kernel_io_file_range_write(int32_t descriptor, uint64_t offset,
                                   const void *buffer, uint32_t length);
int kernel_io_file_range_commit_offset(int32_t descriptor, uint64_t offset);
void kernel_io_file_range_complete_write(int32_t descriptor);
int kernel_io_file_range_sync(int32_t descriptor, int data_only);

#endif
