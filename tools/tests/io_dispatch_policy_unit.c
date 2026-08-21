/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent I/O dispatch policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>

#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"

static int g_failures;
static int g_ready_calls;
static int g_transfer_calls;
static int g_vector_calls;
static int g_write_calls;
static int g_tee_calls;
static int g_splice_calls;
static int g_splice_values_calls;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

int arch_io_descriptor_ready(int32_t descriptor,
                             kernel_io_operation_t operation) {
    ++g_ready_calls;
    return descriptor == 1 && operation == KERNEL_IO_READ_CURRENT;
}

int64_t arch_io_user_transfer(int32_t descriptor, uint64_t user_buffer,
                              uint64_t length, uint64_t offset,
                              kernel_io_operation_t operation,
                              uint32_t flags, void *user_registers) {
    ++g_transfer_calls;
    return descriptor == 2 && user_buffer == 3u && length == 4u &&
           offset == 5u && operation == KERNEL_IO_WRITE_POSITIONAL &&
           flags == 6u && user_registers == (void *)(uintptr_t)7u ?
           21 : -1;
}

int64_t arch_io_user_vector_transfer(
    int32_t descriptor, const struct edge_linux_iovec *vectors,
    uint32_t vector_count, kernel_io_operation_t operation,
    uint32_t flags, void *user_registers) {
    ++g_vector_calls;
    return descriptor == 8 && vectors &&
           vectors[0].iov_base == 9u && vectors[0].iov_len == 10u &&
           vector_count == 1u &&
           operation == KERNEL_IO_READ_POSITIONAL &&
           flags == 11u && user_registers == (void *)(uintptr_t)12u ?
           22 : -1;
}

int64_t arch_io_kernel_write_current(int32_t descriptor,
                                     const void *buffer, uint32_t length,
                                     void *user_registers) {
    ++g_write_calls;
    if (descriptor == 13 && buffer == (void *)(uintptr_t)14u &&
        length == 15u && user_registers == (void *)(uintptr_t)16u)
        return 23;
    if (descriptor == 13 && !buffer && !length)
        return 0;
    return -1;
}

int64_t arch_io_pipe_tee_current(int32_t input_descriptor,
                                 int32_t output_descriptor,
                                 uint64_t length, uint32_t flags,
                                 void *user_registers) {
    ++g_tee_calls;
    return input_descriptor == 17 && output_descriptor == 18 &&
           length == 19u && flags == 20u &&
           user_registers == (void *)(uintptr_t)21u ? 24 : -1;
}

int64_t arch_io_splice_current(int32_t input_descriptor,
                               uint64_t input_offset_user,
                               int32_t output_descriptor,
                               uint64_t output_offset_user,
                               uint64_t length, uint32_t flags,
                               void *user_registers) {
    ++g_splice_calls;
    return input_descriptor == 22 && input_offset_user == 23u &&
           output_descriptor == 24 && output_offset_user == 25u &&
           length == 26u && flags == 27u &&
           user_registers == (void *)(uintptr_t)28u ? 25 : -1;
}

int64_t arch_io_splice_values_current(int32_t input_descriptor,
                                      uint64_t input_offset,
                                      int32_t output_descriptor,
                                      uint64_t output_offset,
                                      uint64_t length, uint32_t flags,
                                      void *user_registers) {
    ++g_splice_values_calls;
    return input_descriptor == 29 && input_offset == 30u &&
           output_descriptor == 31 && output_offset == 32u &&
           length == 33u && flags == 34u &&
           user_registers == (void *)(uintptr_t)35u ? 36 : -1;
}

static void test_readiness_and_transfer(void) {
    struct edge_linux_iovec vector = {
        .iov_base = 9u,
        .iov_len = 10u,
    };

    expect_true("ready negative descriptor",
                kernel_io_descriptor_ready(
                    -1, KERNEL_IO_READ_CURRENT) == 0 &&
                g_ready_calls == 0);
    expect_true("ready invalid operation",
                kernel_io_descriptor_ready(
                    1, (kernel_io_operation_t)0) == 0 &&
                g_ready_calls == 0);
    expect_true("ready dispatch",
                kernel_io_descriptor_ready(
                    1, KERNEL_IO_READ_CURRENT) == 1 &&
                g_ready_calls == 1);

    expect_true("transfer negative descriptor",
                kernel_io_user_transfer(
                    -1, 3, 4, 5, KERNEL_IO_WRITE_POSITIONAL,
                    6, (void *)(uintptr_t)7u) == -EDGE_LINUX_EBADF &&
                g_transfer_calls == 0);
    expect_true("transfer invalid operation",
                kernel_io_user_transfer(
                    2, 3, 4, 5, (kernel_io_operation_t)0,
                    6, (void *)(uintptr_t)7u) == -EDGE_LINUX_EINVAL &&
                g_transfer_calls == 0);
    expect_true("transfer dispatch",
                kernel_io_user_transfer(
                    2, 3, 4, 5, KERNEL_IO_WRITE_POSITIONAL,
                    6, (void *)(uintptr_t)7u) == 21 &&
                g_transfer_calls == 1);

    expect_true("vector negative descriptor",
                kernel_io_user_vector_transfer(
                    -1, &vector, 1, KERNEL_IO_READ_POSITIONAL,
                    11, (void *)(uintptr_t)12u) == -EDGE_LINUX_EBADF &&
                g_vector_calls == 0);
    expect_true("vector invalid operation",
                kernel_io_user_vector_transfer(
                    8, &vector, 1, (kernel_io_operation_t)0,
                    11, (void *)(uintptr_t)12u) == -EDGE_LINUX_EINVAL &&
                g_vector_calls == 0);
    expect_true("vector dispatch",
                kernel_io_user_vector_transfer(
                    8, &vector, 1, KERNEL_IO_READ_POSITIONAL,
                    11, (void *)(uintptr_t)12u) == 22 &&
                g_vector_calls == 1);
}

static void test_kernel_and_pipe_dispatch(void) {
    expect_true("write negative descriptor precedence",
                kernel_io_kernel_write_current(-1, 0, 1, 0) ==
                    -EDGE_LINUX_EBADF &&
                g_write_calls == 0);
    expect_true("write null buffer",
                kernel_io_kernel_write_current(13, 0, 1, 0) ==
                    -EDGE_LINUX_EFAULT &&
                g_write_calls == 0);
    expect_true("write zero dispatch",
                kernel_io_kernel_write_current(13, 0, 0, 0) == 0 &&
                g_write_calls == 1);
    expect_true("write dispatch",
                kernel_io_kernel_write_current(
                    13, (void *)(uintptr_t)14u, 15,
                    (void *)(uintptr_t)16u) == 23 &&
                g_write_calls == 2);

    expect_true("tee negative input",
                kernel_io_pipe_tee_current(
                    -1, 18, 19, 20, (void *)(uintptr_t)21u) ==
                    -EDGE_LINUX_EBADF &&
                g_tee_calls == 0);
    expect_true("tee negative output",
                kernel_io_pipe_tee_current(
                    17, -1, 19, 20, (void *)(uintptr_t)21u) ==
                    -EDGE_LINUX_EBADF &&
                g_tee_calls == 0);
    expect_true("tee dispatch",
                kernel_io_pipe_tee_current(
                    17, 18, 19, 20, (void *)(uintptr_t)21u) == 24 &&
                g_tee_calls == 1);

    expect_true("splice negative input",
                kernel_io_splice_current(
                    -1, 23, 24, 25, 26, 27,
                    (void *)(uintptr_t)28u) == -EDGE_LINUX_EBADF &&
                g_splice_calls == 0);
    expect_true("splice negative output",
                kernel_io_splice_current(
                    22, 23, -1, 25, 26, 27,
                    (void *)(uintptr_t)28u) == -EDGE_LINUX_EBADF &&
                g_splice_calls == 0);
    expect_true("splice dispatch",
                kernel_io_splice_current(
                    22, 23, 24, 25, 26, 27,
                    (void *)(uintptr_t)28u) == 25 &&
                g_splice_calls == 1);
    expect_true("splice values negative input",
                kernel_io_splice_values_current(
                    -1, 30, 31, 32, 33, 34,
                    (void *)(uintptr_t)35u) == -EDGE_LINUX_EBADF &&
                g_splice_values_calls == 0);
    expect_true("splice values dispatch",
                kernel_io_splice_values_current(
                    29, 30, 31, 32, 33, 34,
                    (void *)(uintptr_t)35u) == 36 &&
                g_splice_values_calls == 1);
}

int main(void) {
    test_readiness_and_transfer();
    test_kernel_and_pipe_dispatch();
    if (g_failures) return 1;
    puts("io_dispatch_policy_unit: PASS");
    return 0;
}
