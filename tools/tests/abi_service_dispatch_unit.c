/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent ABI service dispatch unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/ioctl_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/socket_message.h"
#include "kernel/socket_runtime.h"

static jmp_buf g_exit_jump;
static int g_failures;
static int32_t g_exit_code;
static int g_exit_group;
static int g_fbdev_result;
static int g_ioctl_calls;
static int g_buffer_calls;
static int g_message_calls;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

__attribute__((noreturn)) void arch_current_exit(
    int32_t code, int whole_thread_group) {
    g_exit_code = code;
    g_exit_group = whole_thread_group;
    longjmp(g_exit_jump, 1);
}

int arch_ioctl_descriptor_is_fbdev(int32_t descriptor) {
    return descriptor == 9;
}

int64_t kernel_fbdev_ioctl(const kernel_ioctl_request_t *request) {
    return request && request->descriptor == 9 ?
        g_fbdev_result : -EDGE_LINUX_EIO;
}

int64_t arch_ioctl_execute(const kernel_ioctl_request_t *request) {
    ++g_ioctl_calls;
    return request && request->descriptor == 9 &&
        request->command == 10 ? 41 : -EDGE_LINUX_EBADF;
}

int64_t arch_socket_buffer_execute(
    const kernel_socket_buffer_request_t *request) {
    ++g_buffer_calls;
    return request && request->descriptor == 11 &&
        request->receiving ? 42 : -EDGE_LINUX_EBADF;
}

int64_t arch_socket_message_batch(
    const kernel_socket_mmsg_request_t *request) {
    ++g_message_calls;
    return request && request->descriptor == 12 &&
        request->vector_length == 13 ? 43 : -EDGE_LINUX_EBADF;
}

static void test_exit_dispatch(void) {
    if (setjmp(g_exit_jump) == 0)
        kernel_current_exit(7, 3);
    expect_true("exit dispatch",
                g_exit_code == 7 && g_exit_group == 1);
}

static void test_ioctl_dispatch(void) {
    kernel_ioctl_request_t request;

    memset(&request, 0, sizeof(request));
    request.descriptor = 9;
    request.command = 10;
    expect_true("ioctl null request",
                kernel_ioctl_execute(0) == -EDGE_LINUX_EIO);
    g_fbdev_result = 40;
    expect_true("fbdev short circuit",
                kernel_ioctl_execute(&request) == 40 &&
                g_ioctl_calls == 0);
    g_fbdev_result = -EDGE_LINUX_ENOTTY;
    expect_true("fbdev fallback",
                kernel_ioctl_execute(&request) == 41 &&
                g_ioctl_calls == 1);
}

static void test_socket_dispatch(void) {
    kernel_socket_buffer_request_t buffer_request;
    kernel_socket_mmsg_request_t message_request;

    memset(&buffer_request, 0, sizeof(buffer_request));
    buffer_request.descriptor = 11;
    buffer_request.receiving = 1;
    expect_true("buffer null request",
                kernel_socket_buffer_execute(0) == -EDGE_LINUX_EIO);
    expect_true("buffer dispatch",
                kernel_socket_buffer_execute(&buffer_request) == 42 &&
                g_buffer_calls == 1);

    memset(&message_request, 0, sizeof(message_request));
    message_request.descriptor = 12;
    message_request.vector_length = 13;
    expect_true("message null request",
                kernel_socket_message_batch(0) == -EDGE_LINUX_EIO);
    expect_true("message dispatch",
                kernel_socket_message_batch(&message_request) == 43 &&
                g_message_calls == 1);
}

int main(void) {
    test_exit_dispatch();
    test_ioctl_dispatch();
    test_socket_dispatch();
    if (g_failures) return 1;
    puts("abi_service_dispatch_unit: PASS");
    return 0;
}
