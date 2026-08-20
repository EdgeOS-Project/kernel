/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent ABI service dispatch.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/fbdev_runtime.h"
#include "kernel/ioctl_runtime.h"
#include "kernel/keyring_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/socket_message.h"
#include "kernel/socket_runtime.h"
#include "kernel/userfaultfd_runtime.h"

__attribute__((noreturn)) void kernel_current_exit(
    int32_t code, int whole_thread_group) {
#ifdef CONFIG_KEYS
    kernel_linux_identity_t identity;
    if (kernel_current_linux_identity(&identity) == 0)
        kernel_keyring_task_exit(
            identity.global_tid, identity.global_tgid,
            whole_thread_group != 0);
#endif
    arch_current_exit(code, whole_thread_group != 0);
    __builtin_unreachable();
}

int64_t kernel_ioctl_execute(const kernel_ioctl_request_t *request) {
    int64_t result;

    if (!request) return -EDGE_LINUX_EIO;
    if (arch_ioctl_descriptor_is_fbdev(request->descriptor)) {
        result = kernel_fbdev_ioctl(request);
        if (result != -EDGE_LINUX_ENOTTY) return result;
    }
    result = kernel_userfaultfd_ioctl(request);
    if (result != -EDGE_LINUX_ENOTTY) return result;
    return arch_ioctl_execute(request);
}

int64_t kernel_socket_buffer_execute(
    const kernel_socket_buffer_request_t *request) {
    if (!request) return -EDGE_LINUX_EIO;
    return arch_socket_buffer_execute(request);
}

int64_t kernel_socket_message_batch(
    const kernel_socket_mmsg_request_t *request) {
    if (!request) return -EDGE_LINUX_EIO;
    return arch_socket_message_batch(request);
}
