/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent ABI service dispatch.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/bpf_runtime.h"
#include "kernel/anonymous_fd.h"
#include "kernel/fbdev_runtime.h"
#include "kernel/ioctl_runtime.h"
#include "kernel/keyring_runtime.h"
#include "kernel/landlock_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/perf_event.h"
#include "kernel/perf_event_runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/socket_message.h"
#include "kernel/socket_runtime.h"
#include "kernel/userfaultfd_runtime.h"
#include "kernel/watch_queue_runtime.h"
#include "kernel/virtgpu_runtime.h"

__attribute__((noreturn)) void kernel_current_exit(
    int32_t code, int whole_thread_group) {
    kernel_linux_identity_t bpf_identity;
    kernel_proc_task_view_t bpf_task;

    if (kernel_current_linux_identity(&bpf_identity) == 0 &&
        kernel_proc_task_view_get(
            bpf_identity.global_tid, &bpf_task) == 0)
        kernel_bpf_task_storage_task_exit(
            bpf_task.tid, bpf_task.start_time_ticks);
#ifdef CONFIG_LANDLOCK
    kernel_linux_identity_t landlock_identity;
    if (kernel_current_linux_identity(&landlock_identity) == 0)
        kernel_landlock_task_exit(
            landlock_identity.global_tid,
            landlock_identity.global_tgid,
            whole_thread_group != 0);
#endif
#ifdef CONFIG_PERF_EVENTS
    kernel_linux_identity_t perf_identity;
    if (kernel_current_linux_identity(&perf_identity) == 0)
        kernel_perf_event_task_exit(perf_identity.global_tid);
#endif
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
    int sync_file_id;
    int64_t result;

    if (!request) return -EDGE_LINUX_EIO;
    sync_file_id = kernel_anonymous_fd_descriptor_object_id(
        request->descriptor, KERNEL_ANONYMOUS_FD_DRM_SYNC);
    if (sync_file_id >= 0)
        return edge_virtgpu_sync_file_ioctl(sync_file_id, request);
    if (arch_ioctl_descriptor_is_fbdev(request->descriptor)) {
        result = kernel_fbdev_ioctl(request);
        if (result != -EDGE_LINUX_ENOTTY) return result;
    }
    result = kernel_userfaultfd_ioctl(request);
    if (result != -EDGE_LINUX_ENOTTY) return result;
    result = kernel_perf_event_ioctl(request);
    if (result != -EDGE_LINUX_ENOTTY) return result;
    result = kernel_watch_queue_ioctl(request);
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
