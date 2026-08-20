/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent event wait dispatch policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/event_runtime.h"
#include "kernel/fanotify_runtime.h"
#include "kernel/inotify_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/runtime_limits.h"
#include "kernel/userfaultfd_runtime.h"

int64_t kernel_epoll_wait_descriptor(int32_t epoll_descriptor,
                                     uint64_t user_events,
                                     uint32_t maximum_events,
                                     int64_t timeout_microseconds,
                                     int replace_signal_mask,
                                     uint64_t signal_mask,
                                     void *user_registers) {
    return arch_epoll_wait_descriptor(
        epoll_descriptor, user_events, maximum_events,
        timeout_microseconds, replace_signal_mask,
        signal_mask, user_registers);
}

int64_t kernel_poll_wait_descriptors(uint64_t user_poll_fds,
                                     uint64_t descriptor_count,
                                     int64_t timeout_microseconds,
                                     uint64_t user_timeout,
                                     int replace_signal_mask,
                                     uint64_t signal_mask,
                                     void *user_registers) {
    if (descriptor_count > KERNEL_WAIT_DESCRIPTOR_MAX)
        return -EDGE_LINUX_EINVAL;
    return arch_poll_wait_descriptors(
        user_poll_fds, descriptor_count, timeout_microseconds,
        user_timeout, replace_signal_mask, signal_mask,
        user_registers);
}

int64_t kernel_select_wait_descriptors(uint64_t descriptor_count,
                                       uint64_t user_read_set,
                                       uint64_t user_write_set,
                                       uint64_t user_except_set,
                                       int64_t timeout_microseconds,
                                       uint64_t user_timeout,
                                       uint32_t timeout_format,
                                       int replace_signal_mask,
                                       uint64_t signal_mask,
                                       void *user_registers) {
    if (descriptor_count > KERNEL_WAIT_DESCRIPTOR_MAX)
        return -EDGE_LINUX_EINVAL;
    return arch_select_wait_descriptors(
        descriptor_count, user_read_set, user_write_set,
        user_except_set, timeout_microseconds, user_timeout,
        timeout_format, replace_signal_mask, signal_mask,
        user_registers);
}

void kernel_inotify_state_changed(int inotify_id) {
    if (inotify_id < 0 ||
        inotify_id >= EDGE_RUNTIME_MAX_INOTIFY_INSTANCES)
        return;
    arch_inotify_state_changed(inotify_id);
}

void kernel_fanotify_state_changed(int group_id) {
    if (group_id < 0 ||
        group_id >= EDGE_RUNTIME_MAX_FANOTIFY_GROUPS)
        return;
    arch_fanotify_state_changed(group_id);
}

void kernel_userfaultfd_state_changed(int context_id) {
    if (context_id < 0 ||
        context_id >= EDGE_RUNTIME_MAX_USERFAULTFDS)
        return;
    arch_userfaultfd_state_changed(context_id);
}
