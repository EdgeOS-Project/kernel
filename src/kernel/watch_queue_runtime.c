/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux watch queue control. */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/pipe_runtime.h"
#include "kernel/vfs_runtime.h"
#include "kernel/watch_queue_runtime.h"

#define WATCH_INFO_LENGTH 0x0000007fu

typedef struct kernel_watch_filter_header {
    uint32_t count;
    uint32_t reserved;
} kernel_watch_filter_header_t;

int64_t kernel_watch_queue_ioctl(const kernel_ioctl_request_t *request) {
#ifndef CONFIG_WATCH_QUEUE
    (void)request;
    return -EDGE_LINUX_ENOTTY;
#else
    kernel_pipe_watch_filter_t filters[KERNEL_PIPE_WATCH_FILTER_MAX];
    kernel_vfs_descriptor_t description;
    kernel_watch_filter_header_t header;
    uint32_t accepted = 0u;
    int result;

    if (!request) return -EDGE_LINUX_EIO;
    if (request->command != KERNEL_WATCH_QUEUE_SET_SIZE &&
        request->command != KERNEL_WATCH_QUEUE_SET_FILTER)
        return -EDGE_LINUX_ENOTTY;
    result = kernel_vfs_describe_descriptor(
        request->descriptor, &description);
    if (result < 0) return result;
    if (description.kind != KERNEL_VFS_DESCRIPTOR_PIPE ||
        !description.pipe)
        return -EDGE_LINUX_ENOTTY;
    if (!kernel_pipe_notification_mode(description.pipe))
        return -EDGE_LINUX_ENODEV;

    if (request->command == KERNEL_WATCH_QUEUE_SET_SIZE)
        return kernel_pipe_watch_size_set(
            description.pipe, (uint32_t)request->argument);

    if (!request->argument)
        return kernel_pipe_watch_filter_set(description.pipe, 0, 0u);
    if (!request->copy_from_user ||
        request->copy_from_user(
            request->copy_context, &header, request->argument,
            sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!header.count || header.count > KERNEL_PIPE_WATCH_FILTER_MAX ||
        header.reserved)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < header.count; ++index) {
        kernel_pipe_watch_filter_t candidate;
        uint64_t source = request->argument + sizeof(header) +
            (uint64_t)index * sizeof(candidate);

        if (request->copy_from_user(
                request->copy_context, &candidate, source,
                sizeof(candidate)) < 0)
            return -EDGE_LINUX_EFAULT;
        if ((candidate.info_filter & ~candidate.info_mask) ||
            (candidate.info_mask & WATCH_INFO_LENGTH))
            return -EDGE_LINUX_EINVAL;
        if (candidate.type >= KERNEL_PIPE_WATCH_TYPE_COUNT)
            continue;
        filters[accepted++] = candidate;
    }
    return kernel_pipe_watch_filter_set(
        description.pipe, filters, accepted);
#endif
}
