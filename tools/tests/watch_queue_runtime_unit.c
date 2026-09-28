/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/pipe_runtime.h"
#include "kernel/vfs_runtime.h"
#include "kernel/watch_queue_runtime.h"

typedef struct test_filter_request {
    uint32_t count;
    uint32_t reserved;
    kernel_pipe_watch_filter_t filters[2];
} test_filter_request_t;

static kernel_pipe_runtime_t test_pipe;

static int copy_from_user(void *context, void *destination,
                          uint64_t source, uint64_t length) {
    (void)context;
    if (!destination || (!source && length)) return -1;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)length);
    return 0;
}

int kernel_vfs_describe_descriptor(
        int32_t descriptor, kernel_vfs_descriptor_t *description) {
    if (!description) return -EDGE_LINUX_EFAULT;
    if (descriptor < 0) return -EDGE_LINUX_EBADF;
    memset(description, 0, sizeof(*description));
    if (descriptor == 9) {
        description->kind = KERNEL_VFS_DESCRIPTOR_PIPE;
        description->pipe = &test_pipe;
    } else {
        description->kind = KERNEL_VFS_DESCRIPTOR_REGULAR;
    }
    return 0;
}

int main(void) {
    kernel_ioctl_request_t request;
    test_filter_request_t filter;

    memset(&request, 0, sizeof(request));
    request.descriptor = 9;
    request.copy_from_user = copy_from_user;
    kernel_pipe_object_initialize(&test_pipe);

    request.command = KERNEL_WATCH_QUEUE_SET_SIZE;
    request.argument = 1u;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_ENODEV);
    assert(kernel_pipe_notification_mode_set(&test_pipe, 1) == 0);
    request.argument = 0u;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_EINVAL);
    request.argument = 513u;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_EINVAL);
    request.argument = 1u;
    assert(kernel_watch_queue_ioctl(&request) == 0);
    assert(test_pipe.watch_note_capacity == 32u);
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_EBUSY);

    memset(&filter, 0, sizeof(filter));
    request.command = KERNEL_WATCH_QUEUE_SET_FILTER;
    request.argument = (uint64_t)(uintptr_t)&filter;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_EINVAL);
    filter.count = 1u;
    filter.reserved = 1u;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_EINVAL);
    filter.reserved = 0u;
    filter.filters[0].type = 1u;
    filter.filters[0].info_filter = 1u;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_EINVAL);
    filter.filters[0].info_filter = 0u;
    filter.filters[0].info_mask = 0x7fu;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_EINVAL);
    filter.filters[0].info_mask = 0u;
    filter.filters[0].subtype_filter[0] = 1u << 1u;
    assert(kernel_watch_queue_ioctl(&request) == 0);
    assert(test_pipe.watch_filter_count == 1u);

    filter.count = 2u;
    filter.filters[0].type = 9u;
    filter.filters[1].type = 10u;
    assert(kernel_watch_queue_ioctl(&request) == 0);
    assert(test_pipe.watch_filter_count == 0u);
    request.argument = 0u;
    assert(kernel_watch_queue_ioctl(&request) == 0);

    request.descriptor = 10;
    request.command = KERNEL_WATCH_QUEUE_SET_SIZE;
    request.argument = 1u;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_ENOTTY);
    request.descriptor = -1;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_EBADF);
    request.command = 0u;
    assert(kernel_watch_queue_ioctl(&request) == -EDGE_LINUX_ENOTTY);

    puts("watch_queue_runtime_unit: PASS");
    return 0;
}
