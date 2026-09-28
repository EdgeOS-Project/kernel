/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux perf event descriptor and ioctl service.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/anonymous_fd.h"
#include "kernel/linux_errno.h"
#include "kernel/perf_event.h"
#include "kernel/perf_event_runtime.h"

int kernel_perf_event_create_descriptor(
    const kernel_perf_event_open_request_t *request) {
    int event_id;
    int descriptor;

    event_id = kernel_perf_event_open(request);
    if (event_id < 0) return event_id;
    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_PERF_EVENT, event_id, 2u,
        (request->flags & KERNEL_PERF_FLAG_FD_CLOEXEC) != 0);
    if (descriptor < 0) kernel_perf_event_release(event_id);
    return descriptor;
}

int kernel_perf_event_descriptor_id(int32_t descriptor) {
    kernel_perf_event_state_t state;
    int event_id = kernel_anonymous_fd_descriptor_object_id(
        descriptor, KERNEL_ANONYMOUS_FD_PERF_EVENT);
    if (event_id < 0) return event_id;
    return kernel_perf_event_query(event_id, &state) < 0 ?
        -EDGE_LINUX_EBADF : event_id;
}

int64_t kernel_perf_event_read_descriptor(
    int32_t descriptor, uint64_t *values, uint32_t value_capacity) {
    int event_id = kernel_perf_event_descriptor_id(descriptor);
    if (event_id < 0) return event_id;
    return kernel_perf_event_read(event_id, values, value_capacity);
}

static int perf_event_copy_to_user(
    const kernel_ioctl_request_t *request, uint64_t destination,
    const void *source, uint64_t size) {
    if (!request || !request->copy_to_user || !destination)
        return -EDGE_LINUX_EFAULT;
    return request->copy_to_user(
        request->copy_context, destination, source, size) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

int64_t kernel_perf_event_ioctl(const kernel_ioctl_request_t *request) {
    uint64_t id = 0;
    uint32_t flags;
    int event_id;
    int status;

    if (!request) return -EDGE_LINUX_EIO;
    event_id = kernel_perf_event_descriptor_id(request->descriptor);
    if (event_id < 0) return -EDGE_LINUX_ENOTTY;
    flags = request->command == KERNEL_PERF_IOC_ID ?
        0u : (uint32_t)request->argument;
    status = kernel_perf_event_control(
        event_id, request->command, flags, &id);
    if (status < 0) return status;
    if (request->command == KERNEL_PERF_IOC_ID)
        return perf_event_copy_to_user(
            request, request->argument, &id, sizeof(id));
    return 0;
}
