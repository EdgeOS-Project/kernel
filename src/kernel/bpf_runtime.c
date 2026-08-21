/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux BPF descriptor service.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/anonymous_fd.h"
#include "kernel/bpf_runtime.h"
#include "kernel/linux_errno.h"

int kernel_bpf_create_descriptor(int object_id) {
    kernel_bpf_object_kind_t kind;
    int descriptor;

    if (kernel_bpf_object_kind(object_id, &kind) < 0)
        return -EDGE_LINUX_EBADF;
    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_BPF, object_id, 2u, 1u);
    if (descriptor < 0) kernel_bpf_object_release(object_id);
    return descriptor;
}

int kernel_bpf_descriptor_object(int32_t descriptor,
                                 kernel_bpf_object_kind_t expected_kind) {
    kernel_bpf_object_kind_t actual_kind;
    int object_id = kernel_anonymous_fd_descriptor_object_id(
        descriptor, KERNEL_ANONYMOUS_FD_BPF);

    if (object_id < 0) return object_id;
    if (kernel_bpf_object_kind(object_id, &actual_kind) < 0 ||
        actual_kind != expected_kind)
        return -EDGE_LINUX_EBADF;
    return object_id;
}
