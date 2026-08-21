/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent descriptor factory policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/fd_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/memfd_runtime.h"
#include "kernel/namespace_runtime.h"

#define KERNEL_PIPE_NONBLOCK 0x00000800u
#define KERNEL_PIPE_CLOEXEC  0x00080000u

int kernel_fd_pipe_prepare(
    uint32_t flags, int32_t descriptors[2],
    kernel_fd_publication_t *publication) {
    if (!descriptors || !publication)
        return -EDGE_LINUX_EINVAL;
    descriptors[0] = -1;
    descriptors[1] = -1;
    if (flags & ~(KERNEL_PIPE_NONBLOCK | KERNEL_PIPE_CLOEXEC))
        return -EDGE_LINUX_EINVAL;
    if (publication->active)
        return -EDGE_LINUX_EBUSY;
    return arch_fd_pipe_prepare(flags, descriptors, publication);
}

int64_t kernel_memfd_create_descriptor(const char *name, uint32_t flags) {
    if (!name) return -EDGE_LINUX_EINVAL;
    return arch_memfd_create_descriptor(name, flags);
}

int64_t kernel_memfd_secret_descriptor(uint32_t descriptor_flags) {
    if (descriptor_flags & ~KERNEL_MEMFD_CLOEXEC)
        return -EDGE_LINUX_EINVAL;
    return arch_memfd_secret_descriptor(descriptor_flags);
}

int kernel_namespace_descriptor_get(
    int32_t descriptor, kernel_namespace_descriptor_t *information) {
    if (!information) return -EDGE_LINUX_EINVAL;
    return arch_namespace_descriptor_get(descriptor, information);
}
