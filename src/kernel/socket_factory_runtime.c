/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent socket factory policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/fd_runtime.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/socket_runtime.h"

int64_t kernel_socket_create_descriptor(uint32_t domain, uint32_t type,
                                        uint32_t protocol, uint32_t flags) {
    return arch_socket_create_descriptor(domain, type, protocol, flags);
}

int kernel_socket_create_unix_pair_prepare(
    int32_t descriptors[2],
    kernel_fd_publication_t *publication) {
    if (!descriptors || !publication)
        return -EDGE_LINUX_EINVAL;
    descriptors[0] = -1;
    descriptors[1] = -1;
    if (publication->active)
        return -EDGE_LINUX_EBUSY;
    return arch_socket_create_unix_pair_prepare(
        descriptors, publication);
}

int kernel_socket_create_unix_pair_construct(
    uint32_t type, uint32_t flags, const int32_t descriptors[2],
    const kernel_fd_publication_t *publication) {
    if (!descriptors || !publication)
        return -EDGE_LINUX_EINVAL;
    return arch_socket_create_unix_pair_construct(
        type, flags, descriptors, publication);
}

int kernel_socket_accept_prepare(
    int32_t descriptor, uint32_t flags, kernel_socket_address_t *address,
    uint64_t deferred_user_address, uint64_t deferred_user_length,
    void *user_registers, int32_t *accepted_descriptor,
    kernel_fd_publication_t *publication) {
    if (!accepted_descriptor || !publication)
        return -EDGE_LINUX_EINVAL;
    *accepted_descriptor = -1;
    if (!address)
        return -EDGE_LINUX_EIO;
    if (flags &
        ~(EDGE_LINUX_SOCK_NONBLOCK | EDGE_LINUX_SOCK_CLOEXEC))
        return -EDGE_LINUX_EINVAL;
    if (publication->active)
        return -EDGE_LINUX_EBUSY;
    return arch_socket_accept_prepare(
        descriptor, flags, address,
        deferred_user_address, deferred_user_length,
        user_registers, accepted_descriptor, publication);
}
