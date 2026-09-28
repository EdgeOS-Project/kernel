/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent ioctl runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_IOCTL_RUNTIME_H
#define EDGEOS_KERNEL_IOCTL_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"

typedef struct kernel_ioctl_request {
    int32_t descriptor;
    uint32_t command;
    uint64_t argument;
    void *user_registers;
    void *copy_context;
    edge_linux_copy_from_user_fn copy_from_user;
    edge_linux_copy_to_user_fn copy_to_user;
    uint8_t user_pointer_size;
} kernel_ioctl_request_t;

int64_t kernel_ioctl_execute(const kernel_ioctl_request_t *request);
int arch_ioctl_descriptor_is_fbdev(int32_t descriptor);
int64_t arch_ioctl_execute(const kernel_ioctl_request_t *request);

#endif
