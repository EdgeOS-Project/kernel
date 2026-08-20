/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS userfaultfd descriptor and wake interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_USERFAULTFD_RUNTIME_H
#define EDGEOS_KERNEL_USERFAULTFD_RUNTIME_H

#include <stdint.h>

#include "kernel/ioctl_runtime.h"

int kernel_userfaultfd_create_descriptor(uint32_t flags);
int kernel_userfaultfd_descriptor_id(int32_t descriptor);
void kernel_userfaultfd_state_changed(int context_id);
void arch_userfaultfd_state_changed(int context_id);
int64_t kernel_userfaultfd_ioctl(const kernel_ioctl_request_t *request);

#endif
