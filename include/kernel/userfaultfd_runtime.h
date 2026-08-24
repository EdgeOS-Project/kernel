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
int kernel_userfaultfd_install_existing_descriptor(
    int context_id, uint32_t flags);
int kernel_userfaultfd_descriptor_id(int32_t descriptor);
void kernel_userfaultfd_state_changed(int context_id);
void arch_userfaultfd_state_changed(int context_id);
void arch_userfaultfd_wait_event(int context_id, uint64_t ticket,
                                 int64_t completion_result);
int arch_userfaultfd_consume_completed_event(int64_t *completion_result);
int64_t kernel_userfaultfd_ioctl(const kernel_ioctl_request_t *request);

#endif
