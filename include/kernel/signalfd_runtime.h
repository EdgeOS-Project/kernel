/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_SIGNALFD_RUNTIME_H
#define EDGEOS_KERNEL_SIGNALFD_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#define KERNEL_SIGNALFD_NONBLOCK 0x00000800u
#define KERNEL_SIGNALFD_CLOEXEC  0x00080000u

int kernel_signalfd_create_descriptor(uint64_t mask, uint32_t flags);
int kernel_signalfd_descriptor_id(int32_t descriptor);
void kernel_signalfd_state_changed(int signalfd_id);
int kernel_signalfd_current_pending(uint64_t mask);
int kernel_signalfd_current_dequeue(
    void *context, uint64_t mask,
    struct edge_linux_signalfd_siginfo *information);

#endif
