/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_TIMERFD_RUNTIME_H
#define EDGEOS_KERNEL_TIMERFD_RUNTIME_H

#include <stdint.h>

#define KERNEL_TIMERFD_NONBLOCK 0x00000800u
#define KERNEL_TIMERFD_CLOEXEC  0x00080000u

int kernel_timerfd_create_descriptor(int32_t clock_id, uint32_t flags);
int kernel_timerfd_descriptor_id(int32_t descriptor);
void kernel_timerfd_state_changed(int timer_id);

#endif
