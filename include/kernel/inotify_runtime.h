/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_INOTIFY_RUNTIME_H
#define EDGEOS_KERNEL_INOTIFY_RUNTIME_H

#include <stdint.h>

#define KERNEL_INOTIFY_NONBLOCK 0x00000800u
#define KERNEL_INOTIFY_CLOEXEC  0x00080000u

int kernel_inotify_create_descriptor(uint32_t flags);
int kernel_inotify_descriptor_id(int32_t descriptor);
void kernel_inotify_state_changed(int inotify_id);
void arch_inotify_state_changed(int inotify_id);

#endif
