/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral fanotify descriptor interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_FANOTIFY_RUNTIME_H
#define EDGEOS_KERNEL_FANOTIFY_RUNTIME_H

#include <stdint.h>

int kernel_fanotify_create_descriptor(uint32_t flags,
                                      uint32_t event_flags);
int kernel_fanotify_descriptor_id(int32_t descriptor);
void kernel_fanotify_state_changed(int group_id);
void arch_fanotify_state_changed(int group_id);

#endif
