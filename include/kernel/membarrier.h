/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux membarrier runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_MEMBARRIER_H
#define EDGEOS_KERNEL_MEMBARRIER_H

#include <stdint.h>

uint32_t kernel_membarrier_supported_commands(void);
int kernel_current_membarrier_registrations(uint32_t *registrations);
int kernel_current_membarrier_register(uint32_t command);
int kernel_membarrier_execute(uint32_t command);

/* Returns the current thread group's shared registration word. */
int kernel_arch_current_membarrier_state(uint32_t **registrations);

#endif
