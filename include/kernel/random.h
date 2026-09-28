/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef EDGEOS_KERNEL_RANDOM_H
#define EDGEOS_KERNEL_RANDOM_H

#include <stdint.h>

void edge_random_fill(void *buffer, uint32_t length);
void edge_random_mix(const void *buffer, uint32_t length);

#endif
