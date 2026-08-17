/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS memory-file runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_MEMFD_RUNTIME_H
#define EDGEOS_KERNEL_MEMFD_RUNTIME_H

#include <stdint.h>

#define KERNEL_MEMFD_NAME_MAX       249u
#define KERNEL_MEMFD_CLOEXEC        0x0001u
#define KERNEL_MEMFD_ALLOW_SEALING  0x0002u
#define KERNEL_MEMFD_HUGETLB        0x0004u
#define KERNEL_MEMFD_HUGE_MASK      0xfc000000u

int64_t kernel_memfd_create_descriptor(const char *name, uint32_t flags);
int64_t arch_memfd_create_descriptor(const char *name, uint32_t flags);

#endif
