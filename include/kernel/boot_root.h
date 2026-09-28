/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent root filesystem boot policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_BOOT_ROOT_H
#define EDGEOS_KERNEL_BOOT_ROOT_H

#include <stdint.h>

#include "block/block.h"

#define EDGEOS_BOOT_ROOT_SPEC_MAX 128u
#define EDGEOS_BOOT_ROOT_FSTYPES_MAX 128u
#define EDGEOS_BOOT_ROOT_FLAGS_MAX 256u

typedef struct {
    char device_spec[EDGEOS_BOOT_ROOT_SPEC_MAX];
    char filesystem_types[EDGEOS_BOOT_ROOT_FSTYPES_MAX];
    char filesystem_flags[EDGEOS_BOOT_ROOT_FLAGS_MAX];
    uint32_t mount_flags;
    uint32_t delay_seconds;
    uint32_t wait_seconds;
    uint8_t device_explicit;
    uint8_t wait_for_device;
    uint8_t wait_forever;
} kernel_boot_root_policy_t;

typedef struct {
    block_device_t *device;
    char filesystem_type[32];
    uint32_t mount_flags;
    uint8_t device_explicit;
} kernel_boot_root_result_t;

int kernel_boot_root_policy_load(kernel_boot_root_policy_t *policy);
block_device_t *kernel_boot_root_resolve_device(const char *specification);
int kernel_boot_root_mount(kernel_boot_root_result_t *result);

#endif /* EDGEOS_KERNEL_BOOT_ROOT_H */
