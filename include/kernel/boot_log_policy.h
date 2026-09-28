/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent boot logging policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_BOOT_LOG_POLICY_H
#define EDGEOS_KERNEL_BOOT_LOG_POLICY_H

#include <stddef.h>

#define EDGEOS_BOOT_LOG_PATH_MAX 256u

typedef struct kernel_boot_log_policy {
    int console_loglevel;
    int console_loglevel_explicit;
    int quiet;
    int file_enabled;
    char file_path[EDGEOS_BOOT_LOG_PATH_MAX];
} kernel_boot_log_policy_t;

int kernel_boot_log_path_valid(const char *path);
int kernel_boot_log_policy_load(kernel_boot_log_policy_t *policy);

#endif /* EDGEOS_KERNEL_BOOT_LOG_POLICY_H */
