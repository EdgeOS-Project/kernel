/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent filesystem-context helpers.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_FS_CONTEXT_H
#define EDGEOS_KERNEL_FS_CONTEXT_H

#include <stdint.h>

int kernel_fs_context_copy_path(char *destination, uint32_t capacity,
                                const char *source);
int kernel_fs_path_is_beneath(const char *root, const char *path);
int kernel_fs_path_normalize(const char *base, const char *path,
                             char *output, uint32_t capacity);
int kernel_fs_path_resolve(const char *root, const char *base,
                           const char *path, char *scratch,
                           uint32_t scratch_capacity, char *output,
                           uint32_t output_capacity);
int kernel_fs_cwd_make_visible(const char *root, char *cwd,
                               uint32_t capacity);

#endif
