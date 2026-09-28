/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef EDGEOS_FS_PROCFS_H
#define EDGEOS_FS_PROCFS_H

#include <stdint.h>

int procfs_mount(const char *device, const char *target);
void procfs_userns_description_release(uint64_t identity);

#endif
