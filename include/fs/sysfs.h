/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_FS_SYSFS_H
#define EDGEOS_FS_SYSFS_H

int sysfs_mount(const char *device, const char *target);
void sysfs_set_dmi_system(const char *vendor, const char *product);

#endif
