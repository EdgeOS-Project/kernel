/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS memory-backed block device interface. */
#ifndef EDGEOS_DRIVERS_RAMDISK_H
#define EDGEOS_DRIVERS_RAMDISK_H

#include <stdint.h>

int ramdisk_register(const char *name, void *base, uint64_t size, int writable);

#endif
