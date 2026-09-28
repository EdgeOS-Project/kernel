/* SPDX-License-Identifier: MPL-2.0 */
/* Boot metadata shared by unmodified BSD firmware drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_FIRMWARE_METADATA_H
#define EDGEOS_COMPAT_FREEBSD_FIRMWARE_METADATA_H

#include <stddef.h>
#include <stdint.h>

int bsd_firmware_metadata_configure_efi(uint64_t system_table,
    const void *memory_map, size_t memory_map_size,
    size_t descriptor_size, uint32_t descriptor_version);
void bsd_firmware_metadata_reset_smap(void);
int bsd_firmware_metadata_add_smap(uint64_t base, uint64_t length,
    uint32_t type);
size_t bsd_firmware_metadata_smap_count(void);

#endif
