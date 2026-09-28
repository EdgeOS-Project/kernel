/* SPDX-License-Identifier: MPL-2.0 */
/* Legacy firmware discovery interface used by imported BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_PC_BIOS_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_PC_BIOS_H

#include <sys/types.h>
#include <vm/pmap.h>

#define BIOS_PADDRTOVADDR(address) \
    ((uintptr_t)pmap_mapbios((uint64_t)(address), 1))

#define SMAP_TYPE_MEMORY 1
#define SMAP_TYPE_RESERVED 2
#define SMAP_TYPE_ACPI_RECLAIM 3
#define SMAP_TYPE_ACPI_NVS 4
#define SMAP_TYPE_ACPI_ERROR 5
#define SMAP_TYPE_PRAM 12

struct bios_smap {
    uint64_t base;
    uint64_t length;
    uint32_t type;
} __attribute__((packed));

struct bios_smap_xattr {
    struct bios_smap base;
    uint32_t xattr;
} __attribute__((packed));

uint32_t bios_sigsearch(uint32_t start, unsigned char *signature,
    int signature_length, int paragraph_length, int signature_offset);

#endif
