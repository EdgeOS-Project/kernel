/* SPDX-License-Identifier: MPL-2.0 */
/* Host tests for firmware metadata passed to imported FreeBSD drivers. */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "compat/freebsd/edgeos/firmware_metadata.h"
#include "compat/freebsd/machine/metadata.h"
#include "compat/freebsd/machine/pc/bios.h"
#include <sys/errno.h>
#include <sys/efi.h>
#include "compat/freebsd/sys/linker.h"

void *
bsd_memset(void *destination, int value, size_t length)
{
    return memset(destination, value, length);
}

void *
bsd_memcpy(void *destination, const void *source, size_t length)
{
    return memcpy(destination, source, length);
}

static void
test_efi_metadata(void)
{
    struct efi_md input[2] = {0};
    struct efi_map_header *header;
    struct efi_md *output;
    size_t descriptor_offset;

    assert(preload_search_info(preload_kmdp,
        MODINFO_METADATA | MODINFOMD_EFI_MAP) == 0);
    assert(bsd_firmware_metadata_configure_efi(0, input, sizeof(input),
        sizeof(input[0]), EFI_MEMORY_DESCRIPTOR_VERSION) == 22);
    assert(bsd_firmware_metadata_configure_efi(0x1000, 0, sizeof(input),
        sizeof(input[0]), EFI_MEMORY_DESCRIPTOR_VERSION) == 22);
    assert(bsd_firmware_metadata_configure_efi(0x1000, input, 0,
        sizeof(input[0]), EFI_MEMORY_DESCRIPTOR_VERSION) == 22);
    assert(bsd_firmware_metadata_configure_efi(0x1000, input,
        sizeof(input), sizeof(input[0]) - 1u,
        EFI_MEMORY_DESCRIPTOR_VERSION) == 22);
    assert(bsd_firmware_metadata_configure_efi(0x1000, input,
        sizeof(input) - 1u, sizeof(input[0]),
        EFI_MEMORY_DESCRIPTOR_VERSION) == 22);
    assert(bsd_firmware_metadata_configure_efi(0x1000, input,
        sizeof(input[0]) * 4000u, sizeof(input[0]),
        EFI_MEMORY_DESCRIPTOR_VERSION) == 7);

    input[0].md_type = EFI_MD_TYPE_RT_DATA;
    input[0].md_phys = 0x12345000u;
    input[0].md_pages = 4;
    input[0].md_attr = EFI_MD_ATTR_RT | EFI_MD_ATTR_WB;
    input[1].md_type = EFI_MD_TYPE_FREE;
    input[1].md_phys = 0x20000000u;
    input[1].md_pages = 8;
    input[1].md_attr = EFI_MD_ATTR_WB;
    assert(bsd_firmware_metadata_configure_efi(0xfeed0000u, input,
        sizeof(input), sizeof(input[0]),
        EFI_MEMORY_DESCRIPTOR_VERSION) == 0);
    assert(efi_systbl_phys == 0xfeed0000u);
    assert(input[0].md_virt == 0);
    header = (struct efi_map_header *)(void *)preload_search_info(
        preload_kmdp, MODINFO_METADATA | MODINFOMD_EFI_MAP);
    assert(header != 0);
    assert(header->memory_size == sizeof(input));
    assert(header->descriptor_size == sizeof(input[0]));
    assert(header->descriptor_version == EFI_MEMORY_DESCRIPTOR_VERSION);
    descriptor_offset = (sizeof(*header) + 15u) & ~(size_t)15u;
    output = (struct efi_md *)(void *)((uint8_t *)header +
        descriptor_offset);
    assert(((uintptr_t)output & 15u) == 0);
    assert(output[0].md_phys == input[0].md_phys);
    assert(output[0].md_virt == input[0].md_phys);
    assert(output[0].md_attr == input[0].md_attr);
    assert(output[1].md_phys == input[1].md_phys);
    assert(output[1].md_virt == 0);
}

static void
test_smap_metadata(void)
{
    const struct bios_smap *entries;

    bsd_firmware_metadata_reset_smap();
    assert(bsd_firmware_metadata_smap_count() == 0);
    assert(preload_search_info(preload_kmdp,
        MODINFO_METADATA | MODINFOMD_SMAP) == 0);
    assert(bsd_firmware_metadata_add_smap(0, 0, SMAP_TYPE_MEMORY) == 22);
    assert(bsd_firmware_metadata_add_smap(UINT64_MAX, 2,
        SMAP_TYPE_RESERVED) == 22);
    assert(bsd_firmware_metadata_add_smap(0x100000u, 0x200000u,
        SMAP_TYPE_MEMORY) == 0);
    entries = (const struct bios_smap *)(const void *)preload_search_info(
        preload_kmdp, MODINFO_METADATA | MODINFOMD_SMAP);
    assert(entries != 0);
    assert(entries[0].base == 0x100000u);
    assert(entries[0].length == 0x200000u);
    assert(entries[0].type == SMAP_TYPE_MEMORY);
    for (size_t index = 1; index < 256; ++index) {
        assert(bsd_firmware_metadata_add_smap(index * 0x1000u,
            0x1000u, SMAP_TYPE_RESERVED) == 0);
    }
    assert(bsd_firmware_metadata_smap_count() == 256);
    assert(bsd_firmware_metadata_add_smap(0x400000u, 0x1000u,
        SMAP_TYPE_RESERVED) == 7);
    bsd_firmware_metadata_reset_smap();
    assert(bsd_firmware_metadata_smap_count() == 0);
    assert(preload_search_info(preload_kmdp,
        MODINFO_METADATA | MODINFOMD_SMAP) == 0);
}

int
main(void)
{
    test_efi_metadata();
    test_smap_metadata();
    printf("bsd_bridge_firmware_metadata_unit: PASS\n");
    return 0;
}
