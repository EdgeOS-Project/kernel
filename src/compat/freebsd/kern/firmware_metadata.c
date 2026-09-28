/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS boot metadata adapter for unmodified FreeBSD firmware drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/firmware_metadata.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/machine/metadata.h"
#include "compat/freebsd/machine/pc/bios.h"
#include "compat/freebsd/sys/linker.h"
#include <sys/errno.h>
#include <sys/efi.h>

#define BSD_EFI_MEMORY_MAP_MAX (128u * 1024u)
#define BSD_SMAP_ENTRY_MAX 256u
#define BSD_METADATA_EINVAL 22
#define BSD_METADATA_E2BIG 7

typedef struct {
    struct efi_map_header header;
    uint8_t alignment_padding[16u - sizeof(struct efi_map_header) % 16u];
    uint8_t descriptors[BSD_EFI_MEMORY_MAP_MAX];
} bsd_efi_metadata_t;

typedef struct {
    uint32_t size;
    struct bios_smap entries[BSD_SMAP_ENTRY_MAX];
} bsd_smap_metadata_t;

static bsd_efi_metadata_t g_efi_metadata __attribute__((aligned(16)));
static bsd_smap_metadata_t g_smap_metadata;
static size_t g_smap_count;
static volatile uint32_t g_efi_ready;

caddr_t preload_kmdp = (caddr_t)&g_efi_metadata;
vm_paddr_t efi_systbl_phys;

_Static_assert(offsetof(bsd_efi_metadata_t, descriptors) ==
    ((sizeof(struct efi_map_header) + 15u) & ~(size_t)15u),
    "EFI metadata header alignment must match the upstream ABI");

static size_t
efi_descriptor_offset(void)
{
    return offsetof(bsd_efi_metadata_t, descriptors);
}

int
bsd_firmware_metadata_configure_efi(uint64_t system_table,
    const void *memory_map, size_t memory_map_size,
    size_t descriptor_size, uint32_t descriptor_version)
{
    uint8_t *descriptors;
    size_t offset;

    if (system_table == 0 || !memory_map || memory_map_size == 0 ||
        descriptor_size < sizeof(struct efi_md) ||
        memory_map_size % descriptor_size != 0)
        return BSD_METADATA_EINVAL;
    if (memory_map_size > sizeof(g_efi_metadata.descriptors))
        return BSD_METADATA_E2BIG;

    offset = efi_descriptor_offset();
    descriptors = (uint8_t *)&g_efi_metadata + offset;
    bsd_memset(&g_efi_metadata, 0, sizeof(g_efi_metadata));
    g_efi_metadata.header.memory_size = memory_map_size;
    g_efi_metadata.header.descriptor_size = descriptor_size;
    g_efi_metadata.header.descriptor_version = descriptor_version;
    bsd_memcpy(descriptors, memory_map, memory_map_size);

    for (size_t position = 0; position < memory_map_size;
         position += descriptor_size) {
        struct efi_md *descriptor =
            (struct efi_md *)(void *)(descriptors + position);

        if ((descriptor->md_attr & EFI_MD_ATTR_RT) != 0 &&
            descriptor->md_virt == 0)
            descriptor->md_virt = descriptor->md_phys;
    }

    efi_systbl_phys = system_table;
    __atomic_store_n(&g_efi_ready, 1u, __ATOMIC_RELEASE);
    return 0;
}

void
bsd_firmware_metadata_reset_smap(void)
{
    bsd_memset(&g_smap_metadata, 0, sizeof(g_smap_metadata));
    g_smap_count = 0;
}

int
bsd_firmware_metadata_add_smap(uint64_t base, uint64_t length,
    uint32_t type)
{
    struct bios_smap *entry;

    if (length == 0 || base > UINT64_MAX - (length - 1u))
        return BSD_METADATA_EINVAL;
    if (g_smap_count >= BSD_SMAP_ENTRY_MAX)
        return BSD_METADATA_E2BIG;
    entry = &g_smap_metadata.entries[g_smap_count++];
    entry->base = base;
    entry->length = length;
    entry->type = type;
    g_smap_metadata.size =
        (uint32_t)(g_smap_count * sizeof(struct bios_smap));
    return 0;
}

size_t
bsd_firmware_metadata_smap_count(void)
{
    return g_smap_count;
}

caddr_t
preload_search_info(caddr_t metadata, int type)
{
    (void)metadata;
    if (type == (MODINFO_METADATA | MODINFOMD_EFI_MAP) &&
        __atomic_load_n(&g_efi_ready, __ATOMIC_ACQUIRE) != 0)
        return (caddr_t)&g_efi_metadata;
#if defined(__x86_64__) || defined(BSD_BRIDGE_FIRMWARE_METADATA_TEST_X86)
    if (type == (MODINFO_METADATA | MODINFOMD_SMAP) && g_smap_count != 0)
        return (caddr_t)g_smap_metadata.entries;
#endif
    return (caddr_t)0;
}
