/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Shared ACPI table discovery for unmodified BSD drivers.
 *
 * The parsing and validation rules follow the complete FreeBSD machine ACPI
 * contract.  EdgeOS keeps the discovery policy here so architecture code only
 * supplies the firmware root and the BSD driver sources remain unchanged.
 */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/contrib/dev/acpica/include/acpi.h"
#include "compat/freebsd/edgeos/acpi_tables.h"
#include "compat/freebsd/vm/pmap.h"
#include "compat/freebsd/vm/vm.h"

#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
#include "drivers/acpi.h"
#endif

#define BSD_ACPI_RSDP_V1_LENGTH 20u
#define BSD_ACPI_RSDP_V2_MIN_LENGTH 36u
#define BSD_ACPI_MAX_TABLE_LENGTH (16u * 1024u * 1024u)

typedef struct bsd_acpi_rsdp {
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_physical;
    uint32_t length;
    uint64_t xsdt_physical;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed)) bsd_acpi_rsdp_t;

static uint64_t g_bsd_acpi_rsdp;

static int
bsd_acpi_bytes_equal(const void *left, const void *right, size_t length)
{
    const uint8_t *left_bytes = left;
    const uint8_t *right_bytes = right;
    size_t index;

    if (!left || !right)
        return 0;
    for (index = 0; index < length; ++index) {
        if (left_bytes[index] != right_bytes[index])
            return 0;
    }
    return 1;
}

static int
bsd_acpi_checksum_valid(const void *table, size_t length)
{
    const uint8_t *bytes = table;
    uint8_t checksum = 0;
    size_t index;

    if (!table || length == 0)
        return 0;
    for (index = 0; index < length; ++index)
        checksum = (uint8_t)(checksum + bytes[index]);
    return checksum == 0;
}

static uint32_t
bsd_acpi_read_le32(const void *value)
{
    const uint8_t *bytes = value;

    return (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static uint64_t
bsd_acpi_read_le64(const void *value)
{
    const uint8_t *bytes = value;

    return (uint64_t)bsd_acpi_read_le32(bytes) |
        ((uint64_t)bsd_acpi_read_le32(bytes + 4) << 32);
}

static void *
bsd_acpi_map_physical(vm_paddr_t physical_address, size_t length)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)length;
    return (void *)(uintptr_t)physical_address;
#else
    return pmap_mapbios((uint64_t)physical_address, (uint64_t)length);
#endif
}

static void
bsd_acpi_unmap_physical(void *mapping, size_t length)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)mapping;
    (void)length;
#else
    pmap_unmapbios(mapping, (uint64_t)length);
#endif
}

static uint64_t
bsd_acpi_root_pointer(void)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    return acpi_rsdp_address();
#else
    return g_bsd_acpi_rsdp;
#endif
}

static void *
bsd_acpi_map_root(uint64_t root_pointer, size_t length)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    (void)length;
    return (void *)(uintptr_t)root_pointer;
#else
    return bsd_acpi_map_physical((vm_paddr_t)root_pointer, length);
#endif
}

static void
bsd_acpi_unmap_root(void *mapping, size_t length)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    (void)mapping;
    (void)length;
#else
    bsd_acpi_unmap_physical(mapping, length);
#endif
}

void
bsd_acpi_tables_install_rsdp(uint64_t physical_address)
{
    g_bsd_acpi_rsdp = physical_address;
}

uint64_t
bsd_acpi_tables_rsdp_address(void)
{
    return bsd_acpi_root_pointer();
}

void *
bsd_acpi_map_table(vm_paddr_t physical_address, const char *signature)
{
    ACPI_TABLE_HEADER *header;
    uint32_t length;

    if (physical_address == 0 || !signature)
        return 0;
    header = bsd_acpi_map_physical(physical_address, sizeof(*header));
    if (!header)
        return 0;
    if (!bsd_acpi_bytes_equal(header->Signature, signature,
        ACPI_NAMESEG_SIZE)) {
        bsd_acpi_unmap_physical(header, sizeof(*header));
        return 0;
    }
    length = header->Length;
    bsd_acpi_unmap_physical(header, sizeof(*header));
    if (length < sizeof(*header) || length > BSD_ACPI_MAX_TABLE_LENGTH)
        return 0;
    header = bsd_acpi_map_physical(physical_address, length);
    if (!header)
        return 0;
    if (!bsd_acpi_checksum_valid(header, length)) {
        bsd_acpi_unmap_physical(header, length);
        return 0;
    }
    return header;
}

void
bsd_acpi_unmap_table(void *table)
{
    ACPI_TABLE_HEADER *header = table;
    uint32_t length;

    if (!header)
        return;
    length = header->Length;
    if (length < sizeof(*header) || length > BSD_ACPI_MAX_TABLE_LENGTH)
        return;
    bsd_acpi_unmap_physical(table, length);
}

static vm_paddr_t
bsd_acpi_find_in_sdt(vm_paddr_t sdt_physical, const char *sdt_signature,
    size_t entry_width, const char *wanted_signature)
{
    ACPI_TABLE_HEADER *sdt;
    const uint8_t *entry;
    const uint8_t *end;
    vm_paddr_t result = 0;

    sdt = bsd_acpi_map_table(sdt_physical, sdt_signature);
    if (!sdt)
        return 0;
    entry = (const uint8_t *)sdt + sizeof(*sdt);
    end = (const uint8_t *)sdt + sdt->Length;
    while ((size_t)(end - entry) >= entry_width) {
        vm_paddr_t candidate = entry_width == sizeof(uint64_t) ?
            (vm_paddr_t)bsd_acpi_read_le64(entry) :
            (vm_paddr_t)bsd_acpi_read_le32(entry);
        ACPI_TABLE_HEADER *table;

        table = bsd_acpi_map_table(candidate, wanted_signature);
        if (table) {
            bsd_acpi_unmap_table(table);
            result = candidate;
            break;
        }
        entry += entry_width;
    }
    bsd_acpi_unmap_table(sdt);
    return result;
}

vm_paddr_t
bsd_acpi_find_table(const char *signature)
{
    static const char rsdp_signature[8] = {
        'R', 'S', 'D', ' ', 'P', 'T', 'R', ' '
    };
    bsd_acpi_rsdp_t *rsdp;
    uint64_t root_pointer;
    uint32_t rsdp_length;
    vm_paddr_t result = 0;

    if (!signature)
        return 0;
    root_pointer = bsd_acpi_root_pointer();
    if (root_pointer == 0)
        return 0;
    rsdp = bsd_acpi_map_root(root_pointer, BSD_ACPI_RSDP_V2_MIN_LENGTH);
    if (!rsdp)
        return 0;
    if (!bsd_acpi_bytes_equal(rsdp->signature, rsdp_signature,
        sizeof(rsdp_signature)) ||
        !bsd_acpi_checksum_valid(rsdp, BSD_ACPI_RSDP_V1_LENGTH))
        goto out;
    if (rsdp->revision >= 2) {
        rsdp_length = rsdp->length;
        if (rsdp_length < BSD_ACPI_RSDP_V2_MIN_LENGTH ||
            rsdp_length > sizeof(*rsdp) ||
            !bsd_acpi_checksum_valid(rsdp, rsdp_length))
            goto out;
        if (rsdp->xsdt_physical != 0) {
            result = bsd_acpi_find_in_sdt(
                (vm_paddr_t)rsdp->xsdt_physical, "XSDT",
                sizeof(uint64_t), signature);
        }
    }
    if (result == 0 && rsdp->rsdt_physical != 0) {
        result = bsd_acpi_find_in_sdt(
            (vm_paddr_t)rsdp->rsdt_physical, "RSDT",
            sizeof(uint32_t), signature);
    }
out:
    bsd_acpi_unmap_root(rsdp, BSD_ACPI_RSDP_V2_MIN_LENGTH);
    return result;
}

void
acpi_walk_subtables(void *first, void *end,
    void (*handler)(ACPI_SUBTABLE_HEADER *, void *), void *argument)
{
    uint8_t *entry = first;
    uint8_t *limit = end;

    if (!entry || !limit || entry > limit || !handler)
        return;
    while ((size_t)(limit - entry) >= sizeof(ACPI_SUBTABLE_HEADER)) {
        ACPI_SUBTABLE_HEADER *header = (ACPI_SUBTABLE_HEADER *)entry;

        if (header->Length < sizeof(*header) ||
            (size_t)(limit - entry) < header->Length)
            return;
        handler(header, argument);
        entry += header->Length;
    }
}
