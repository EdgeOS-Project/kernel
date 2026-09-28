/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "compat/freebsd/contrib/dev/acpica/include/acpi.h"
#include "compat/freebsd/edgeos/acpi_tables.h"
#include "compat/freebsd/machine/acpica_machdep.h"
#include "compat/freebsd/dev/acpica/acpivar.h"

typedef struct test_rsdp {
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_physical;
    uint32_t length;
    uint64_t xsdt_physical;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed)) test_rsdp_t;

typedef struct test_xsdt {
    ACPI_TABLE_HEADER header;
    uint64_t entries[1];
} __attribute__((packed)) test_xsdt_t;

typedef struct test_table {
    ACPI_TABLE_HEADER header;
    uint32_t payload;
} __attribute__((packed)) test_table_t;

static void
set_checksum(void *object, size_t length, uint8_t *checksum)
{
    uint8_t *bytes = object;
    uint8_t sum = 0;
    size_t index;

    *checksum = 0;
    for (index = 0; index < length; ++index)
        sum = (uint8_t)(sum + bytes[index]);
    *checksum = (uint8_t)(0u - sum);
}

static void
count_subtable(ACPI_SUBTABLE_HEADER *header, void *argument)
{
    unsigned int *count = argument;

    assert(header != 0);
    ++*count;
}

int
main(void)
{
    test_rsdp_t rsdp;
    test_xsdt_t xsdt;
    test_table_t iort;
    uint8_t subtables[] = { 1, 2, 2, 4, 0xaa, 0xbb };
    vm_paddr_t found;
    unsigned int count = 0;

    memset(&rsdp, 0, sizeof(rsdp));
    memset(&xsdt, 0, sizeof(xsdt));
    memset(&iort, 0, sizeof(iort));
    memcpy(rsdp.signature, "RSD PTR ", 8);
    memcpy(rsdp.oem_id, "EDGEOS", 6);
    rsdp.revision = 2;
    rsdp.length = sizeof(rsdp);
    rsdp.xsdt_physical = (uint64_t)(uintptr_t)&xsdt;

    memcpy(xsdt.header.Signature, "XSDT", 4);
    xsdt.header.Length = sizeof(xsdt);
    xsdt.entries[0] = (uint64_t)(uintptr_t)&iort;
    set_checksum(&xsdt, sizeof(xsdt), &xsdt.header.Checksum);

    memcpy(iort.header.Signature, "IORT", 4);
    iort.header.Length = sizeof(iort);
    iort.payload = UINT32_C(0x12345678);
    set_checksum(&iort, sizeof(iort), &iort.header.Checksum);
    set_checksum(&rsdp, 20, &rsdp.checksum);
    set_checksum(&rsdp, sizeof(rsdp), &rsdp.extended_checksum);

    bsd_acpi_tables_install_rsdp((uint64_t)(uintptr_t)&rsdp);
    found = acpi_find_table("IORT");
    assert(found == (vm_paddr_t)(uintptr_t)&iort);
    assert(acpi_map_table(found, "IORT") == &iort);
    assert(acpi_map_table(found, "APIC") == 0);

    acpi_walk_subtables(subtables, subtables + sizeof(subtables),
        count_subtable, &count);
    assert(count == 2);

    iort.payload ^= 1u;
    assert(acpi_map_table(found, "IORT") == 0);
    return 0;
}
