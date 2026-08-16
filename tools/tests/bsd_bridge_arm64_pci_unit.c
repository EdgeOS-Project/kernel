/* SPDX-License-Identifier: MPL-2.0 */
/* Host unit tests for the generic ARM64 ECAM PCI backend. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/pci.h"
#include "compat/freebsd/machine/resource.h"

#define TEST_ROOT_NODE 1
#define TEST_PCI_NODE 2
#define TEST_GIC_NODE 3
#define TEST_SLOT 5
#define TEST_ECAM_SIZE (1024u * 1024u)

int bsd_pci_arch_initialize(void);

struct malloc_type M_DEVBUF[1];

static uint8_t g_ecam[TEST_ECAM_SIZE]
    __attribute__((aligned(4096)));
static bsd_pci_backend_ops_t g_operations;

void *
bsd_mallocarray(size_t count, size_t size, struct malloc_type *type,
    int flags)
{
    (void)type;
    (void)flags;
    if (count != 0 && size > SIZE_MAX / count)
        return 0;
    return calloc(count, size);
}

void
bsd_free(void *allocation, struct malloc_type *type)
{
    (void)type;
    free(allocation);
}

int
bsd_pci_initialize(const bsd_pci_backend_ops_t *operations)
{
    assert(operations != 0);
    g_operations = *operations;
    return 0;
}

phandle_t
bsd_ofw_fdt_find_compatible(const char *compatible,
    unsigned int index)
{
    assert(strcmp(compatible, "pci-host-ecam-generic") == 0);
    return index == 0 ? TEST_PCI_NODE : 0;
}

int
bsd_ofw_fdt_get_reg(phandle_t node, unsigned int index,
    uint64_t *address, uint64_t *size)
{
    if (node != TEST_PCI_NODE || index != 0 || !address || !size)
        return 22;
    *address = (uint64_t)(uintptr_t)g_ecam;
    *size = sizeof(g_ecam);
    return 0;
}

phandle_t
OF_parent(phandle_t node)
{
    if (node == TEST_PCI_NODE || node == TEST_GIC_NODE)
        return TEST_ROOT_NODE;
    return 0;
}

phandle_t
OF_node_from_xref(phandle_t xref)
{
    return xref == TEST_GIC_NODE ? TEST_GIC_NODE : 0;
}

static const pcell_t *
test_property(phandle_t node, const char *property, size_t *cell_count)
{
    static const pcell_t root_address_cells[] = {2};
    static const pcell_t bus_range[] = {0, 0};
    static const pcell_t domain[] = {0};
    static const pcell_t pci_address_cells[] = {3};
    static const pcell_t pci_size_cells[] = {2};
    static const pcell_t pci_interrupt_cells[] = {1};
    static const pcell_t ranges[] = {
        UINT32_C(0x01000000), 0, 0,
        0, UINT32_C(0x3eff0000), 0, UINT32_C(0x00010000),
        UINT32_C(0x02000000), 0, UINT32_C(0x10000000),
        0, UINT32_C(0x10000000), 0, UINT32_C(0x2eff0000),
    };
    static const pcell_t interrupt_map_mask[] = {
        UINT32_C(0x00001800), 0, 0, 7,
    };
    static const pcell_t interrupt_map[] = {
        UINT32_C(0x00002800), 0, 0, 1,
        TEST_GIC_NODE, 0, 0, 0, 4, 4,
    };
    static const pcell_t gic_address_cells[] = {2};
    static const pcell_t gic_interrupt_cells[] = {3};

#define RETURN_PROPERTY(value) do { \
    *cell_count = sizeof(value) / sizeof((value)[0]); \
    return (value); \
} while (0)

    if (node == TEST_ROOT_NODE &&
        strcmp(property, "#address-cells") == 0)
        RETURN_PROPERTY(root_address_cells);
    if (node == TEST_PCI_NODE &&
        strcmp(property, "bus-range") == 0)
        RETURN_PROPERTY(bus_range);
    if (node == TEST_PCI_NODE &&
        strcmp(property, "linux,pci-domain") == 0)
        RETURN_PROPERTY(domain);
    if (node == TEST_PCI_NODE &&
        strcmp(property, "#address-cells") == 0)
        RETURN_PROPERTY(pci_address_cells);
    if (node == TEST_PCI_NODE &&
        strcmp(property, "#size-cells") == 0)
        RETURN_PROPERTY(pci_size_cells);
    if (node == TEST_PCI_NODE &&
        strcmp(property, "#interrupt-cells") == 0)
        RETURN_PROPERTY(pci_interrupt_cells);
    if (node == TEST_PCI_NODE &&
        strcmp(property, "ranges") == 0)
        RETURN_PROPERTY(ranges);
    if (node == TEST_PCI_NODE &&
        strcmp(property, "interrupt-map-mask") == 0)
        RETURN_PROPERTY(interrupt_map_mask);
    if (node == TEST_PCI_NODE &&
        strcmp(property, "interrupt-map") == 0)
        RETURN_PROPERTY(interrupt_map);
    if (node == TEST_GIC_NODE &&
        strcmp(property, "#address-cells") == 0)
        RETURN_PROPERTY(gic_address_cells);
    if (node == TEST_GIC_NODE &&
        strcmp(property, "#interrupt-cells") == 0)
        RETURN_PROPERTY(gic_interrupt_cells);
    *cell_count = 0;
    return 0;
#undef RETURN_PROPERTY
}

ssize_t
OF_getencprop(phandle_t node, const char *property, pcell_t *buffer,
    size_t length)
{
    size_t cell_count;
    const pcell_t *value = test_property(node, property, &cell_count);
    size_t bytes = cell_count * sizeof(*value);

    if (!value)
        return -1;
    if (length < bytes)
        return (ssize_t)bytes;
    memcpy(buffer, value, bytes);
    return (ssize_t)bytes;
}

ssize_t
OF_getencprop_alloc(phandle_t node, const char *property,
    void **buffer)
{
    size_t cell_count;
    const pcell_t *value = test_property(node, property, &cell_count);
    size_t bytes = cell_count * sizeof(*value);

    if (!buffer || !value)
        return -1;
    *buffer = malloc(bytes);
    assert(*buffer != 0);
    memcpy(*buffer, value, bytes);
    return (ssize_t)bytes;
}

void
OF_prop_free(void *buffer)
{
    free(buffer);
}

static void
write_config(unsigned int slot, unsigned int offset,
    uint32_t value, unsigned int width)
{
    size_t ecam_offset = ((size_t)slot << 15) + offset;

    assert(ecam_offset + width <= sizeof(g_ecam));
    memcpy(&g_ecam[ecam_offset], &value, width);
}

int
main(void)
{
    bsd_pci_location_t location;
    uint64_t host_address;
    uint32_t interrupt;
    uint32_t flags;
    uint32_t bar;

    memset(g_ecam, UINT8_C(0xff), sizeof(g_ecam));
    memset(&g_ecam[(size_t)TEST_SLOT << 15], 0, 4096);
    write_config(TEST_SLOT, 0x00, UINT32_C(0x001b1b36), 4);
    write_config(TEST_SLOT, 0x0e, 0, 1);
    write_config(TEST_SLOT, 0x3d, 1, 1);

    assert(bsd_pci_arch_initialize() == 0);
    assert(g_operations.function_count(g_operations.context) == 1);
    assert(g_operations.function_at(
        g_operations.context, 0, &location) == 0);
    assert(location.domain == 0);
    assert(location.bus == 0);
    assert(location.slot == TEST_SLOT);
    assert(location.function == 0);
    assert(g_operations.read_config(g_operations.context,
        &location, 0, 2) == UINT32_C(0x1b36));

    assert(g_operations.prepare_device(
        g_operations.context, &location) == 0);
    bar = g_operations.read_config(
        g_operations.context, &location, 0x10, 4);
    assert((bar & ~UINT32_C(15)) == UINT32_C(0x10000000));
    assert(g_operations.translate_resource(g_operations.context,
        &location, SYS_RES_MEMORY, bar & ~UINT32_C(15), 16,
        &host_address) == 0);
    assert(host_address == UINT64_C(0x10000000));

    assert(g_operations.legacy_interrupt(g_operations.context,
        &location, UINT8_MAX, &interrupt, &flags) == 0);
    assert(interrupt == 36);
    assert(flags == 4);
    return 0;
}
