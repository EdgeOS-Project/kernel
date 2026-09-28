/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared immutable OFW Device Tree implementation. */

#include <libfdt.h>

#include <assert.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/dev/ofw/ofw_bus_subr.h"

#define TEST_BLOB_SIZE 4096

static unsigned char g_blob[TEST_BLOB_SIZE];

static void
build_test_tree(void)
{
    static const char root_compatible[] =
        "edgeos,test-board\0qemu,virt";
    static const char uart_compatible[] =
        "arm,pl011\0arm,primecell";
    fdt32_t registers[] = {
        cpu_to_fdt32(0),
        cpu_to_fdt32(UINT32_C(0x1000)),
    };
    fdt32_t ranges[] = {
        cpu_to_fdt32(0),
        cpu_to_fdt32(0),
        cpu_to_fdt32(UINT32_C(0x09000000)),
        cpu_to_fdt32(UINT32_C(0x00100000)),
    };
    fdt32_t interrupt[] = {
        cpu_to_fdt32(0),
        cpu_to_fdt32(1),
        cpu_to_fdt32(4),
    };
    fdt32_t interrupt_map[] = {
        cpu_to_fdt32(UINT32_C(0x1000)),
        cpu_to_fdt32(5),
        cpu_to_fdt32(1),
        cpu_to_fdt32(0),
        cpu_to_fdt32(7),
        cpu_to_fdt32(4),
    };
    fdt32_t interrupt_map_mask[] = {
        cpu_to_fdt32(UINT32_MAX),
        cpu_to_fdt32(UINT32_MAX),
    };
    fdt32_t msi_map[] = {
        cpu_to_fdt32(UINT32_C(0x100)),
        cpu_to_fdt32(77),
        cpu_to_fdt32(UINT32_C(0x200)),
        cpu_to_fdt32(UINT32_C(0x20)),
    };
    fdt32_t iommu_map[] = {
        cpu_to_fdt32(UINT32_C(0x300)),
        cpu_to_fdt32(77),
        cpu_to_fdt32(UINT32_C(0x400)),
        cpu_to_fdt32(UINT32_C(0x10)),
    };
    fdt32_t resets[] = {
        cpu_to_fdt32(77),
        cpu_to_fdt32(5),
        cpu_to_fdt32(77),
        cpu_to_fdt32(9),
    };
    static const char reset_names[] = "bus\0logic";
    static const char clock_output_names[] = "card\0sample";

    assert(fdt_create(g_blob, sizeof(g_blob)) == 0);
    assert(fdt_finish_reservemap(g_blob) == 0);
    assert(fdt_begin_node(g_blob, "") == 0);
    assert(fdt_property(g_blob, "compatible", root_compatible,
        sizeof(root_compatible)) == 0);
    assert(fdt_property_u32(g_blob, "#address-cells", 2) == 0);
    assert(fdt_property_u32(g_blob, "#size-cells", 2) == 0);
    assert(fdt_property_u32(g_blob, "interrupt-parent", 1) == 0);

    assert(fdt_begin_node(g_blob, "aliases") == 0);
    assert(fdt_property_string(g_blob, "serial10",
        "/soc/serial@9000000") == 0);
    assert(fdt_end_node(g_blob) == 0);

    assert(fdt_begin_node(g_blob, "chosen") == 0);
    assert(fdt_property_string(g_blob, "bootargs",
        "console=ttyAMA0 root=/dev/vda") == 0);
    assert(fdt_property_string(g_blob, "stdout-path",
        "serial10:115200n8") == 0);
    assert(fdt_end_node(g_blob) == 0);

    assert(fdt_begin_node(g_blob, "soc") == 0);
    assert(fdt_property_u32(g_blob, "#address-cells", 1) == 0);
    assert(fdt_property_u32(g_blob, "#size-cells", 1) == 0);
    assert(fdt_property(g_blob, "ranges", ranges,
        sizeof(ranges)) == 0);
    assert(fdt_property(g_blob, "interrupt-map", interrupt_map,
        sizeof(interrupt_map)) == 0);
    assert(fdt_property(g_blob, "interrupt-map-mask",
        interrupt_map_mask, sizeof(interrupt_map_mask)) == 0);
    assert(fdt_property(g_blob, "msi-map", msi_map,
        sizeof(msi_map)) == 0);
    assert(fdt_property_u32(g_blob, "msi-map-mask", UINT32_MAX) == 0);
    assert(fdt_property(g_blob, "iommu-map", iommu_map,
        sizeof(iommu_map)) == 0);
    assert(fdt_property_u32(g_blob, "iommu-map-mask", UINT32_MAX) == 0);

    assert(fdt_begin_node(g_blob, "serial@9000000") == 0);
    assert(fdt_property(g_blob, "compatible", uart_compatible,
        sizeof(uart_compatible)) == 0);
    assert(fdt_property_string(g_blob, "status", "okay") == 0);
    assert(fdt_property(g_blob, "reg", registers,
        sizeof(registers)) == 0);
    assert(fdt_property(g_blob, "interrupts", interrupt,
        sizeof(interrupt)) == 0);
    assert(fdt_property_u32(g_blob, "msi-parent", 1) == 0);
    assert(fdt_property(g_blob, "resets", resets, sizeof(resets)) == 0);
    assert(fdt_property(g_blob, "reset-names", reset_names,
        sizeof(reset_names)) == 0);
    assert(fdt_property(g_blob, "clock-output-names",
        clock_output_names, sizeof(clock_output_names)) == 0);
    assert(fdt_property_u32(g_blob, "phandle", 42) == 0);
    assert(fdt_end_node(g_blob) == 0);

    assert(fdt_begin_node(g_blob, "reset-controller@7000000") == 0);
    assert(fdt_property_string(g_blob, "compatible",
        "edgeos,test-reset") == 0);
    assert(fdt_property(g_blob, "reset-controller", 0, 0) == 0);
    assert(fdt_property_u32(g_blob, "#reset-cells", 1) == 0);
    assert(fdt_property_u32(g_blob, "phandle", 77) == 0);
    assert(fdt_end_node(g_blob) == 0);

    assert(fdt_begin_node(g_blob, "disabled@a000000") == 0);
    assert(fdt_property_string(g_blob, "compatible",
        "edgeos,disabled-device") == 0);
    assert(fdt_property_string(g_blob, "status", "disabled") == 0);
    assert(fdt_end_node(g_blob) == 0);
    assert(fdt_end_node(g_blob) == 0);

    assert(fdt_begin_node(g_blob, "interrupt-controller@8000000") == 0);
    assert(fdt_property_string(g_blob, "compatible", "arm,gic-v3") == 0);
    assert(fdt_property(g_blob, "interrupt-controller", 0, 0) == 0);
    assert(fdt_property_u32(g_blob, "#interrupt-cells", 3) == 0);
    assert(fdt_property_u32(g_blob, "phandle", 1) == 0);
    assert(fdt_end_node(g_blob) == 0);
    assert(fdt_end_node(g_blob) == 0);
    assert(fdt_finish(g_blob) == 0);
}

static void
test_tree_navigation(void)
{
    phandle_t root = OF_peer(0);
    phandle_t aliases = OF_child(root);
    phandle_t chosen = OF_peer(aliases);
    phandle_t soc = OF_peer(chosen);
    phandle_t uart = OF_child(soc);
    phandle_t reset = OF_peer(uart);
    phandle_t disabled = OF_peer(reset);
    char buffer[128];

    assert(root != 0);
    assert(aliases == OF_finddevice("/aliases"));
    assert(chosen == OF_finddevice("/chosen"));
    assert(soc == OF_finddevice("/soc"));
    assert(uart == OF_finddevice("/soc/serial@9000000"));
    assert(reset == OF_finddevice("/soc/reset-controller@7000000"));
    assert(disabled == OF_finddevice("/soc/disabled@a000000"));
    assert(OF_parent(uart) == soc);
    assert(OF_parent(soc) == root);
    assert(OF_parent(root) == 0);
    assert(OF_peer(disabled) == 0);
    assert(OF_package_to_path(uart, buffer, sizeof(buffer)) == 19);
    assert(bsd_strcmp(buffer, "/soc/serial@9000000") == 0);
    assert(OF_canon("/soc/serial@9000000", buffer,
        sizeof(buffer)) == 19);
    assert(OF_finddevice("/missing") == (phandle_t)-1);
    assert(OF_finddevice("serial10") == uart);
    assert(OF_finddevice("serial10:115200n8") == uart);
    assert(OF_finddevice("/soc/serial@9000000:115200n8") == uart);
    assert(bsd_ofw_fdt_stdout_node() == uart);
    assert(OF_finddevice("missing-alias") == (phandle_t)-1);
    assert(OF_package_to_path((phandle_t)-1, buffer,
        sizeof(buffer)) == -1);
}

static void
test_properties(void)
{
    phandle_t root = OF_peer(0);
    phandle_t chosen = OF_finddevice("/chosen");
    phandle_t uart = OF_finddevice("/soc/serial@9000000");
    char buffer[128];
    pcell_t cells[4] = { 0 };
    void *allocated = 0;
    ssize_t length;
    uint64_t address;
    uint64_t size;
    uint32_t interrupt;
    uint32_t interrupt_flags;
    size_t resource_count;
    const char **string_array = 0;

    length = OF_getprop(root, "compatible", buffer, sizeof(buffer));
    assert(length == 28);
    assert(bsd_strcmp(buffer, "edgeos,test-board") == 0);
    assert(OF_getproplen(chosen, "bootargs") == 30);
    assert(OF_getprop(chosen, "bootargs", buffer, 8) == 30);
    assert(bsd_strncmp(buffer, "console=", 8) == 0);
    assert(OF_getproplen(uart, "name") == 15);
    assert(OF_getprop(uart, "name", buffer, sizeof(buffer)) == 15);
    assert(bsd_strcmp(buffer, "serial@9000000") == 0);
    assert(OF_hasprop(uart, "reg"));
    assert(!OF_hasprop(uart, "missing"));

    assert(bsd_ofw_fdt_get_reg_count(uart, &resource_count) == 0);
    assert(resource_count == 1);
    assert(OF_getencprop(uart, "reg", cells, sizeof(cells)) ==
        (ssize_t)(2 * sizeof(cells[0])));
    assert(cells[0] == 0);
    assert(cells[1] == UINT32_C(0x1000));
    assert(bsd_ofw_fdt_get_reg(uart, 0, &address, &size) == 0);
    assert(address == UINT64_C(0x09000000));
    assert(size == UINT64_C(0x1000));
    assert(bsd_ofw_fdt_get_reg(uart, 1, &address, &size) != 0);
    assert(bsd_ofw_fdt_get_interrupt_count(
        uart, &resource_count) == 0);
    assert(resource_count == 1);
    assert(bsd_ofw_fdt_get_interrupt(
        uart, 0, &interrupt, &interrupt_flags) == 0);
    assert(interrupt == 33);
    assert(interrupt_flags == 4);
    assert(bsd_ofw_fdt_get_interrupt(
        uart, 1, &interrupt, &interrupt_flags) != 0);
    assert(OF_searchencprop(uart, "#address-cells", cells,
        sizeof(cells[0])) == (ssize_t)sizeof(cells[0]));
    assert(cells[0] == 1);

    length = OF_getprop_alloc(chosen, "bootargs", &allocated);
    assert(length == 30);
    assert(allocated != 0);
    assert(bsd_strcmp(allocated,
        "console=ttyAMA0 root=/dev/vda") == 0);
    OF_prop_free(allocated);
    allocated = 0;
    assert(OF_getencprop_alloc(uart, "reg", &allocated) ==
        (ssize_t)(2 * sizeof(cells[0])));
    assert(((pcell_t *)allocated)[1] == UINT32_C(0x1000));
    OF_prop_free(allocated);
    assert(ofw_bus_string_list_to_array(
        uart, "clock-output-names", &string_array) == 2);
    assert(string_array != 0);
    assert(bsd_strcmp(string_array[0], "card") == 0);
    assert(bsd_strcmp(string_array[1], "sample") == 0);
    assert(string_array[2] == 0);
    OF_prop_free(string_array);
    string_array = 0;
    assert(ofw_bus_string_list_to_array(
        uart, "missing", &string_array) == -1);
    assert(string_array == 0);

    assert(OF_nextprop(root, 0, buffer, sizeof(buffer)) == 1);
    assert(bsd_strcmp(buffer, "compatible") == 0);
    assert(OF_nextprop(root, "compatible", buffer, sizeof(buffer)) == 1);
    assert(bsd_strcmp(buffer, "#address-cells") == 0);
    assert(OF_nextprop(root, "#size-cells", buffer,
        sizeof(buffer)) == 1);
    assert(bsd_strcmp(buffer, "interrupt-parent") == 0);
    assert(OF_nextprop(root, "interrupt-parent", buffer,
        sizeof(buffer)) == 0);
    assert(OF_nextprop(root, "missing", buffer,
        sizeof(buffer)) == -1);
    assert(OF_setprop(root, "model", "immutable", 10) == -1);
    assert(!OF_hasprop(root, "model"));
}

static void
test_compatibility_and_xrefs(void)
{
    phandle_t root = OF_peer(0);
    phandle_t uart = OF_finddevice("/soc/serial@9000000");
    phandle_t disabled = OF_finddevice("/soc/disabled@a000000");
    device_t first = (device_t)(uintptr_t)UINT64_C(0x1000);
    device_t second = (device_t)(uintptr_t)UINT64_C(0x2000);

    assert(ofw_bus_is_machine_compatible("QEMU,VIRT"));
    assert(bsd_ofw_fdt_find_compatible("arm,gic-v3", 0) ==
        OF_finddevice("/interrupt-controller@8000000"));
    assert(bsd_ofw_fdt_find_compatible("arm,gic-v3", 1) == 0);
    assert(ofw_bus_node_is_compatible(uart, "ARM,PL011"));
    assert(!ofw_bus_node_is_compatible(uart, "edgeos,missing"));
    assert(ofw_bus_node_status_okay(uart));
    assert(!ofw_bus_node_status_okay(disabled));
    assert(ofw_bus_find_child(root, "soc") == OF_finddevice("/soc"));
    assert(ofw_bus_find_compatible(root, "arm,primecell") == uart);

    assert(OF_xref_from_node(uart) == 42);
    assert(OF_node_from_xref(42) == uart);
    assert(OF_device_register_xref(42, first) == 0);
    assert(OF_device_from_xref(42) == first);
    assert(OF_xref_from_device(first) == 42);
    assert(OF_device_register_xref(42, second) == 0);
    assert(OF_device_from_xref(42) == second);
    assert(OF_xref_from_device(first) == 0);
    OF_device_unregister_xref(42, second);
    assert(OF_device_from_xref(42) == 0);
}

static void
test_xref_lists(void)
{
    phandle_t uart = OF_finddevice("/soc/serial@9000000");
    phandle_t producer = 0;
    pcell_t *cells = 0;
    int count = -1;

    assert(ofw_bus_parse_xref_list_get_length(
        uart, "resets", "#reset-cells", &count) == 0);
    assert(count == 2);
    assert(ofw_bus_parse_xref_list_alloc(
        uart, "resets", "#reset-cells", 0,
        &producer, &count, &cells) == 0);
    assert(producer == 77);
    assert(count == 1);
    assert(cells != 0 && cells[0] == 5);
    OF_prop_free(cells);
    cells = 0;
    assert(ofw_bus_parse_xref_list_alloc(
        uart, "resets", "#reset-cells", 1,
        &producer, &count, &cells) == 0);
    assert(producer == 77);
    assert(count == 1);
    assert(cells != 0 && cells[0] == 9);
    OF_prop_free(cells);
    assert(ofw_bus_parse_xref_list_alloc(
        uart, "resets", "#reset-cells", 2,
        &producer, &count, &cells) == 2);
    assert(ofw_bus_parse_xref_list_get_length(
        uart, "missing", "#reset-cells", &count) == 2);
}

static void
test_interrupt_and_requester_maps(void)
{
    phandle_t soc = OF_finddevice("/soc");
    phandle_t uart = OF_finddevice("/soc/serial@9000000");
    struct ofw_bus_iinfo info = { 0 };
    pcell_t registers = UINT32_C(0x1000);
    pcell_t interrupt = 5;
    pcell_t mapped_interrupt[3] = { 0 };
    phandle_t parent = 0;
    uint32_t mapped_requester = 0;

    ofw_bus_setup_iinfo(soc, &info, sizeof(interrupt));
    assert(info.opi_addrc == sizeof(registers));
    assert(info.opi_imapsz == 6 * (int)sizeof(pcell_t));
    assert(info.opi_imap != 0);
    assert(info.opi_imapmsk != 0);
    assert(ofw_bus_lookup_imap((phandle_t)-1, &info, &registers,
        sizeof(registers), &interrupt, sizeof(interrupt),
        mapped_interrupt, sizeof(mapped_interrupt), &parent) == 3);
    assert(parent == 1);
    assert(mapped_interrupt[0] == 0);
    assert(mapped_interrupt[1] == 7);
    assert(mapped_interrupt[2] == 4);

    interrupt = 6;
    assert(ofw_bus_lookup_imap((phandle_t)-1, &info, &registers,
        sizeof(registers), &interrupt, sizeof(interrupt),
        mapped_interrupt, sizeof(mapped_interrupt), &parent) == 0);
    assert(ofw_bus_search_intrmap(&interrupt, sizeof(interrupt),
        &registers, sizeof(registers), info.opi_imap,
        info.opi_imapsz - 1, info.opi_imapmsk, mapped_interrupt,
        mapped_interrupt, sizeof(mapped_interrupt), &parent) == 0);
    ofw_bus_destroy_iinfo(&info);
    assert(info.opi_imap == 0);
    assert(info.opi_imapmsk == 0);
    assert(info.opi_imapsz == 0);

    assert(ofw_bus_msimap(soc, UINT16_C(0x10a), &parent,
        &mapped_requester) == 0);
    assert(parent == 77);
    assert(mapped_requester == UINT32_C(0x20a));
    assert(ofw_bus_msimap(soc, UINT16_C(0x140), &parent,
        &mapped_requester) == 2);
    assert(ofw_bus_iommu_map(soc, UINT16_C(0x305), &parent,
        &mapped_requester) == 0);
    assert(parent == 77);
    assert(mapped_requester == UINT32_C(0x405));
    assert(ofw_bus_iommu_map(uart, UINT16_C(0x55), &parent,
        &mapped_requester) == 2);
    assert(ofw_bus_msimap(uart, UINT16_C(0x55), &parent,
        &mapped_requester) == 0);
    assert(parent == 1);
    assert(mapped_requester == UINT32_C(0x55));
}

int
main(void)
{
    uint32_t total_size;
    unsigned char magic;

    build_test_tree();
    total_size = fdt_totalsize(g_blob);
    assert(total_size > sizeof(struct fdt_header));
    assert(bsd_ofw_fdt_install(g_blob, total_size - 1) == 22);
    magic = g_blob[0];
    g_blob[0] = 0;
    assert(bsd_ofw_fdt_install(g_blob, total_size) == 22);
    g_blob[0] = magic;

    assert(bsd_ofw_fdt_install(g_blob, total_size) == 0);
    assert(bsd_ofw_fdt_available());
    assert(bsd_ofw_fdt_size() == total_size);
    assert(bsd_ofw_fdt_node_count() == 8);
    assert(OF_install(OFW_FDT, 0));
    assert(OF_test(OFW_FDT) == 0);
    test_tree_navigation();
    test_properties();
    test_compatibility_and_xrefs();
    test_xref_lists();
    test_interrupt_and_requester_maps();
    bsd_ofw_fdt_reset();
    assert(!bsd_ofw_fdt_available());
    assert(OF_peer(0) == 0);
    return 0;
}
