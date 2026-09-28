/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for non-attaching Device Tree inventory and explicit claims. */

#include <libfdt.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/edgeos/fdt_inventory.h"
#include "compat/freebsd/edgeos/firmware.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/resource.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/dev/ofw/ofw_bus.h"
#include "compat/freebsd/machine/resource.h"

#define TEST_BLOB_SIZE 4096

struct kobjop_desc device_probe_desc = {
    0, { &device_probe_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_attach_desc = {
    0, { &device_attach_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_detach_desc = {
    0, { &device_detach_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_shutdown_desc = {
    0, { &device_shutdown_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_suspend_desc = {
    0, { &device_suspend_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_resume_desc = {
    0, { &device_resume_desc, (kobjop_t)kobj_error_method }
};

static unsigned char g_blob[TEST_BLOB_SIZE];
static int g_attach_count;
static int g_detach_count;

static int
test_probe(device_t device)
{
    assert(ofw_bus_status_okay(device));
    assert(ofw_bus_is_compatible(device, "arm,pl011"));
    return BUS_PROBE_DEFAULT;
}

static int
test_attach(device_t device)
{
    rman_res_t start;
    rman_res_t count;

    assert(bus_get_resource(device, SYS_RES_MEMORY, 0,
        &start, &count) == 0);
    assert(start == UINT64_C(0x09000000));
    assert(count == UINT64_C(0x1000));
    assert(bus_get_resource(device, SYS_RES_IRQ, 0,
        &start, &count) == 0);
    assert(start == 33);
    assert(count == 1);
    ++g_attach_count;
    return 0;
}

static int
test_detach(device_t device)
{
    (void)device;
    ++g_detach_count;
    return 0;
}

static const struct kobj_method test_methods[] = {
    { &device_probe_desc, (kobjop_t)test_probe },
    { &device_attach_desc, (kobjop_t)test_attach },
    { &device_detach_desc, (kobjop_t)test_detach },
    KOBJMETHOD_END,
};

static struct kobj_class test_driver = {
    "fdt-test", test_methods, 0, 0, 0, 0
};

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U,
        (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static int
test_map(void *context, bus_addr_t address, bus_size_t size, int flags,
    bus_space_handle_t *handle)
{
    (void)context;
    (void)size;
    (void)flags;
    *handle = (bus_space_handle_t)address;
    return 0;
}

static void
test_unmap(void *context, bus_space_handle_t handle, bus_size_t size)
{
    (void)context;
    (void)handle;
    (void)size;
}

static uint64_t
test_read(void *context, bus_space_handle_t handle, bus_size_t offset,
    unsigned int width)
{
    (void)context;
    (void)width;
    return (uint64_t)handle + offset;
}

static void
test_write(void *context, bus_space_handle_t handle, bus_size_t offset,
    unsigned int width, uint64_t value)
{
    (void)context;
    (void)handle;
    (void)offset;
    (void)width;
    (void)value;
}

static void
build_test_tree(void)
{
    static const char uart_compatible[] =
        "arm,pl011\0arm,primecell";
    fdt32_t uart_registers[] = {
        cpu_to_fdt32(0),
        cpu_to_fdt32(UINT32_C(0x1000)),
    };
    fdt32_t virtio_registers[] = {
        cpu_to_fdt32(0),
        cpu_to_fdt32(UINT32_C(0x0a000000)),
        cpu_to_fdt32(0),
        cpu_to_fdt32(UINT32_C(0x200)),
    };
    fdt32_t ranges[] = {
        cpu_to_fdt32(0),
        cpu_to_fdt32(0),
        cpu_to_fdt32(UINT32_C(0x09000000)),
        cpu_to_fdt32(UINT32_C(0x00100000)),
    };
    fdt32_t uart_interrupt[] = {
        cpu_to_fdt32(0),
        cpu_to_fdt32(1),
        cpu_to_fdt32(4),
    };
    fdt32_t virtio_interrupt[] = {
        cpu_to_fdt32(0),
        cpu_to_fdt32(16),
        cpu_to_fdt32(1),
    };

    assert(fdt_create(g_blob, sizeof(g_blob)) == 0);
    assert(fdt_finish_reservemap(g_blob) == 0);
    assert(fdt_begin_node(g_blob, "") == 0);
    assert(fdt_property_string(g_blob, "compatible", "qemu,virt") == 0);
    assert(fdt_property_u32(g_blob, "#address-cells", 2) == 0);
    assert(fdt_property_u32(g_blob, "#size-cells", 2) == 0);
    assert(fdt_property_u32(g_blob, "interrupt-parent", 1) == 0);

    assert(fdt_begin_node(g_blob, "soc") == 0);
    assert(fdt_property_string(g_blob, "compatible", "simple-bus") == 0);
    assert(fdt_property_u32(g_blob, "#address-cells", 1) == 0);
    assert(fdt_property_u32(g_blob, "#size-cells", 1) == 0);
    assert(fdt_property(g_blob, "ranges", ranges, sizeof(ranges)) == 0);

    assert(fdt_begin_node(g_blob, "serial@0") == 0);
    assert(fdt_property(g_blob, "compatible", uart_compatible,
        sizeof(uart_compatible)) == 0);
    assert(fdt_property_string(g_blob, "status", "okay") == 0);
    assert(fdt_property(g_blob, "reg", uart_registers,
        sizeof(uart_registers)) == 0);
    assert(fdt_property(g_blob, "interrupts", uart_interrupt,
        sizeof(uart_interrupt)) == 0);
    assert(fdt_end_node(g_blob) == 0);

    assert(fdt_begin_node(g_blob, "disabled@1000") == 0);
    assert(fdt_property_string(g_blob, "compatible",
        "edgeos,disabled") == 0);
    assert(fdt_property_string(g_blob, "status", "disabled") == 0);
    assert(fdt_end_node(g_blob) == 0);
    assert(fdt_end_node(g_blob) == 0);

    assert(fdt_begin_node(g_blob, "virtio_mmio@a000000") == 0);
    assert(fdt_property_string(g_blob, "compatible", "virtio,mmio") == 0);
    assert(fdt_property(g_blob, "reg", virtio_registers,
        sizeof(virtio_registers)) == 0);
    assert(fdt_property(g_blob, "interrupts", virtio_interrupt,
        sizeof(virtio_interrupt)) == 0);
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

int
main(void)
{
    bsd_allocator_ops_t allocator_ops = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    bsd_bus_space_ops_t bus_space_ops = {
        .map = test_map,
        .unmap = test_unmap,
        .read = test_read,
        .write = test_write,
    };
    bsd_fdt_inventory_status_t status;
    phandle_t root_node;
    phandle_t soc_node;
    phandle_t uart_node;
    phandle_t disabled_node;
    phandle_t virtio_node;
    device_t root;
    device_t ofwbus;
    device_t soc;
    device_t uart;
    device_t claimed = 0;
    rman_res_t start;
    rman_res_t count;
    size_t resource_count;
    uint64_t decoded_address;
    uint64_t decoded_size;
    uint32_t decoded_interrupt;
    uint32_t decoded_flags;
    int error;

    build_test_tree();
    assert(bsd_allocator_initialize(&allocator_ops) == 0);
    assert(bsd_bus_space_initialize(&bus_space_ops, 0) == 0);
    assert(bsd_ofw_fdt_install(g_blob, fdt_totalsize(g_blob)) == 0);
    uart_node = OF_finddevice("/soc/serial@0");
    assert(bsd_ofw_fdt_get_reg_count(uart_node, &resource_count) == 0);
    assert(resource_count == 1);
    assert(bsd_ofw_fdt_get_reg(uart_node, 0,
        &decoded_address, &decoded_size) == 0);
    assert(decoded_address == UINT64_C(0x09000000));
    assert(decoded_size == UINT64_C(0x1000));
    assert(bsd_ofw_fdt_get_interrupt_count(
        uart_node, &resource_count) == 0);
    assert(resource_count == 1);
    assert(bsd_ofw_fdt_get_interrupt(uart_node, 0,
        &decoded_interrupt, &decoded_flags) == 0);
    assert(decoded_interrupt == 33);
    assert(decoded_flags == 4);
    root = bsd_newbus_create_root("nexus", 0, 0);
    assert(root != 0);
    error = bsd_fdt_inventory_register(root, &status);
    if (error != 0)
        fprintf(stderr, "inventory registration failed: %d\n", error);
    assert(error == 0);
    assert(status.bus != 0);
    assert(status.nodes_seen == 6);
    assert(status.devices_registered == 5);
    assert(status.buses_registered == 2);
    assert(status.disabled_nodes == 1);
    assert(status.unsupported_nodes == 0);
    assert(status.memory_resources == 2);
    assert(status.interrupt_resources == 2);
    assert(status.unresolved_resources == 0);

    root_node = OF_peer(0);
    soc_node = OF_finddevice("/soc");
    disabled_node = OF_finddevice("/soc/disabled@1000");
    virtio_node = OF_finddevice("/virtio_mmio@a000000");
    ofwbus = bsd_fdt_inventory_find(root_node);
    soc = bsd_fdt_inventory_find(soc_node);
    uart = bsd_fdt_inventory_find(uart_node);
    assert(ofwbus == status.bus);
    assert(soc != 0 && device_get_parent(soc) == ofwbus);
    assert(device_get_name(soc) != 0);
    assert(bsd_strcmp(device_get_name(soc), "simplebus") == 0);
    assert(uart != 0 && device_get_parent(uart) == soc);
    assert(!device_is_attached(uart));
    assert(ofw_bus_get_node(uart) == uart_node);
    assert(ofw_bus_is_compatible(uart, "arm,primecell"));
    assert(bus_get_resource(uart, SYS_RES_MEMORY, 0,
        &start, &count) == 0);
    assert(start == UINT64_C(0x09000000));
    assert(count == UINT64_C(0x1000));
    assert(bus_get_resource(bsd_fdt_inventory_find(virtio_node),
        SYS_RES_MEMORY, 0, &start, &count) == 0);
    assert(start == UINT64_C(0x0a000000));
    assert(count == UINT64_C(0x200));

    assert(devclass_add_driver(devclass_find("simplebus"),
        &test_driver, 0, 0) == 0);
    assert(bsd_fdt_inventory_claim(uart_node, 0, &claimed) == 0);
    assert(claimed == uart);
    assert(device_is_attached(uart));
    assert(g_attach_count == 1);
    assert(bsd_fdt_inventory_claim(uart_node, 0, &claimed) == 16);
    assert(bsd_fdt_inventory_release(uart_node) == 0);
    assert(!device_is_attached(uart));
    assert(g_detach_count == 1);
    assert(bsd_fdt_inventory_claim(disabled_node,
        &test_driver, &claimed) == 6);
    assert(bsd_fdt_inventory_claim(soc_node,
        &test_driver, &claimed) == 16);

    assert(bsd_fdt_inventory_unregister(root) == 0);
    assert(device_find_child(root, "ofwbus", DEVICE_UNIT_ANY) == 0);
    assert(OF_device_from_xref(OF_xref_from_node(root_node)) == 0);
    assert(bsd_fdt_inventory_find(uart_node) == 0);
    bsd_fdt_inventory_get_status(&status);
    assert(status.bus == 0);
    bsd_ofw_fdt_reset();
    return 0;
}
