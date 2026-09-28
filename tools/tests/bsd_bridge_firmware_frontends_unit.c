/* SPDX-License-Identifier: MPL-2.0 */
/* Integration tests for unmodified FreeBSD ACPI and FDT frontends. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/edgeos/firmware.h"
#include "compat/freebsd/edgeos/linker.h"
#include "compat/freebsd/edgeos/module.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/virtio_mmio.h"
#include "compat/freebsd/machine/resource.h"
#include "compat/freebsd/sys/module.h"

#include <sys/firmware.h>
#include <dev/virtio/mmio/virtio_mmio.h>

#define TEST_ARENA_SIZE (8U * 1024U * 1024U)
#define TEST_PAGE_SIZE 4096U
#define TEST_ASSERT(condition) \
    test_assert((condition), __LINE__)

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
struct kobjop_desc device_identify_desc = {
    0, { &device_identify_desc, (kobjop_t)kobj_error_method }
};

static int vtmmio_test_attach(device_t device);
static int vtmmio_test_detach(device_t device);

static const kobj_method_t vtmmio_base_methods[] = {
    { &device_attach_desc, (kobjop_t)vtmmio_test_attach },
    { &device_detach_desc, (kobjop_t)vtmmio_test_detach },
    KOBJMETHOD_END,
};

driver_t vtmmio_driver = {
    "virtio_mmio",
    vtmmio_base_methods,
    sizeof(struct vtmmio_softc),
    0,
    0,
    0,
};

static int g_transport_probe_count;
static int g_transport_attach_count;
static int g_transport_detach_count;
static _Alignas(TEST_PAGE_SIZE) uint8_t g_test_arena[TEST_ARENA_SIZE];
static size_t g_test_arena_offset;

int
kernel_boot_option_get(const char *name, char *value, size_t capacity)
{
    (void)name;
    (void)value;
    (void)capacity;
    return 0;
}

void
bsd_linker_release_image(bsd_linker_image_t *image)
{
    (void)image;
}

int
bsd_linker_image_records(const bsd_linker_image_t *image,
    bsd_linker_record_set_t *records)
{
    (void)image;
    (void)records;
    return BSD_LINKER_ERR_INVALID;
}

const void *
bsd_linker_image_base(const bsd_linker_image_t *image)
{
    return image;
}

static void
test_assert(int condition, int line)
{
    if (!condition) {
        dprintf(2, "firmware frontend assertion failed at line %d\n", line);
        __builtin_trap();
    }
}

int
vtmmio_probe(device_t device)
{
    g_transport_probe_count++;
    device_set_desc(device, "mock VirtIO MMIO transport");
    return BUS_PROBE_DEFAULT;
}

static int
vtmmio_test_attach(device_t device)
{
    rman_res_t start;
    rman_res_t count;

    TEST_ASSERT(bus_get_resource(device, SYS_RES_MEMORY, 0,
        &start, &count) == 0);
    TEST_ASSERT(start == UINT64_C(0x10001000));
    TEST_ASSERT(count == UINT64_C(0x1000));
    TEST_ASSERT(bus_get_resource(device, SYS_RES_IRQ, 0,
        &start, &count) == 0);
    TEST_ASSERT(start == 37);
    TEST_ASSERT(count == 1);
    g_transport_attach_count++;
    return 0;
}

static int
vtmmio_test_detach(device_t device)
{
    (void)device;
    g_transport_detach_count++;
    return 0;
}

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    size_t size;
    void *memory;

    (void)context;
    if (page_count > SIZE_MAX / TEST_PAGE_SIZE)
        return 0;
    size = (size_t)page_count * TEST_PAGE_SIZE;
    if (size > sizeof(g_test_arena) - g_test_arena_offset)
        return 0;
    memory = &g_test_arena[g_test_arena_offset];
    g_test_arena_offset += size;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)base;
    (void)page_count;
    (void)context;
}

static int
test_bus_space_map(void *context, bus_addr_t address, bus_size_t size,
    int flags, bus_space_handle_t *handle)
{
    (void)context;
    (void)size;
    (void)flags;
    *handle = (bus_space_handle_t)address;
    return 0;
}

static void
test_bus_space_unmap(void *context, bus_space_handle_t handle,
    bus_size_t size)
{
    (void)context;
    (void)handle;
    (void)size;
}

static uint64_t
test_bus_space_read(void *context, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width)
{
    (void)context;
    (void)width;
    return (uint64_t)handle + offset;
}

static void
test_bus_space_write(void *context, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t value)
{
    (void)context;
    (void)handle;
    (void)offset;
    (void)width;
    (void)value;
}

static device_t
add_firmware_child(device_t bus, int unit,
    const bsd_firmware_description_t *firmware)
{
    device_t child = device_add_child(bus, "virtio_mmio", unit);

    TEST_ASSERT(child != 0);
    TEST_ASSERT(bsd_firmware_bind(child, firmware) == 0);
    return child;
}

int
main(void)
{
    bsd_allocator_ops_t allocator_ops = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    bsd_bus_space_ops_t bus_space_ops = {
        .map = test_bus_space_map,
        .unmap = test_bus_space_unmap,
        .read = test_bus_space_read,
        .write = test_bus_space_write,
    };
    const char *valid_compatible[] = {
        "virtio,mmio",
        "edgeos,integration-test",
    };
    const char *invalid_compatible[] = {
        "edgeos,other-device",
    };
    bsd_firmware_description_t fdt = {
        .kind = BSD_FIRMWARE_FDT,
        .enabled = 1,
        .compatible = valid_compatible,
        .compatible_count =
            sizeof(valid_compatible) / sizeof(valid_compatible[0]),
    };
    bsd_firmware_description_t acpi = {
        .kind = BSD_FIRMWARE_ACPI,
        .enabled = 1,
        .hardware_id = "LNRO0005",
    };
    bsd_firmware_description_t acpi_namespace_object = {
        .kind = BSD_FIRMWARE_ACPI,
        .enabled = 1,
        .acpi_handle = (void *)(uintptr_t)0x1234,
    };
    bsd_virtio_mmio_description_t mmio = {
        .base = UINT64_C(0x10001000),
        .size = UINT64_C(0x1000),
        .interrupt = 37,
        .interrupt_flags = 4,
        .unit = 7,
    };
    device_t root;
    device_t simplebus;
    device_t ofwbus;
    device_t acpi_bus;
    device_t child;
    devclass_t simplebus_class;
    int simplebus_count;
    int error;
    static const uint8_t firmware_data[] = { 1, 2, 3, 4 };
    const struct firmware *registered_firmware;
    const struct firmware *firmware_reference;
    const struct firmware *parent_firmware;
    const struct firmware *child_firmware;

    TEST_ASSERT(bsd_allocator_initialize(&allocator_ops) == 0);
    registered_firmware = firmware_register(
        "edgeos-test-fw", firmware_data, sizeof(firmware_data), 7, 0);
    TEST_ASSERT(registered_firmware != 0);
    TEST_ASSERT(firmware_register(
        "edgeos-test-fw", firmware_data, sizeof(firmware_data), 7, 0) == 0);
    firmware_reference = firmware_get("edgeos-test-fw");
    TEST_ASSERT(firmware_reference == registered_firmware);
    TEST_ASSERT(firmware_reference->datasize == sizeof(firmware_data));
    TEST_ASSERT(firmware_reference->version == 7);
    TEST_ASSERT(firmware_unregister("edgeos-test-fw") == 16);
    firmware_put(firmware_reference, FIRMWARE_UNLOAD);
    TEST_ASSERT(firmware_unregister("edgeos-test-fw") == 0);
    TEST_ASSERT(firmware_get_flags(
        "edgeos-test-fw", FIRMWARE_GET_NOWARN) == 0);
    TEST_ASSERT(bsd_firmware_file_alias_register(
        "edgeos-test-fw", "edgeos-test-fw.bin") == 0);
    TEST_ASSERT(bsd_firmware_file_alias_register(
        "edgeos-test-fw", "edgeos-test-fw.bin") == 0);
    parent_firmware = firmware_register(
        "edgeos-test-parent-fw", firmware_data, sizeof(firmware_data), 1, 0);
    TEST_ASSERT(parent_firmware != 0);
    child_firmware = firmware_register(
        "edgeos-test-child-fw", firmware_data, sizeof(firmware_data), 2,
        parent_firmware);
    TEST_ASSERT(child_firmware != 0);
    TEST_ASSERT(firmware_get("edgeos-test-child-fw") == child_firmware);
    TEST_ASSERT(firmware_unregister("edgeos-test-child-fw") == 16);
    TEST_ASSERT(firmware_unregister("edgeos-test-parent-fw") == 16);
    firmware_put(child_firmware, FIRMWARE_UNLOAD);
    TEST_ASSERT(firmware_unregister("edgeos-test-child-fw") == 0);
    TEST_ASSERT(firmware_unregister("edgeos-test-parent-fw") == 0);
    TEST_ASSERT(bsd_bus_space_initialize(&bus_space_ops, 0) == 0);
    TEST_ASSERT(bsd_module_provide("acpi", 1) == 0);
    TEST_ASSERT(bsd_module_provide("simplebus", 1) == 0);
    TEST_ASSERT(bsd_module_provide("ofwbus", 1) == 0);
    TEST_ASSERT(bsd_module_provide("virtio", 1) == 0);
    TEST_ASSERT(bsd_module_validate_dependencies() == 0);
    TEST_ASSERT(bsd_sysinit_run_all() == 0);

    root = bsd_newbus_create_root("nexus", 0, 0);
    TEST_ASSERT(root != 0);
    simplebus = device_add_child(root, "simplebus", 0);
    ofwbus = device_add_child(root, "ofwbus", 0);
    acpi_bus = device_add_child(root, "acpi", 0);
    TEST_ASSERT(simplebus != 0);
    TEST_ASSERT(ofwbus != 0);
    TEST_ASSERT(acpi_bus != 0);
    simplebus_class = devclass_find("simplebus");
    TEST_ASSERT(simplebus_class != 0);

    child = add_firmware_child(simplebus, 0, &fdt);
    TEST_ASSERT(device_probe(child) == 0);
    TEST_ASSERT(g_transport_probe_count == 2);
    TEST_ASSERT(device_delete_child(simplebus, child) == 0);

    child = add_firmware_child(ofwbus, 0, &fdt);
    TEST_ASSERT(device_probe(child) == 0);
    TEST_ASSERT(g_transport_probe_count == 4);
    TEST_ASSERT(device_delete_child(ofwbus, child) == 0);

    fdt.enabled = 0;
    child = add_firmware_child(simplebus, 1, &fdt);
    TEST_ASSERT(device_probe(child) == 6);
    TEST_ASSERT(g_transport_probe_count == 4);
    TEST_ASSERT(device_delete_child(simplebus, child) == 0);

    fdt.enabled = 1;
    fdt.compatible = invalid_compatible;
    fdt.compatible_count =
        sizeof(invalid_compatible) / sizeof(invalid_compatible[0]);
    child = add_firmware_child(simplebus, 2, &fdt);
    TEST_ASSERT(device_probe(child) == 6);
    TEST_ASSERT(g_transport_probe_count == 4);
    TEST_ASSERT(device_delete_child(simplebus, child) == 0);

    child = add_firmware_child(acpi_bus, 0, &acpi);
    TEST_ASSERT(bsd_firmware_acpi_get_private(child) == 0);
    TEST_ASSERT(bsd_firmware_acpi_match(child, "lnro0005") == 1);
    TEST_ASSERT(bsd_firmware_acpi_set_private(
        child, &g_transport_probe_count) == 0);
    TEST_ASSERT(bsd_firmware_acpi_get_private(child) ==
        &g_transport_probe_count);
    TEST_ASSERT(device_probe(child) == 0);
    TEST_ASSERT(g_transport_probe_count == 6);
    TEST_ASSERT(device_delete_child(acpi_bus, child) == 0);

    acpi.hardware_id = "EDGE0001";
    child = add_firmware_child(acpi_bus, 1, &acpi);
    TEST_ASSERT(device_probe(child) == 6);
    TEST_ASSERT(g_transport_probe_count == 6);
    TEST_ASSERT(device_delete_child(acpi_bus, child) == 0);

    child = add_firmware_child(acpi_bus, 2, &acpi_namespace_object);
    TEST_ASSERT(bsd_firmware_acpi_handle(child) ==
        acpi_namespace_object.acpi_handle);
    TEST_ASSERT(g_transport_probe_count == 6);
    TEST_ASSERT(device_delete_child(acpi_bus, child) == 0);

    child = 0;
    simplebus_count = devclass_get_count(simplebus_class);
    error = bsd_virtio_mmio_attach(root, &mmio, &child);
    if (error)
        dprintf(2, "firmware frontend attach failed: %d\n", error);
    TEST_ASSERT(error == 0);
    TEST_ASSERT(child != 0);
    TEST_ASSERT(device_is_attached(child));
    TEST_ASSERT(g_transport_probe_count == 8);
    TEST_ASSERT(g_transport_attach_count == 1);
    TEST_ASSERT(device_get_parent(child) != root);
    TEST_ASSERT(device_get_parent(device_get_parent(child)) == root);
    TEST_ASSERT(devclass_get_count(simplebus_class) ==
        simplebus_count + 1);
    TEST_ASSERT(bsd_virtio_mmio_detach(root, child) == 0);
    TEST_ASSERT(g_transport_detach_count == 1);
    TEST_ASSERT(devclass_get_count(simplebus_class) == simplebus_count);

    TEST_ASSERT(device_delete_child(root, simplebus) == 0);
    TEST_ASSERT(device_delete_child(root, ofwbus) == 0);
    TEST_ASSERT(device_delete_child(root, acpi_bus) == 0);
    TEST_ASSERT(bsd_sysuninit_run_all() == 0);
    return 0;
}
