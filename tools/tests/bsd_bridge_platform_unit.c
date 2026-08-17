/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for shared BSD platform-device handoff and rollback. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/platform.h"
#include "compat/freebsd/edgeos/systm.h"
#ifdef BSD_BRIDGE_HOST_TEST
#include "compat/freebsd/contrib/dev/acpica/include/acpi.h"
ACPI_HANDLE acpi_get_handle(device_t device);
int acpi_MatchHid(ACPI_HANDLE handle, const char *hardware_id);
#else
#include "compat/freebsd/dev/acpica/acpivar.h"
#endif
#include "compat/freebsd/dev/ofw/ofw_bus.h"
#include "compat/freebsd/machine/resource.h"

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

typedef struct test_softc {
    int attached;
} test_softc_t;

static int g_fail_attach;
static int g_detach_count;
static bsd_firmware_kind_t g_expected_firmware;

static int
test_probe(device_t device)
{
    if (g_expected_firmware == BSD_FIRMWARE_ACPI) {
        ACPI_HANDLE handle = acpi_get_handle(device);

        assert(handle != 0);
        assert(acpi_MatchHid(handle, "EDGE0001"));
        assert(acpi_MatchHid(handle, "PNP0C50"));
        assert(!acpi_MatchHid(handle, "EDGE9999"));
        assert(!ofw_bus_status_okay(device));
    } else if (g_expected_firmware == BSD_FIRMWARE_FDT) {
        assert(acpi_get_handle(device) == 0);
        assert(ofw_bus_status_okay(device));
        assert(ofw_bus_is_compatible(device, "virtio,mmio"));
        assert(ofw_bus_is_compatible(device, "edgeos,test"));
        assert(!ofw_bus_is_compatible(device, "edgeos,missing"));
    }
    device_set_desc(device, "platform test device");
    return BUS_PROBE_DEFAULT;
}

static int
test_attach(device_t device)
{
    test_softc_t *softc = device_get_softc(device);
    struct resource *interrupt;
    rman_res_t start;
    rman_res_t count;
    int rid;

    assert(bus_get_resource(device, SYS_RES_MEMORY, 0,
        &start, &count) == 0);
    assert(start == 0x1000);
    assert(count == 0x200);
    assert(bus_get_resource(device, SYS_RES_IRQ, 0,
        &start, &count) == 0);
    assert(start == 44);
    assert(count == 1);
    rid = 0;
    interrupt = bus_alloc_resource(device, SYS_RES_IRQ, rid,
        0, UINT64_MAX, 1, RF_ACTIVE);
    assert(interrupt != 0);
    assert(bsd_resource_get_interrupt_flags(interrupt) == 4);
    assert(bus_release_resource(device, interrupt) == 0);
    if (g_fail_attach)
        return 6;
    softc->attached = 1;
    return 0;
}

static int
test_detach(device_t device)
{
    test_softc_t *softc = device_get_softc(device);

    assert(softc->attached == 1);
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
    "platform-test", test_methods, sizeof(test_softc_t), 0, 0, 0
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
    (void)size;
    (void)flags;
    (void)context;
    *handle = (uintptr_t)address;
    return 0;
}

static void
test_unmap(void *context, bus_space_handle_t handle, bus_size_t size)
{
    (void)handle;
    (void)size;
    (void)context;
}

static uint64_t
test_read(void *context, bus_space_handle_t handle, bus_size_t offset,
    unsigned int width)
{
    (void)context;
    (void)width;
    return handle + offset;
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
    bsd_platform_resource_t resources[] = {
        {
            .type = SYS_RES_MEMORY,
            .rid = 0,
            .start = 0x1000,
            .count = 0x200,
        },
        {
            .type = SYS_RES_IRQ,
            .rid = 0,
            .start = 44,
            .count = 1,
            .interrupt_flags = 4,
        },
    };
    bsd_platform_device_t description = {
        .name = "platform-test",
        .unit = 3,
        .driver = &test_driver,
        .resources = resources,
        .resource_count = sizeof(resources) / sizeof(resources[0]),
    };
    const char *fdt_compatible[] = {
        "virtio,mmio",
        "edgeos,test",
    };
    const char *acpi_compatible[] = {
        "PNP0C50",
    };
    bsd_firmware_description_t acpi_firmware = {
        .kind = BSD_FIRMWARE_ACPI,
        .enabled = 1,
        .hardware_id = "EDGE0001",
        .compatible = acpi_compatible,
        .compatible_count =
            sizeof(acpi_compatible) / sizeof(acpi_compatible[0]),
    };
    bsd_firmware_description_t fdt_firmware = {
        .kind = BSD_FIRMWARE_FDT,
        .enabled = 1,
        .compatible = fdt_compatible,
        .compatible_count =
            sizeof(fdt_compatible) / sizeof(fdt_compatible[0]),
    };
    device_t root;
    device_t platform_bus;
    device_t child = 0;

    assert(bsd_allocator_initialize(&allocator_ops) == 0);
    assert(bsd_bus_space_initialize(&bus_space_ops, 0) == 0);
    root = bsd_newbus_create_root("nexus", 0, 0);
    assert(root != 0);

    description.firmware = &acpi_firmware;
    g_expected_firmware = BSD_FIRMWARE_ACPI;
    assert(bsd_platform_register_device(root, &description, &child) == 0);
    assert(child != 0);
    assert(!device_is_attached(child));
    assert(bsd_firmware_is_bound(child));
    assert(bus_get_resource_start(child, SYS_RES_MEMORY, 0) == 0x1000);
    assert(bsd_platform_remove_device(root, child) == 0);
    assert(g_detach_count == 0);
    child = 0;

    g_fail_attach = 1;
    assert(bsd_platform_add_device(root, &description, &child) == 6);
    assert(child == 0);
    assert(device_find_child(root, "platform-test", 3) == 0);

    g_fail_attach = 0;
    assert(bsd_platform_add_device(root, &description, &child) == 0);
    assert(child != 0);
    assert(device_is_attached(child));
    assert(device_find_child(root, "platform-test", 3) == child);
    assert(bsd_platform_remove_device(root, child) == 0);
    assert(g_detach_count == 1);
    assert(device_find_child(root, "platform-test", 3) == 0);

    assert(bsd_platform_add_bus(root, "simplebus", 0,
        &platform_bus) == 0);
    assert(device_get_state(platform_bus) == DS_NOTPRESENT);
    description.unit = 4;
    description.firmware = &fdt_firmware;
    g_expected_firmware = BSD_FIRMWARE_FDT;
    assert(bsd_platform_add_device(platform_bus, &description,
        &child) == 0);
    assert(child != 0);
    assert(device_get_parent(child) == platform_bus);
    assert(bsd_platform_remove_device(platform_bus, child) == 0);
    assert(g_detach_count == 2);
    assert(bsd_platform_remove_device(root, platform_bus) == 0);

    resources[0].count = 0;
    assert(bsd_platform_add_device(root, &description, &child) == 22);
    assert(child == 0);
    resources[0].count = 0x200;
    fdt_firmware.enabled = 2;
    assert(bsd_platform_add_device(root, &description, &child) == 22);
    assert(child == 0);
    return 0;
}
