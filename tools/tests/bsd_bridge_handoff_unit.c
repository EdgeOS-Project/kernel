/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for controlled BSD bridge device handoff. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "compat/freebsd/edgeos/bootstrap.h"
#include "compat/freebsd/edgeos/handoff.h"
#include "net/netdev.h"

static char g_root_object;
static char g_bus_object;
static char g_platform_objects[4];
static int g_unclaimed;
static int g_detach_count;
static int g_delete_count;
static int g_platform_attach_count;
static int g_platform_detach_count;
static int g_platform_fail_at = -1;
static int g_cam_scan_count;
static int g_cam_scan_error;
static int g_pci_prepare_count;
static int g_pci_activate_count;
static int g_pci_deactivate_count;
static int g_pci_restore_count;
static int g_pci_activate_error;
static edge_netdev_handle_t g_netdev_handles[2];
static size_t g_netdev_count;
static edge_netdev_handle_t g_lwip_handle;
static int g_attach_netdev;
static bsd_pci_bus_status_t g_bus_status;
static int g_bus_topo_depth;

void
bus_topo_lock(void)
{
    g_bus_topo_depth++;
}

void
bus_topo_unlock(void)
{
    assert(g_bus_topo_depth > 0);
    g_bus_topo_depth--;
}

int
edge_netdev_snapshot(edge_netdev_handle_t *handles, size_t capacity,
    size_t *count)
{
    if (!count || capacity < g_netdev_count)
        return 28;
    for (size_t index = 0; index < g_netdev_count; ++index)
        handles[index] = g_netdev_handles[index];
    *count = g_netdev_count;
    return 0;
}

int
lwip_stack_bind_netdev(edge_netdev_handle_t handle)
{
    if (!handle)
        return -1;
    g_lwip_handle = handle;
    return 0;
}

int
lwip_stack_unbind_netdev(edge_netdev_handle_t handle)
{
    if (!handle || g_lwip_handle != handle)
        return -1;
    g_lwip_handle = 0;
    return 0;
}

edge_netdev_handle_t
lwip_stack_get_netdev(void)
{
    return g_lwip_handle;
}

int
bsd_cam_scan_pending(void)
{
    g_cam_scan_count++;
    return g_cam_scan_error;
}

void
bsd_bridge_bootstrap_get_status(bsd_bridge_bootstrap_status_t *status)
{
    status->state = BSD_BRIDGE_BOOTSTRAP_READY;
    status->stage = BSD_BRIDGE_STAGE_COMPLETE;
    status->error = 0;
    status->flags = BSD_BRIDGE_BOOTSTRAP_DEFAULT_FLAGS;
    status->root = (device_t)(void *)&g_root_object;
    status->pci_bus = 0;
}

device_t
bsd_pci_attach_bus_selected(device_t parent,
    const bsd_pci_attach_options_t *options)
{
    static const bsd_pci_device_identity_t identities[] = {
        {
            .location = {
                .domain = 0,
                .bus = 0,
                .slot = 0x0d,
                .function = 0,
            },
            .vendor = 0x1af4,
            .device = 0x1043,
        },
        {
            .location = {
                .domain = 0,
                .bus = 0,
                .slot = 0x0e,
                .function = 0,
            },
            .vendor = 0x1af4,
            .device = 0x1044,
        },
    };

    assert(parent == (device_t)(void *)&g_root_object);
    assert(options != 0);
    assert(options->select_device != 0);
    g_bus_status.discovered =
        sizeof(identities) / sizeof(identities[0]);
    g_bus_status.selected = 0;
    for (size_t index = 0;
         index < sizeof(identities) / sizeof(identities[0]); ++index) {
        if (options->select_device(options->context,
            &identities[index]))
            g_bus_status.selected++;
    }
    g_bus_status.attached = g_unclaimed ? 0 : g_bus_status.selected;
    g_bus_status.unclaimed = g_unclaimed ?
        g_bus_status.selected : 0;
    if (g_attach_netdev && g_bus_status.attached != 0) {
        assert(g_netdev_count == 1);
        g_netdev_handles[g_netdev_count++] = 202;
    }
    return (device_t)(void *)&g_bus_object;
}

int
bsd_pci_bus_get_status(device_t bus, bsd_pci_bus_status_t *status)
{
    assert(bus == (device_t)(void *)&g_bus_object);
    *status = g_bus_status;
    return 0;
}

int
device_detach(device_t device)
{
    assert(device == (device_t)(void *)&g_bus_object);
    g_detach_count++;
    return 0;
}

int
device_delete_child(device_t parent, device_t child)
{
    assert(parent == (device_t)(void *)&g_root_object);
    assert(child == (device_t)(void *)&g_bus_object);
    if (g_attach_netdev && g_netdev_count == 2)
        g_netdev_count = 1;
    g_delete_count++;
    return 0;
}

static int
test_platform_attach(void *context, device_t parent,
    const bsd_bridge_platform_request_t *request,
    unsigned int unit, device_t *result)
{
    (void)context;
    assert(parent == (device_t)(void *)&g_root_object);
    assert(request->kind == BSD_BRIDGE_PLATFORM_VIRTIO_MMIO);
    assert(unit < sizeof(g_platform_objects));
    if (g_platform_attach_count++ == g_platform_fail_at)
        return 2;
    *result = (device_t)(void *)&g_platform_objects[unit];
    return 0;
}

static int
test_platform_detach(void *context, device_t parent, device_t device)
{
    (void)context;
    assert(parent == (device_t)(void *)&g_root_object);
    assert(device >= (device_t)(void *)&g_platform_objects[0]);
    assert(device <= (device_t)(void *)&g_platform_objects[3]);
    g_platform_detach_count++;
    return 0;
}

static int
test_pci_prepare(void *context, const bsd_pci_location_t *locations,
    size_t count)
{
    (void)context;
    assert(locations != 0);
    assert(count == 1);
    assert(locations[0].domain == 0);
    assert(locations[0].bus == 0);
    assert(locations[0].slot == 0x0d);
    assert(locations[0].function == 0);
    g_pci_prepare_count++;
    return 0;
}

static int
test_pci_activate(void *context)
{
    (void)context;
    g_pci_activate_count++;
    return g_pci_activate_error;
}

static int
test_pci_deactivate(void *context)
{
    (void)context;
    g_pci_deactivate_count++;
    return 0;
}

static int
test_pci_restore(void *context)
{
    (void)context;
    g_pci_restore_count++;
    return 0;
}

static void
assert_location(const bsd_pci_location_t *location,
    uint32_t domain, uint8_t bus, uint8_t slot, uint8_t function)
{
    assert(location->domain == domain);
    assert(location->bus == bus);
    assert(location->slot == slot);
    assert(location->function == function);
}

int
main(void)
{
    bsd_bridge_handoff_config_t config;
    bsd_bridge_handoff_status_t status;
    bsd_bridge_platform_handoff_ops_t platform_operations = {
        .attach = test_platform_attach,
        .detach = test_platform_detach,
    };
    bsd_bridge_pci_handoff_ops_t pci_operations = {
        .prepare = test_pci_prepare,
        .activate = test_pci_activate,
        .deactivate = test_pci_deactivate,
        .restore = test_pci_restore,
    };

    assert(bsd_bridge_handoff_parse_command_line(0, &config) == 0);
    assert(config.pci_location_count == 0);
    assert(config.platform_request_count == 0);
    assert(bsd_bridge_handoff_parse_command_line(
        "console=ttyS0 quiet", &config) == 0);
    assert(config.pci_location_count == 0);
    assert(bsd_bridge_handoff_parse_command_line(
        "bsd_bridge.pci=0000:00:0d.0 "
        "bsd_bridge.pci=2:ff:1f.7 "
        "bsd_bridge.pci=0000:00:0d.0", &config) == 0);
    assert(config.pci_location_count == 2);
    assert(config.platform_request_count == 0);
    assert_location(&config.pci_locations[0], 0, 0, 0x0d, 0);
    assert_location(&config.pci_locations[1], 2, 0xff, 0x1f, 7);
    assert(bsd_bridge_handoff_parse_command_line(
        "bsd_bridge.pci=0000:00:20.0", &config) == 22);
    assert(bsd_bridge_handoff_parse_command_line(
        "bsd_bridge.pci=0000:00:0d.8", &config) == 22);
    assert(bsd_bridge_handoff_parse_command_line(
        "bsd_bridge.pci=", &config) == 22);
    assert(bsd_bridge_handoff_parse_command_line(
        "bsd_bridge.platform=virtio-mmio:3:0 "
        "bsd_bridge.platform=virtio-mmio:10:2 "
        "bsd_bridge.platform=virtio-mmio:3:0", &config) == 0);
    assert(config.pci_location_count == 0);
    assert(config.platform_request_count == 2);
    assert(config.platform_requests[0].kind ==
        BSD_BRIDGE_PLATFORM_VIRTIO_MMIO);
    assert(config.platform_requests[0].device == 3);
    assert(config.platform_requests[0].instance == 0);
    assert(config.platform_requests[1].device == 0x10);
    assert(config.platform_requests[1].instance == 2);
    assert(bsd_bridge_handoff_parse_command_line(
        "bsd_bridge.platform=virtio-mmio:0:0", &config) == 22);
    assert(bsd_bridge_handoff_parse_command_line(
        "bsd_bridge.platform=virtio-mmio:3", &config) == 22);
    assert(bsd_bridge_handoff_parse_command_line(
        "bsd_bridge.platform=unknown:3:0", &config) == 22);

    assert(bsd_bridge_handoff_start_from_command_line(
        "quiet", &status) == 0);
    assert(status.enabled == 0);
    assert(bsd_bridge_handoff_start_from_command_line(
        "bsd_bridge.pci=0000:00:0d.0", &status) == 0);
    assert(status.enabled == 1);
    assert(status.pci_bus == (device_t)(void *)&g_bus_object);
    assert(status.pci.discovered == 2);
    assert(status.pci.selected == 1);
    assert(status.pci.attached == 1);
    assert(status.pci.unclaimed == 0);
    assert(g_cam_scan_count == 1);
    assert(bsd_bridge_handoff_start_from_command_line(
        "bsd_bridge.pci=0000:00:0e.0", &status) == 16);
    assert(bsd_bridge_handoff_stop() == 0);
    assert(g_detach_count == 1);
    assert(g_delete_count == 1);
    assert(bsd_bridge_handoff_stop() == 0);

    assert(bsd_bridge_handoff_start_from_command_line(
        "bsd_bridge.pci=0000:00:0f.0", &status) == 2);
    assert(status.enabled == 0);
    assert(g_detach_count == 2);
    assert(g_delete_count == 2);

    g_unclaimed = 1;
    assert(bsd_bridge_handoff_start_from_command_line(
        "bsd_bridge.pci=0000:00:0d.0", &status) == 2);
    assert(status.enabled == 0);
    assert(g_detach_count == 3);
    assert(g_delete_count == 3);

    assert(bsd_bridge_handoff_start_from_command_line(
        "bsd_bridge.platform=virtio-mmio:3:0", &status) == 22);
    g_platform_attach_count = 0;
    g_platform_fail_at = -1;
    assert(bsd_bridge_handoff_start_from_command_line_with_platform(
        "bsd_bridge.platform=virtio-mmio:3:0 "
        "bsd_bridge.platform=virtio-mmio:10:2",
        &platform_operations, &status) == 0);
    assert(status.enabled == 1);
    assert(status.pci_bus == 0);
    assert(status.platform_selected == 2);
    assert(status.platform_attached == 2);
    assert(g_platform_attach_count == 2);
    assert(g_cam_scan_count == 2);
    assert(bsd_bridge_handoff_stop() == 0);
    assert(g_platform_detach_count == 2);

    g_platform_attach_count = 0;
    g_platform_fail_at = 1;
    assert(bsd_bridge_handoff_start_from_command_line_with_platform(
        "bsd_bridge.platform=virtio-mmio:3:0 "
        "bsd_bridge.platform=virtio-mmio:10:2",
        &platform_operations, &status) == 2);
    assert(status.enabled == 0);
    assert(g_platform_attach_count == 2);
    assert(g_platform_detach_count == 3);
    assert(bsd_bridge_handoff_stop() == 0);

    g_platform_attach_count = 0;
    g_platform_fail_at = -1;
    g_cam_scan_error = 5;
    assert(bsd_bridge_handoff_start_from_command_line_with_platform(
        "bsd_bridge.platform=virtio-mmio:3:0",
        &platform_operations, &status) == 5);
    assert(status.enabled == 0);
    assert(g_platform_attach_count == 1);
    assert(g_platform_detach_count == 4);
    assert(g_cam_scan_count == 3);

    g_unclaimed = 0;
    g_cam_scan_error = 0;
    assert(bsd_bridge_handoff_parse_command_line(
        "bsd_bridge.pci=0000:00:0d.0", &config) == 0);
    assert(bsd_bridge_handoff_start_with_ops(
        &config, &pci_operations, 0, &status) == 0);
    assert(g_pci_prepare_count == 1);
    assert(g_pci_activate_count == 1);
    assert(g_pci_deactivate_count == 0);
    assert(g_pci_restore_count == 0);
    assert(bsd_bridge_handoff_stop() == 0);
    assert(g_pci_deactivate_count == 1);
    assert(g_pci_restore_count == 1);

    g_pci_activate_error = 5;
    assert(bsd_bridge_handoff_start_with_ops(
        &config, &pci_operations, 0, &status) == 5);
    assert(g_pci_prepare_count == 2);
    assert(g_pci_activate_count == 2);
    assert(g_pci_deactivate_count == 2);
    assert(g_pci_restore_count == 2);
    assert(bsd_bridge_handoff_stop() == 0);

    g_pci_activate_error = 0;
    g_cam_scan_error = 6;
    assert(bsd_bridge_handoff_start_with_ops(
        &config, &pci_operations, 0, &status) == 6);
    assert(g_pci_prepare_count == 3);
    assert(g_pci_activate_count == 3);
    assert(g_pci_deactivate_count == 3);
    assert(g_pci_restore_count == 3);
    assert(bsd_bridge_handoff_stop() == 0);

    g_cam_scan_error = 0;
    g_netdev_handles[0] = 101;
    g_netdev_count = 1;
    g_lwip_handle = 101;
    g_attach_netdev = 1;
    assert(bsd_bridge_handoff_start_from_command_line(
        "bsd_bridge.pci=0000:00:0d.0", &status) == 0);
    assert(g_netdev_count == 2);
    assert(g_lwip_handle == 202);
    assert(bsd_bridge_handoff_stop() == 0);
    assert(g_netdev_count == 1);
    assert(g_lwip_handle == 101);

    puts("bsd_bridge_handoff_unit: PASS");
    return 0;
}
