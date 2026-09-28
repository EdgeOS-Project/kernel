/* SPDX-License-Identifier: MPL-2.0 */
/* Transaction tests for x86-64 BSD PCI network handoff. */

#include "compat/freebsd/edgeos/x86_64_handoff.h"
#include "drivers/e1000.h"
#include "drivers/usb_handoff.h"
#include "net/lwip_stack.h"
#include "net/native_netdev.h"
#include "net/netdev.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static bsd_bridge_pci_handoff_ops_t g_operations;
static edge_netdev_handle_t g_lwip_handle;
static edge_netdev_handle_t g_bsd_handle;
static e1000_rx_frame_cb_t g_native_receive;
static uint8_t g_selected_slot = 5;
static int g_native_ready = 1;
static int g_register_bsd_netdev = 1;
static int g_stop_error;
static int g_fail_next_bind;
static int g_stop_count;
static int g_resume_count;
static int g_usb_reserved;
static int g_usb_prepare_error;
static int g_usb_prepare_count;
static int g_usb_restore_count;
static int g_usb_release_count;

static int
usb_location_selected(const usb_handoff_location_t *locations,
    uint32_t count)
{
    for (uint32_t index = 0; index < count; ++index) {
        if (locations[index].domain == 0 &&
            locations[index].bus == 0 &&
            locations[index].slot == 6 &&
            locations[index].function == 0)
            return 1;
    }
    return 0;
}

int
usb_handoff_reserve_locations(
    const usb_handoff_location_t *locations, uint32_t count)
{
    g_usb_reserved = usb_location_selected(locations, count);
    return 0;
}

int
usb_handoff_prepare_locations(
    const usb_handoff_location_t *locations, uint32_t count,
    usb_handoff_state_t *state)
{
    if (!usb_location_selected(locations, count))
        return 0;
    g_usb_prepare_count++;
    if (g_usb_prepare_error)
        return g_usb_prepare_error;
    state->controller_mask = 1u;
    g_usb_reserved = 1;
    return 0;
}

int
usb_handoff_restore(usb_handoff_state_t *state)
{
    if (state->controller_mask != 0) {
        g_usb_restore_count++;
        state->controller_mask = 0;
        g_usb_reserved = 0;
    }
    return 0;
}

int
usb_handoff_release_reservations(void)
{
    g_usb_release_count++;
    g_usb_reserved = 0;
    return 0;
}

static int
test_transmit(void *context, const void *frame, uint32_t length)
{
    (void)context;
    (void)frame;
    return (int)length;
}

static void
register_bsd_netdev(void)
{
    edge_netdev_config_t config = {0};

    config.name = "vtnet0";
    config.mac[0] = 0x52;
    config.mac[1] = 0x54;
    config.mac[2] = 0;
    config.mac[3] = 0x12;
    config.mac[4] = 0x34;
    config.mac[5] = 0x56;
    config.mtu = 1500;
    config.link_up = 1;
    config.ops.transmit = test_transmit;
    assert(edge_netdev_register(&config, &g_bsd_handle) == 0);
}

static void
unregister_bsd_netdev(void)
{
    if (!g_bsd_handle)
        return;
    assert(edge_netdev_set_up(g_bsd_handle, 0) == 0);
    assert(edge_netdev_unregister(g_bsd_handle) == 0);
    g_bsd_handle = 0;
}

int
bsd_bridge_handoff_parse_command_line(const char *command_line,
    bsd_bridge_handoff_config_t *config)
{
    assert(command_line != 0);
    assert(config != 0);
    memset(config, 0, sizeof(*config));
    config->pci_location_count = 1;
    config->pci_locations[0].domain = 0;
    config->pci_locations[0].bus = 0;
    config->pci_locations[0].slot = g_selected_slot;
    config->pci_locations[0].function = 0;
    return 0;
}

int
bsd_bridge_handoff_start_with_ops(
    const bsd_bridge_handoff_config_t *config,
    const bsd_bridge_pci_handoff_ops_t *pci_ops,
    const bsd_bridge_platform_handoff_ops_t *platform_ops,
    bsd_bridge_handoff_status_t *status)
{
    int error;

    assert(config != 0);
    assert(pci_ops != 0);
    assert(platform_ops == 0);
    g_operations = *pci_ops;
    error = pci_ops->prepare(pci_ops->context,
        config->pci_locations, config->pci_location_count);
    if (error != 0)
        return error;
    if (g_register_bsd_netdev)
        register_bsd_netdev();
    error = pci_ops->activate(pci_ops->context);
    if (error != 0) {
        (void)pci_ops->deactivate(pci_ops->context);
        unregister_bsd_netdev();
        (void)pci_ops->restore(pci_ops->context);
        memset(&g_operations, 0, sizeof(g_operations));
        return error;
    }
    if (status) {
        memset(status, 0, sizeof(*status));
        status->enabled = 1;
        status->pci.selected = 1;
        status->pci.attached = 1;
    }
    return 0;
}

int
bsd_bridge_handoff_stop(void)
{
    int error;

    if (!g_operations.deactivate)
        return 0;
    error = g_operations.deactivate(g_operations.context);
    if (error != 0)
        return error;
    unregister_bsd_netdev();
    error = g_operations.restore(g_operations.context);
    if (error == 0)
        memset(&g_operations, 0, sizeof(g_operations));
    return error;
}

void
e1000_init(void)
{
}

int
e1000_is_ready(void)
{
    return g_native_ready;
}

void
e1000_poll(void)
{
}

int
e1000_get_mac(uint8_t mac[6])
{
    static const uint8_t address[6] =
        {0x52, 0x54, 0, 0xab, 0xcd, 0xef};

    if (!g_native_ready)
        return -1;
    memcpy(mac, address, sizeof(address));
    return 0;
}

int
e1000_send_frame_raw(const void *frame, uint16_t length)
{
    (void)frame;
    return length;
}

void
e1000_set_rx_frame_callback(e1000_rx_frame_cb_t callback)
{
    g_native_receive = callback;
}

int
e1000_get_pci_location(uint8_t *bus, uint8_t *slot,
    uint8_t *function)
{
    if (!g_native_ready)
        return -1;
    *bus = 0;
    *slot = 5;
    *function = 0;
    return 0;
}

int
e1000_stop(void)
{
    g_stop_count++;
    if (g_stop_error)
        return g_stop_error;
    g_native_ready = 0;
    return 0;
}

int
e1000_resume(void)
{
    g_resume_count++;
    g_native_ready = 1;
    return 0;
}

int
e1000_send_icmp_echo(uint32_t destination, const uint8_t *payload,
    uint16_t length)
{
    (void)destination;
    (void)payload;
    (void)length;
    return -1;
}

int
e1000_recv_icmp_reply_for_id(uint16_t identifier, uint8_t *packet,
    uint32_t *packet_length, uint32_t *source)
{
    (void)identifier;
    (void)packet;
    (void)packet_length;
    (void)source;
    return 0;
}

int
lwip_stack_bind_netdev(edge_netdev_handle_t handle)
{
    if (g_fail_next_bind) {
        g_fail_next_bind = 0;
        return -1;
    }
    if (edge_netdev_set_active(handle) != 0 ||
        edge_netdev_set_up(handle, 1) != 0)
        return -1;
    g_lwip_handle = handle;
    return 0;
}

int
lwip_stack_unbind_netdev(edge_netdev_handle_t handle)
{
    if (!handle || handle != g_lwip_handle ||
        edge_netdev_set_up(handle, 0) != 0)
        return -1;
    g_lwip_handle = 0;
    return 0;
}

edge_netdev_handle_t
lwip_stack_get_netdev(void)
{
    return g_lwip_handle;
}

static void
register_and_bind_native(void)
{
    assert(edge_native_netdev_register() == 0);
    assert(g_native_receive != 0);
    assert(lwip_stack_bind_netdev(
        edge_native_netdev_get_handle()) == 0);
}

static void
assert_native_restored(void)
{
    assert(g_native_ready == 1);
    assert(edge_native_netdev_get_handle() != 0);
    assert(g_lwip_handle == edge_native_netdev_get_handle());
    assert(g_native_receive != 0);
    assert(edge_netdev_count() == 1);
}

int
main(void)
{
    bsd_bridge_handoff_status_t status;
    edge_netdev_handle_t native;

    register_and_bind_native();
    assert(bsd_bridge_x86_64_handoff_start(
        "bsd_bridge.pci=0000:00:05.0", &status) == 0);
    assert(status.enabled == 1);
    assert(g_native_ready == 0);
    assert(edge_native_netdev_get_handle() == 0);
    assert(g_lwip_handle == g_bsd_handle);
    assert(g_stop_count == 1);
    assert(bsd_bridge_handoff_stop() == 0);
    assert(g_resume_count == 1);
    assert_native_restored();

    g_fail_next_bind = 1;
    assert(bsd_bridge_x86_64_handoff_start(
        "bsd_bridge.pci=0000:00:05.0", &status) == 2);
    assert(g_stop_count == 2);
    assert(g_resume_count == 2);
    assert_native_restored();

    g_stop_error = 5;
    assert(bsd_bridge_x86_64_handoff_start(
        "bsd_bridge.pci=0000:00:05.0", &status) == 5);
    g_stop_error = 0;
    assert(g_resume_count == 3);
    assert_native_restored();

    native = edge_native_netdev_get_handle();
    assert(lwip_stack_unbind_netdev(native) == 0);
    assert(edge_native_netdev_unregister() == 0);
    g_native_ready = 0;
    assert(bsd_bridge_x86_64_handoff_start(
        "bsd_bridge.pci=0000:00:05.0", &status) == 0);
    assert(g_lwip_handle == g_bsd_handle);
    assert(edge_netdev_count() == 1);
    assert(bsd_bridge_handoff_stop() == 0);
    assert(g_lwip_handle == 0);
    assert(edge_netdev_count() == 0);
    g_native_ready = 1;
    register_and_bind_native();

    g_selected_slot = 6;
    assert(bsd_bridge_x86_64_reserve_native_devices(
        "bsd_bridge.pci=0000:00:06.0") == 0);
    assert(g_usb_reserved == 1);
    assert(bsd_bridge_x86_64_native_pci_reserved(0, 6, 0) == 1);
    assert(bsd_bridge_x86_64_native_pci_reserved(0, 5, 0) == 0);
    assert(bsd_bridge_x86_64_handoff_start(
        "bsd_bridge.pci=0000:00:06.0", &status) == 0);
    assert(g_usb_prepare_count == 1);
    assert(g_native_ready == 1);
    assert(g_lwip_handle == g_bsd_handle);
    assert(edge_netdev_count() == 2);
    assert(bsd_bridge_handoff_stop() == 0);
    assert(g_usb_restore_count == 1);
    assert(g_usb_reserved == 0);
    assert(bsd_bridge_x86_64_native_pci_reserved(0, 6, 0) == 0);
    assert_native_restored();

    g_register_bsd_netdev = 0;
    assert(bsd_bridge_x86_64_handoff_start(
        "bsd_bridge.pci=0000:00:06.0", &status) == 0);
    assert(g_native_ready == 1);
    assert(g_lwip_handle == edge_native_netdev_get_handle());
    assert(edge_netdev_count() == 1);
    assert(bsd_bridge_handoff_stop() == 0);
    assert(g_usb_restore_count == 2);
    assert_native_restored();

    g_usb_prepare_error = 11;
    assert(bsd_bridge_x86_64_reserve_native_devices(
        "bsd_bridge.pci=0000:00:06.0") == 0);
    assert(bsd_bridge_x86_64_handoff_start(
        "bsd_bridge.pci=0000:00:06.0", &status) == 11);
    assert(g_usb_release_count > 0);
    assert(g_usb_reserved == 0);
    g_usb_prepare_error = 0;

    return 0;
}
