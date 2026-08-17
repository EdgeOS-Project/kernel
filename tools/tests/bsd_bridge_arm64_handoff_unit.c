/* SPDX-License-Identifier: MPL-2.0 */
/* Transaction tests for ARM64 native-to-BSD network handoff. */

#include "compat/freebsd/edgeos/arm64_handoff.h"
#include "compat/freebsd/edgeos/virtio_mmio.h"
#include "drivers/e1000.h"
#include "drivers/virtio_net_mmio.h"
#include "net/lwip_stack.h"
#include "net/native_netdev.h"
#include "net/netdev.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static char g_parent_object;
static char g_bsd_device_object;
static bsd_bridge_platform_handoff_ops_t g_platform_operations;
static device_t g_platform_device;
static edge_netdev_handle_t g_lwip_handle;
static edge_netdev_handle_t g_bsd_handle;
static int g_describe_error;
static int g_attach_error;
static int g_stop_error;
static int g_resume_error;
static int g_fail_next_bind;
static int g_stop_count;
static int g_resume_count;
static int g_bsd_attach_count;
static int g_bsd_detach_count;
static int g_native_ready = 1;
static e1000_rx_frame_cb_t g_native_receive;

static int
test_transmit(void *context, const void *frame, uint32_t length)
{
    (void)context;
    (void)frame;
    return (int)length;
}

int
bsd_bridge_handoff_start_from_command_line_with_platform(
    const char *command_line,
    const bsd_bridge_platform_handoff_ops_t *operations,
    bsd_bridge_handoff_status_t *status)
{
    bsd_bridge_platform_request_t request = {
        .kind = BSD_BRIDGE_PLATFORM_VIRTIO_MMIO,
        .device = 1,
        .instance = 0,
    };
    device_t device = 0;
    int error;

    assert(command_line != 0);
    assert(operations != 0);
    g_platform_operations = *operations;
    error = operations->attach(operations->context,
        (device_t)(void *)&g_parent_object, &request, 0, &device);
    if (error)
        return error;
    g_platform_device = device;
    if (status) {
        memset(status, 0, sizeof(*status));
        status->enabled = 1;
        status->platform_selected = 1;
        status->platform_attached = 1;
    }
    return 0;
}

int
edgeos_arm64_virtio_mmio_describe_nth(
    const edgeos_arm64_bootinfo_t *bootinfo, uint32_t device_id,
    uint32_t instance, uint64_t *base, uint64_t *size,
    uint32_t *interrupt, uint32_t *interrupt_flags)
{
    assert(bootinfo != 0);
    assert(device_id == 1);
    assert(instance == 0);
    if (g_describe_error)
        return g_describe_error;
    *base = 0x0a003c00;
    *size = 0x200;
    *interrupt = 78;
    *interrupt_flags = 4;
    return 0;
}

int
bsd_virtio_mmio_attach(device_t parent,
    const bsd_virtio_mmio_description_t *description, device_t *result)
{
    edge_netdev_config_t config = {0};

    assert(parent == (device_t)(void *)&g_parent_object);
    assert(description != 0);
    if (g_attach_error)
        return g_attach_error;
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
    *result = (device_t)(void *)&g_bsd_device_object;
    g_bsd_attach_count++;
    return 0;
}

int
bsd_virtio_mmio_detach(device_t parent, device_t device)
{
    assert(parent == (device_t)(void *)&g_parent_object);
    assert(device == (device_t)(void *)&g_bsd_device_object);
    if (g_bsd_handle) {
        assert(edge_netdev_set_up(g_bsd_handle, 0) == 0);
        assert(edge_netdev_unregister(g_bsd_handle) == 0);
        g_bsd_handle = 0;
    }
    g_bsd_detach_count++;
    return 0;
}

int
edgeos_arm64_virtio_net_stop(void)
{
    g_stop_count++;
    if (g_stop_error)
        return g_stop_error;
    g_native_ready = 0;
    return 0;
}

int
edgeos_arm64_virtio_net_resume(void)
{
    g_resume_count++;
    if (g_resume_error)
        return g_resume_error;
    g_native_ready = 1;
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

static void
detach_successful_handoff(void)
{
    assert(g_platform_device != 0);
    assert(g_platform_operations.detach(
        g_platform_operations.context,
        (device_t)(void *)&g_parent_object,
        g_platform_device) == 0);
    g_platform_device = 0;
    assert_native_restored();
}

int
main(void)
{
    edgeos_arm64_bootinfo_t bootinfo = {0};
    bsd_bridge_handoff_status_t status;
    int initial_stop_count;
    int initial_resume_count;

    register_and_bind_native();
    assert(bsd_bridge_arm64_handoff_start(
        "bsd_bridge.platform=virtio-mmio:1:0",
        &bootinfo, &status) == 0);
    assert(status.enabled == 1);
    assert(g_native_ready == 0);
    assert(edge_native_netdev_get_handle() == 0);
    assert(g_lwip_handle == g_bsd_handle);
    assert(g_stop_count == 1);
    assert(g_bsd_attach_count == 1);
    detach_successful_handoff();
    assert(g_resume_count == 1);
    assert(g_bsd_detach_count == 1);

    initial_stop_count = g_stop_count;
    initial_resume_count = g_resume_count;
    g_describe_error = 2;
    assert(bsd_bridge_arm64_handoff_start(
        "bsd_bridge.platform=virtio-mmio:1:0",
        &bootinfo, &status) == 2);
    g_describe_error = 0;
    assert(g_stop_count == initial_stop_count + 1);
    assert(g_resume_count == initial_resume_count + 1);
    assert_native_restored();

    initial_stop_count = g_stop_count;
    initial_resume_count = g_resume_count;
    g_attach_error = 5;
    assert(bsd_bridge_arm64_handoff_start(
        "bsd_bridge.platform=virtio-mmio:1:0",
        &bootinfo, &status) == 5);
    g_attach_error = 0;
    assert(g_stop_count == initial_stop_count + 1);
    assert(g_resume_count == initial_resume_count + 1);
    assert_native_restored();

    initial_stop_count = g_stop_count;
    initial_resume_count = g_resume_count;
    g_fail_next_bind = 1;
    assert(bsd_bridge_arm64_handoff_start(
        "bsd_bridge.platform=virtio-mmio:1:0",
        &bootinfo, &status) == 2);
    assert(g_stop_count == initial_stop_count + 1);
    assert(g_resume_count == initial_resume_count + 1);
    assert_native_restored();

    initial_stop_count = g_stop_count;
    g_stop_error = 16;
    assert(bsd_bridge_arm64_handoff_start(
        "bsd_bridge.platform=virtio-mmio:1:0",
        &bootinfo, &status) == 16);
    g_stop_error = 0;
    assert(g_stop_count == initial_stop_count + 1);
    assert_native_restored();

    assert(edge_native_netdev_unregister() == 0);
    g_lwip_handle = 0;
    assert(edge_netdev_count() == 0);
    return 0;
}
