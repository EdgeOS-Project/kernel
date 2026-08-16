/* SPDX-License-Identifier: MPL-2.0 */
/* Shared registration adapter for the original EdgeOS network backend. */

#include "net/native_netdev.h"

#include "drivers/e1000.h"

#include <stdint.h>

#define EDGE_NATIVE_NETDEV_EBUSY 16
#define EDGE_NATIVE_NETDEV_ENODEV 19

static edge_netdev_handle_t g_native_handle;

static int
native_transmit(void *context, const void *frame, uint32_t length)
{
    (void)context;
    if (length > UINT16_MAX)
        return -1;
    return e1000_send_frame_raw(frame, (uint16_t)length);
}

static void
native_poll(void *context)
{
    (void)context;
    e1000_poll();
}

static int
native_set_up(void *context, int up)
{
    (void)context;
    return !up || e1000_is_ready() ? 0 : -1;
}

static void
native_receive(const uint8_t *frame, uint32_t length)
{
    edge_netdev_handle_t handle = __atomic_load_n(&g_native_handle,
        __ATOMIC_ACQUIRE);

    if (handle)
        (void)edge_netdev_receive(handle, frame, length);
}

int
edge_native_netdev_register(void)
{
    edge_netdev_config_t config = {0};
    edge_netdev_handle_t handle;

    if (g_native_handle)
        return EDGE_NATIVE_NETDEV_EBUSY;
    if (!e1000_is_ready())
        return EDGE_NATIVE_NETDEV_ENODEV;
    config.name = "native0";
    if (e1000_get_mac(config.mac) != 0)
        return EDGE_NATIVE_NETDEV_ENODEV;
    config.mtu = 1500;
    config.link_up = 1;
    config.ops.transmit = native_transmit;
    config.ops.poll = native_poll;
    config.ops.set_up = native_set_up;
    if (edge_netdev_register(&config, &handle) != 0)
        return EDGE_NATIVE_NETDEV_EBUSY;
    __atomic_store_n(&g_native_handle, handle, __ATOMIC_RELEASE);
    e1000_set_rx_frame_callback(native_receive);
    return 0;
}

int
edge_native_netdev_unregister(void)
{
    edge_netdev_handle_t handle = __atomic_load_n(&g_native_handle,
        __ATOMIC_ACQUIRE);
    int error;

    if (!handle)
        return 0;
    e1000_set_rx_frame_callback(0);
    error = edge_netdev_set_up(handle, 0);
    if (error == 0)
        error = edge_netdev_unregister(handle);
    if (error != 0) {
        e1000_set_rx_frame_callback(native_receive);
        return error;
    }
    __atomic_store_n(&g_native_handle, 0, __ATOMIC_RELEASE);
    return 0;
}

edge_netdev_handle_t
edge_native_netdev_get_handle(void)
{
    return __atomic_load_n(&g_native_handle, __ATOMIC_ACQUIRE);
}
