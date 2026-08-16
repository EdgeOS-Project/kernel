/* SPDX-License-Identifier: MPL-2.0 */

#include "drivers/e1000.h"
#include "net/native_netdev.h"
#include "net/netdev.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static int g_ready = 1;
static int g_poll_count;
static int g_transmit_count;
static uint8_t g_transmitted[64];
static uint16_t g_transmitted_length;
static e1000_rx_frame_cb_t g_receive;
static int g_receive_count;

void
e1000_init(void)
{
}

int
e1000_is_ready(void)
{
    return g_ready;
}

void
e1000_poll(void)
{
    g_poll_count++;
}

int
e1000_get_mac(uint8_t mac_out[6])
{
    static const uint8_t mac[6] = {0x52, 0x54, 0, 0x12, 0x34, 0x56};

    if (!g_ready || !mac_out)
        return -1;
    memcpy(mac_out, mac, sizeof(mac));
    return 0;
}

int
e1000_send_frame_raw(const void *frame, uint16_t length)
{
    assert(length <= sizeof(g_transmitted));
    memcpy(g_transmitted, frame, length);
    g_transmitted_length = length;
    g_transmit_count++;
    return length;
}

void
e1000_set_rx_frame_callback(e1000_rx_frame_cb_t callback)
{
    g_receive = callback;
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
test_receive(const uint8_t *frame, uint32_t length, void *context)
{
    const uint8_t *expected = context;

    assert(length == 4);
    assert(memcmp(frame, expected, length) == 0);
    g_receive_count++;
}

int
main(void)
{
    uint8_t frame[] = {1, 2, 3, 4};
    edge_netdev_handle_t handle;

    assert(edge_native_netdev_register() == 0);
    handle = edge_native_netdev_get_handle();
    assert(handle != 0);
    assert(edge_netdev_get_active() == handle);
    assert(edge_native_netdev_register() == 16);
    assert(edge_netdev_set_receive_callback(handle, test_receive,
        frame) == 0);
    assert(edge_netdev_set_up(handle, 1) == 0);
    assert(g_receive != 0);
    g_receive(frame, sizeof(frame));
    assert(g_receive_count == 1);
    assert(edge_netdev_transmit(handle, frame, sizeof(frame)) ==
        (int)sizeof(frame));
    assert(g_transmit_count == 1);
    assert(g_transmitted_length == sizeof(frame));
    assert(memcmp(g_transmitted, frame, sizeof(frame)) == 0);
    edge_netdev_poll(handle);
    assert(g_poll_count == 1);
    assert(edge_native_netdev_unregister() == 0);
    assert(edge_native_netdev_get_handle() == 0);
    assert(g_receive == 0);
    assert(edge_netdev_count() == 0);
    assert(edge_native_netdev_unregister() == 0);

    g_ready = 0;
    assert(edge_native_netdev_register() == 19);
    return 0;
}
