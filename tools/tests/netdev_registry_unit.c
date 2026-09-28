/* SPDX-License-Identifier: MPL-2.0 */

#include "net/netdev.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

typedef struct test_device {
    int up_calls;
    int poll_calls;
    int transmit_calls;
    int up;
    uint8_t last_frame[64];
    uint32_t last_length;
} test_device_t;

typedef struct receive_state {
    int calls;
    uint8_t last_frame[64];
    uint32_t last_length;
} receive_state_t;

typedef struct link_state {
    int calls;
    int link_up;
} link_state_t;

static int
test_transmit(void *context, const void *frame, uint32_t length)
{
    test_device_t *device = context;

    assert(length <= sizeof(device->last_frame));
    memcpy(device->last_frame, frame, length);
    device->last_length = length;
    device->transmit_calls++;
    return 0;
}

static void
test_poll(void *context)
{
    test_device_t *device = context;

    device->poll_calls++;
}

static int
test_set_up(void *context, int up)
{
    test_device_t *device = context;

    device->up_calls++;
    device->up = up;
    return 0;
}

static void
test_receive(const uint8_t *frame, uint32_t length, void *context)
{
    receive_state_t *state = context;

    assert(length <= sizeof(state->last_frame));
    memcpy(state->last_frame, frame, length);
    state->last_length = length;
    state->calls++;
}

static void
test_link_change(int link_up, void *context)
{
    link_state_t *state = context;

    state->calls++;
    state->link_up = link_up;
}

static edge_netdev_config_t
test_config(const char *name, test_device_t *device, uint8_t suffix)
{
    edge_netdev_config_t config;

    memset(&config, 0, sizeof(config));
    config.name = name;
    config.mac[0] = 0x52;
    config.mac[1] = 0x54;
    config.mac[2] = 0x00;
    config.mac[3] = 0x12;
    config.mac[4] = 0x34;
    config.mac[5] = suffix;
    config.mtu = 1500;
    config.link_up = 1;
    config.ops.transmit = test_transmit;
    config.ops.poll = test_poll;
    config.ops.set_up = test_set_up;
    config.context = device;
    return config;
}

int
main(void)
{
    test_device_t first = {0};
    test_device_t second = {0};
    receive_state_t receive = {0};
    link_state_t link = {0};
    edge_netdev_config_t first_config = test_config("vtnet0", &first, 1);
    edge_netdev_config_t second_config = test_config("vtnet1", &second, 2);
    edge_netdev_handle_t first_handle;
    edge_netdev_handle_t second_handle;
    edge_netdev_handle_t replacement_handle;
    edge_netdev_handle_t snapshot[EDGE_NETDEV_MAX];
    size_t snapshot_count;
    uint8_t frame[] = {0xde, 0xad, 0xbe, 0xef};
    uint8_t mac[EDGE_NETDEV_MAC_LENGTH];
    char name[EDGE_NETDEV_NAME_MAX];
    uint32_t mtu;
    int link_up;
    int up;

    assert(edge_netdev_register(&first_config, &first_handle) == 0);
    assert(edge_netdev_register(&second_config, &second_handle) == 0);
    assert(first_handle != second_handle);
    assert(edge_netdev_count() == 2);
    assert(edge_netdev_snapshot(snapshot, EDGE_NETDEV_MAX,
        &snapshot_count) == 0);
    assert(snapshot_count == 2);
    assert(snapshot[0] == first_handle);
    assert(snapshot[1] == second_handle);
    assert(edge_netdev_snapshot(snapshot, 1, &snapshot_count) == 28);
    assert(snapshot_count == 2);
    assert(edge_netdev_get_active() == first_handle);
    assert(edge_netdev_register(&first_config, &replacement_handle) == 16);

    assert(edge_netdev_get_info(first_handle, name, sizeof(name), mac, &mtu,
        &link_up, &up) == 0);
    assert(strcmp(name, "vtnet0") == 0);
    assert(mac[5] == 1);
    assert(mtu == 1500);
    assert(link_up == 1);
    assert(up == 0);

    assert(edge_netdev_set_receive_callback(first_handle, test_receive,
        &receive) == 0);
    assert(edge_netdev_transmit(first_handle, 0, sizeof(frame)) == -22);
    assert(edge_netdev_transmit(first_handle, frame, 0) == -22);
    assert(edge_netdev_receive(first_handle, frame, sizeof(frame)) == 2);
    assert(edge_netdev_set_up(first_handle, 1) == 0);
    assert(first.up_calls == 1 && first.up == 1);
    assert(edge_netdev_transmit(first_handle, frame, sizeof(frame)) == 0);
    assert(first.transmit_calls == 1);
    assert(first.last_length == sizeof(frame));
    assert(memcmp(first.last_frame, frame, sizeof(frame)) == 0);
    edge_netdev_poll(first_handle);
    assert(first.poll_calls == 1);
    assert(edge_netdev_receive(first_handle, frame, sizeof(frame)) == 0);
    assert(receive.calls == 1);
    assert(receive.last_length == sizeof(frame));

    assert(edge_netdev_unregister(first_handle) == 16);
    assert(edge_netdev_set_up(first_handle, 0) == 0);
    assert(edge_netdev_unregister(first_handle) == 0);
    assert(edge_netdev_get_active() == second_handle);
    assert(edge_netdev_transmit(first_handle, frame, sizeof(frame)) == -2);

    assert(edge_netdev_register(&first_config, &replacement_handle) == 0);
    assert(replacement_handle != first_handle);
    assert(edge_netdev_set_active(replacement_handle) == 0);
    assert(edge_netdev_set_up(replacement_handle, 1) == 0);
    assert(edge_netdev_set_link_callback(replacement_handle,
        test_link_change, &link) == 0);
    assert(link.calls == 1 && link.link_up == 1);
    assert(edge_netdev_set_link(replacement_handle, 0) == 0);
    assert(link.calls == 2 && link.link_up == 0);
    assert(edge_netdev_set_link(replacement_handle, 0) == 0);
    assert(link.calls == 2);
    assert(edge_netdev_transmit(replacement_handle, frame, sizeof(frame)) == -2);
    assert(edge_netdev_set_link(replacement_handle, 1) == 0);
    assert(link.calls == 3 && link.link_up == 1);
    assert(edge_netdev_set_link_callback(replacement_handle, 0, 0) == 0);
    assert(edge_netdev_set_link(replacement_handle, 0) == 0);
    assert(link.calls == 3);
    assert(edge_netdev_set_link(replacement_handle, 1) == 0);
    assert(edge_netdev_set_up(replacement_handle, 0) == 0);
    assert(edge_netdev_unregister(replacement_handle) == 0);
    assert(edge_netdev_unregister(second_handle) == 0);
    assert(edge_netdev_count() == 0);
    assert(edge_netdev_get_active() == 0);
    return 0;
}
