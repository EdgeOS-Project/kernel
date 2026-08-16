/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "net/network_core.h"

typedef struct test_endpoint {
    uint32_t receives;
    uint32_t transmits;
    uint32_t bytes;
    int32_t last_ifindex;
    uint32_t last_namespace;
    int32_t last_packet_input_ifindex;
    int32_t last_packet_output_ifindex;
    uint32_t last_packet_namespace;
    uint32_t last_packet_mark;
    uint8_t last_frame[128];
} test_endpoint_t;

static uint32_t release_count;
static uint32_t hook_order[32];
static uint32_t hook_order_count;

static enum edge_net_hook_verdict mark_packet(
    enum edge_net_hook_stage stage, edge_net_packet_t *packet,
    void *context) {
    uint32_t value = *(const uint32_t *)context;

    assert(stage == EDGE_NET_HOOK_LOCAL_INPUT);
    assert(hook_order_count < sizeof(hook_order) / sizeof(hook_order[0]));
    hook_order[hook_order_count++] = 1u;
    packet->metadata.mark = value;
    return EDGE_NET_VERDICT_ACCEPT;
}

static enum edge_net_hook_verdict observe_mark(
    enum edge_net_hook_stage stage, edge_net_packet_t *packet,
    void *context) {
    uint32_t expected = *(const uint32_t *)context;

    assert(stage == EDGE_NET_HOOK_LOCAL_INPUT);
    assert(packet->metadata.mark == expected);
    assert(hook_order_count < sizeof(hook_order) / sizeof(hook_order[0]));
    hook_order[hook_order_count++] = 2u;
    return EDGE_NET_VERDICT_ACCEPT;
}

static enum edge_net_hook_verdict drop_packet(
    enum edge_net_hook_stage stage, edge_net_packet_t *packet,
    void *context) {
    (void)packet;
    (void)context;
    assert(stage == EDGE_NET_HOOK_LOCAL_INPUT);
    assert(hook_order_count < sizeof(hook_order) / sizeof(hook_order[0]));
    hook_order[hook_order_count++] = 3u;
    return EDGE_NET_VERDICT_DROP;
}

static void release_packet(void *context) {
    uint32_t *count = (uint32_t *)context;

    ++*count;
}

static void receive_packet(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context) {
    test_endpoint_t *endpoint = (test_endpoint_t *)context;
    int length;

    ++endpoint->receives;
    endpoint->last_ifindex = ifindex;
    endpoint->last_namespace = network_namespace;
    endpoint->last_packet_input_ifindex = packet->metadata.input_ifindex;
    endpoint->last_packet_output_ifindex = packet->metadata.output_ifindex;
    endpoint->last_packet_namespace = packet->metadata.network_namespace;
    endpoint->last_packet_mark = packet->metadata.mark;
    length = edge_net_packet_linearize(
        packet, endpoint->last_frame, sizeof(endpoint->last_frame));
    assert(length >= 0);
    endpoint->bytes += (uint32_t)length;
}

static void transmit_packet(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context) {
    test_endpoint_t *endpoint = (test_endpoint_t *)context;

    ++endpoint->transmits;
    endpoint->last_ifindex = ifindex;
    endpoint->last_namespace = network_namespace;
    endpoint->last_packet_input_ifindex = packet->metadata.input_ifindex;
    endpoint->last_packet_output_ifindex = packet->metadata.output_ifindex;
    endpoint->last_packet_namespace = packet->metadata.network_namespace;
    endpoint->last_packet_mark = packet->metadata.mark;
    assert(edge_net_packet_linearize(
               packet, endpoint->last_frame,
               sizeof(endpoint->last_frame)) == (int)packet->total_length);
    endpoint->bytes += packet->total_length;
}

static edge_net_device_configuration_t configuration(
    int32_t ifindex, uint32_t network_namespace,
    enum edge_net_device_kind kind, const char *name,
    const uint8_t hardware_address[6], test_endpoint_t *endpoint) {
    edge_net_device_configuration_t result;

    memset(&result, 0, sizeof(result));
    result.ifindex = ifindex;
    result.network_namespace = network_namespace;
    result.kind = kind;
    result.flags = EDGE_NET_DEVICE_FLAG_UP |
                   EDGE_NET_DEVICE_FLAG_BROADCAST |
                   EDGE_NET_DEVICE_FLAG_RUNNING |
                   EDGE_NET_DEVICE_FLAG_MULTICAST;
    result.mtu = 1500u;
    result.carrier = 1u;
    memcpy(result.hardware_address, hardware_address, 6u);
    memcpy(result.name, name, strlen(name) + 1u);
    if (endpoint) {
        result.receive = receive_packet;
        result.transmit = transmit_packet;
        result.callback_context = endpoint;
    }
    return result;
}

static edge_net_packet_t packet_from_frame(
    const uint8_t *frame, uint32_t length, uint64_t timestamp_ns) {
    edge_net_packet_t packet;
    edge_net_packet_segment_t segments[2];
    edge_net_packet_metadata_t metadata;
    uint32_t split = 9u;

    assert(length > split);
    memset(&metadata, 0, sizeof(metadata));
    metadata.timestamp_ns = timestamp_ns;
    segments[0].data = frame;
    segments[0].length = split;
    segments[1].data = frame + split;
    segments[1].length = length - split;
    assert(edge_net_packet_initialize(
               &packet, segments, 2u, &metadata,
               release_packet, &release_count) == EDGE_NET_OK);
    return packet;
}

int main(void) {
    static const uint8_t bridge_mac[6] = {
        0x02u, 0x42u, 0, 0, 0, 0x10u
    };
    static const uint8_t host1_mac[6] = {
        0x02u, 0x42u, 0, 0, 0, 0x11u
    };
    static const uint8_t container1_mac[6] = {
        0x02u, 0x42u, 0, 0, 0, 0x12u
    };
    static const uint8_t host2_mac[6] = {
        0x02u, 0x42u, 0, 0, 0, 0x13u
    };
    static const uint8_t container2_mac[6] = {
        0x02u, 0x42u, 0, 0, 0, 0x14u
    };
    static const uint8_t broadcast[6] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu
    };
    test_endpoint_t bridge_endpoint;
    test_endpoint_t container1_endpoint;
    test_endpoint_t container2_endpoint;
    edge_net_device_configuration_t bridge;
    edge_net_device_configuration_t host1;
    edge_net_device_configuration_t container1;
    edge_net_device_configuration_t host2;
    edge_net_device_configuration_t container2;
    edge_net_device_snapshot_t snapshot;
    edge_net_bridge_fdb_entry_t fdb;
    edge_net_bridge_mdb_entry_t mdb;
    edge_net_bridge_vlan_entry_t bridge_vlan;
    edge_net_packet_t packet;
    uint8_t frame[64];
    uint8_t linear[64];
    uint8_t multicast_frame[96];
    uint32_t receives_before;
    int32_t ifindex;
    int setting_value;
    uint32_t mark_hook_handle;
    uint32_t observe_hook_handle;
    uint32_t drop_hook_handle;
    uint32_t hook_mark = 0x42u;
    edge_net_hook_registration_t hook;

    memset(&bridge_endpoint, 0, sizeof(bridge_endpoint));
    memset(&container1_endpoint, 0, sizeof(container1_endpoint));
    memset(&container2_endpoint, 0, sizeof(container2_endpoint));
    release_count = 0u;
    edge_net_core_reset();

    assert(edge_net_namespace_ipv4_forwarding_get(
               0u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 0);
    assert(edge_net_namespace_ipv4_forwarding_set(0u, 1) == EDGE_NET_OK);
    assert(edge_net_namespace_ipv4_forwarding_get(
               0u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 1);
    assert(edge_net_namespace_ensure(100u) == EDGE_NET_OK);
    assert(edge_net_namespace_ipv4_forwarding_get(
               100u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 0);
    assert(edge_net_namespace_ipv4_forwarding_set(100u, 1) == EDGE_NET_OK);
    assert(edge_net_namespace_ipv4_forwarding_get(
               100u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 1);
    assert(edge_net_namespace_ipv6_setting_get(
               100u, 1u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 0);
    assert(edge_net_namespace_ipv6_setting_set(
               100u, 1u, 1) == EDGE_NET_OK);
    assert(edge_net_namespace_ipv6_setting_get(
               100u, 1u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 1);
    assert(edge_net_namespace_ipv6_setting_get(
               100u, 2u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 1);
    assert(edge_net_namespace_ipv6_setting_set(
               100u, 2u, 2) == EDGE_NET_OK);
    assert(edge_net_namespace_ipv6_setting_get(
               100u, 2u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 2);
    assert(edge_net_namespace_ipv6_setting_set(
               100u, 4u, 1) == EDGE_NET_INVALID);
    assert(edge_net_namespace_bridge_filter_get(
               100u, 0u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 1);
    assert(edge_net_namespace_bridge_filter_set(100u, 0u, 0) ==
           EDGE_NET_OK);
    assert(edge_net_namespace_bridge_filter_get(
               100u, 0u, &setting_value) == EDGE_NET_OK);
    assert(setting_value == 0);
    assert(edge_net_namespace_bridge_filter_set(100u, 3u, 1) ==
           EDGE_NET_INVALID);

    assert(edge_net_route_interface_snapshot(1, 0u, &snapshot) ==
           EDGE_NET_OK);
    assert(snapshot.configuration.ifindex == 1);
    assert(snapshot.configuration.network_namespace == 0u);
    assert(snapshot.configuration.kind == EDGE_NET_DEVICE_LOOPBACK);
    assert(strcmp(snapshot.configuration.name, "lo") == 0);
    assert(edge_net_route_interface_snapshot(1, 9u, &snapshot) ==
           EDGE_NET_OK);
    assert(snapshot.configuration.network_namespace == 9u);
    assert(edge_net_route_interface_snapshot(2, 0u, &snapshot) ==
           EDGE_NET_NOT_FOUND);

    bridge = configuration(
        10, 0u, EDGE_NET_DEVICE_BRIDGE, "docker0",
        bridge_mac, &bridge_endpoint);
    host1 = configuration(
        11, 0u, EDGE_NET_DEVICE_VETH, "veth-host1",
        host1_mac, 0);
    container1 = configuration(
        12, 1u, EDGE_NET_DEVICE_VETH, "eth0",
        container1_mac, &container1_endpoint);
    host2 = configuration(
        13, 0u, EDGE_NET_DEVICE_VETH, "veth-host2",
        host2_mac, 0);
    container2 = configuration(
        14, 2u, EDGE_NET_DEVICE_VETH, "eth0",
        container2_mac, &container2_endpoint);

    assert(edge_net_device_register(&bridge) == EDGE_NET_OK);
    assert(edge_net_veth_register_pair(&host1, &container1) == EDGE_NET_OK);
    assert(edge_net_veth_register_pair(&host2, &container2) == EDGE_NET_OK);
    assert(edge_net_device_set_master(11, 10) == EDGE_NET_OK);
    assert(edge_net_device_set_master(13, 10) == EDGE_NET_OK);
    assert(edge_net_device_snapshot(11, &snapshot) == EDGE_NET_OK);
    assert(snapshot.bridge_state == EDGE_NET_BRIDGE_STATE_FORWARDING);
    assert(snapshot.bridge_learning == 1u);
    assert(snapshot.bridge_unicast_flood == 1u);
    assert(snapshot.bridge_multicast_flood == 1u);
    assert(snapshot.bridge_broadcast_flood == 1u);
    assert(snapshot.bridge_isolated == 0u);
    assert(edge_net_device_find(0u, "docker0", &ifindex) == EDGE_NET_OK);
    assert(ifindex == 10);
    assert(edge_net_device_find(1u, "eth0", &ifindex) == EDGE_NET_OK);
    assert(ifindex == 12);
    assert(edge_net_route_interface_snapshot(12, 1u, &snapshot) ==
           EDGE_NET_OK);
    assert(edge_net_route_interface_snapshot(12, 0u, &snapshot) ==
           EDGE_NET_WRONG_NAMESPACE);
    assert(edge_net_device_get_ipv6_setting(10, 0u, &setting_value) ==
           EDGE_NET_OK);
    assert(setting_value == 0);
    assert(edge_net_device_get_ipv6_setting(10, 2u, &setting_value) ==
           EDGE_NET_OK);
    assert(setting_value == 1);
    assert(edge_net_device_set_ipv6_setting(10, 0u, 1) == EDGE_NET_OK);
    assert(edge_net_device_get_ipv6_setting(10, 0u, &setting_value) ==
           EDGE_NET_OK);
    assert(setting_value == 1);
    assert(edge_net_device_get_ipv6_setting(999, 0u, &setting_value) ==
           EDGE_NET_NOT_FOUND);
    assert(edge_net_device_set_ipv6_setting(10, 4u, 1) ==
           EDGE_NET_INVALID);
    assert(edge_net_device_set_ipv6_setting(10, 2u, 2) == EDGE_NET_OK);
    assert(edge_net_device_get_ipv6_setting(10, 2u, &setting_value) ==
           EDGE_NET_OK);
    assert(setting_value == 2);

    memset(&hook, 0, sizeof(hook));
    hook.network_namespace = 2u;
    hook.stage = EDGE_NET_HOOK_LOCAL_INPUT;
    hook.priority = -100;
    hook.callback = mark_packet;
    hook.context = &hook_mark;
    assert(edge_net_hook_register(&hook, &mark_hook_handle) == EDGE_NET_OK);
    hook.priority = 0;
    hook.callback = observe_mark;
    assert(edge_net_hook_register(&hook, &observe_hook_handle) ==
           EDGE_NET_OK);

    memset(frame, 0, sizeof(frame));
    memcpy(frame, broadcast, 6u);
    memcpy(frame + 6u, container1_mac, 6u);
    frame[12] = 0x08u;
    frame[13] = 0x00u;
    packet = packet_from_frame(frame, sizeof(frame), 100u);
    assert(edge_net_packet_linearize(
               &packet, linear, sizeof(linear)) == (int)sizeof(frame));
    assert(memcmp(linear, frame, sizeof(frame)) == 0);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(bridge_endpoint.receives == 1u);
    assert(container1_endpoint.receives == 0u);
    assert(container2_endpoint.receives == 1u);
    assert(container2_endpoint.last_namespace == 2u);
    assert(container2_endpoint.last_packet_input_ifindex == 14);
    assert(container2_endpoint.last_packet_output_ifindex == 13);
    assert(container2_endpoint.last_packet_namespace == 2u);
    assert(container2_endpoint.last_packet_mark == hook_mark);
    assert(hook_order_count == 2u);
    assert(hook_order[0] == 1u && hook_order[1] == 2u);
    assert(bridge_endpoint.last_packet_input_ifindex == 11);
    assert(bridge_endpoint.last_packet_output_ifindex == 12);
    assert(bridge_endpoint.last_packet_namespace == 0u);
    assert(packet.metadata.input_ifindex == 0);
    assert(packet.metadata.output_ifindex == 0);
    assert(edge_net_bridge_fdb_snapshot(10, 0u, &fdb) == EDGE_NET_OK);
    assert(fdb.port_ifindex == 11);
    assert(memcmp(fdb.hardware_address, container1_mac, 6u) == 0);
    assert(release_count == 0u);
    edge_net_packet_release(&packet);
    assert(release_count == 1u);

    assert(edge_net_namespace_bridge_filter_set(2u, 0u, 0) == EDGE_NET_OK);
    hook_order_count = 0u;
    packet = packet_from_frame(frame, sizeof(frame), 125u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == 2u);
    assert(container2_endpoint.last_packet_mark == 0u);
    assert(hook_order_count == 0u);
    edge_net_packet_release(&packet);
    assert(edge_net_namespace_bridge_filter_set(2u, 0u, 1) == EDGE_NET_OK);

    hook.priority = 100;
    hook.callback = drop_packet;
    hook.context = NULL;
    assert(edge_net_hook_register(&hook, &drop_hook_handle) == EDGE_NET_OK);
    hook_order_count = 0u;
    packet = packet_from_frame(frame, sizeof(frame), 150u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == 2u);
    assert(hook_order_count == 3u);
    assert(hook_order[0] == 1u && hook_order[1] == 2u &&
           hook_order[2] == 3u);
    edge_net_packet_release(&packet);
    assert(release_count == 3u);
    assert(edge_net_hook_unregister(drop_hook_handle) == EDGE_NET_OK);
    assert(edge_net_hook_unregister(drop_hook_handle) ==
           EDGE_NET_NOT_FOUND);

    memcpy(frame, container1_mac, 6u);
    memcpy(frame + 6u, container2_mac, 6u);
    packet = packet_from_frame(frame, sizeof(frame), 200u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    assert(container1_endpoint.receives == 1u);
    assert(container2_endpoint.receives == 2u);
    assert(bridge_endpoint.receives == 3u);
    edge_net_packet_release(&packet);
    assert(release_count == 4u);

    assert(edge_net_device_snapshot(11, &snapshot) == EDGE_NET_OK);
    assert(snapshot.master_ifindex == 10);
    assert(snapshot.rx_packets == 3u);
    assert(snapshot.tx_packets == 1u);
    assert(edge_net_device_snapshot(12, &snapshot) == EDGE_NET_OK);
    assert(snapshot.peer_ifindex == 11);
    assert(snapshot.tx_packets == 3u);
    assert(snapshot.rx_packets == 1u);

    assert(edge_net_device_set_hairpin(11, 1) == EDGE_NET_OK);
    memcpy(frame, container1_mac, 6u);
    memcpy(frame + 6u, container1_mac, 6u);
    packet = packet_from_frame(frame, sizeof(frame), 300u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container1_endpoint.receives == 2u);
    edge_net_packet_release(&packet);

    assert(edge_net_device_set_bridge_port_controls(
               11, EDGE_NET_BRIDGE_PORT_ISOLATED, 0u,
               0, 0, 0, 0, 0, 1) == EDGE_NET_OK);
    assert(edge_net_device_set_bridge_port_controls(
               13, EDGE_NET_BRIDGE_PORT_ISOLATED, 0u,
               0, 0, 0, 0, 0, 1) == EDGE_NET_OK);
    memcpy(frame, container2_mac, 6u);
    memcpy(frame + 6u, container1_mac, 6u);
    packet = packet_from_frame(frame, sizeof(frame), 325u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == 2u);
    edge_net_packet_release(&packet);
    assert(edge_net_device_set_bridge_port_controls(
               13, EDGE_NET_BRIDGE_PORT_ISOLATED, 0u,
               0, 0, 0, 0, 0, 0) == EDGE_NET_OK);
    packet = packet_from_frame(frame, sizeof(frame), 330u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == 3u);
    edge_net_packet_release(&packet);
    assert(edge_net_device_set_bridge_port_controls(
               11, EDGE_NET_BRIDGE_PORT_ISOLATED, 0u,
               0, 0, 0, 0, 0, 0) == EDGE_NET_OK);
    assert(edge_net_device_set_bridge_port_controls(
               13, EDGE_NET_BRIDGE_PORT_STATE, EDGE_NET_BRIDGE_STATE_BLOCKING,
               0, 0, 0, 0, 0, 0) == EDGE_NET_OK);
    packet = packet_from_frame(frame, sizeof(frame), 335u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == 3u);
    edge_net_packet_release(&packet);
    assert(edge_net_device_set_bridge_port_controls(
               13, EDGE_NET_BRIDGE_PORT_STATE,
               EDGE_NET_BRIDGE_STATE_FORWARDING,
               0, 0, 0, 0, 0, 0) == EDGE_NET_OK);

    memset(&mdb, 0, sizeof(mdb));
    mdb.bridge_ifindex = 10;
    mdb.port_ifindex = 11;
    mdb.hardware_address[0] = 0x01u;
    mdb.hardware_address[1] = 0x00u;
    mdb.hardware_address[2] = 0x5eu;
    mdb.hardware_address[3] = 0x01u;
    mdb.hardware_address[4] = 0x01u;
    mdb.hardware_address[5] = 0x01u;
    mdb.family = 2u;
    mdb.group_address[0] = 239u;
    mdb.group_address[1] = 1u;
    mdb.group_address[2] = 1u;
    mdb.group_address[3] = 1u;
    mdb.is_static = 1u;
    assert(edge_net_bridge_mdb_add(&mdb) == EDGE_NET_OK);
    memcpy(frame, mdb.hardware_address, 6u);
    memcpy(frame + 6u, container1_mac, 6u);
    packet = packet_from_frame(frame, sizeof(frame), 340u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == 3u);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_delete(
               10, 11, mdb.hardware_address, 0u) == EDGE_NET_OK);
    mdb.port_ifindex = 13;
    assert(edge_net_bridge_mdb_add(&mdb) == EDGE_NET_OK);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) == EDGE_NET_OK);
    assert(mdb.port_ifindex == 13 && mdb.family == 2u &&
           mdb.group_address[0] == 239u);
    packet = packet_from_frame(frame, sizeof(frame), 345u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == 4u);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_delete(
               10, 13, mdb.hardware_address, 0u) == EDGE_NET_OK);

    memset(multicast_frame, 0, sizeof(multicast_frame));
    multicast_frame[0] = 0x01u;
    multicast_frame[1] = 0x00u;
    multicast_frame[2] = 0x5eu;
    multicast_frame[3] = 0x01u;
    multicast_frame[4] = 0x01u;
    multicast_frame[5] = 0x01u;
    memcpy(multicast_frame + 6u, container2_mac, 6u);
    multicast_frame[12] = 0x08u;
    multicast_frame[13] = 0x00u;
    multicast_frame[14] = 0x45u;
    multicast_frame[23] = 2u;
    multicast_frame[34] = 0x16u;
    multicast_frame[38] = 239u;
    multicast_frame[39] = 1u;
    multicast_frame[40] = 1u;
    multicast_frame[41] = 1u;
    packet = packet_from_frame(multicast_frame, 42u, 500u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) == EDGE_NET_OK);
    assert(mdb.port_ifindex == 13 && mdb.family == 2u &&
           mdb.is_static == 0u && mdb.last_seen_ns == 500u);
    receives_before = container2_endpoint.receives;
    memcpy(multicast_frame + 6u, container1_mac, 6u);
    multicast_frame[23] = 17u;
    packet = packet_from_frame(multicast_frame, 42u, 510u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == receives_before + 1u);
    edge_net_packet_release(&packet);
    memcpy(multicast_frame + 6u, container2_mac, 6u);
    multicast_frame[23] = 2u;
    multicast_frame[34] = 0x17u;
    packet = packet_from_frame(multicast_frame, 42u, 520u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) ==
           EDGE_NET_NOT_FOUND);

    multicast_frame[34] = 0x16u;
    packet = packet_from_frame(multicast_frame, 42u, 530u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    edge_net_bridge_mdb_age(1031u, 500u);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) ==
           EDGE_NET_NOT_FOUND);

    memset(multicast_frame, 0, sizeof(multicast_frame));
    multicast_frame[0] = 0x33u;
    multicast_frame[1] = 0x33u;
    multicast_frame[4] = 0x12u;
    multicast_frame[5] = 0x34u;
    memcpy(multicast_frame + 6u, container2_mac, 6u);
    multicast_frame[12] = 0x86u;
    multicast_frame[13] = 0xddu;
    multicast_frame[14] = 0x60u;
    multicast_frame[20] = 0u;
    multicast_frame[54] = 58u;
    multicast_frame[55] = 0u;
    multicast_frame[62] = 131u;
    multicast_frame[70] = 0xffu;
    multicast_frame[71] = 0x3eu;
    multicast_frame[84] = 0x12u;
    multicast_frame[85] = 0x34u;
    packet = packet_from_frame(multicast_frame, 86u, 600u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) == EDGE_NET_OK);
    assert(mdb.port_ifindex == 13 && mdb.family == 10u &&
           mdb.group_address[0] == 0xffu &&
           mdb.group_address[15] == 0x34u);
    multicast_frame[62] = 132u;
    packet = packet_from_frame(multicast_frame, 86u, 610u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) ==
           EDGE_NET_NOT_FOUND);

    memset(multicast_frame, 0, sizeof(multicast_frame));
    multicast_frame[0] = 0x01u;
    multicast_frame[1] = 0x00u;
    multicast_frame[2] = 0x5eu;
    multicast_frame[5] = 0x16u;
    memcpy(multicast_frame + 6u, container2_mac, 6u);
    multicast_frame[12] = 0x08u;
    multicast_frame[13] = 0x00u;
    multicast_frame[14] = 0x45u;
    multicast_frame[23] = 2u;
    multicast_frame[34] = 0x22u;
    multicast_frame[41] = 1u;
    multicast_frame[42] = 4u;
    multicast_frame[46] = 239u;
    multicast_frame[47] = 129u;
    multicast_frame[48] = 1u;
    multicast_frame[49] = 1u;
    packet = packet_from_frame(multicast_frame, 50u, 620u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) == EDGE_NET_OK);
    assert(mdb.family == 2u && mdb.group_address[1] == 129u);
    multicast_frame[42] = 3u;
    packet = packet_from_frame(multicast_frame, 50u, 630u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) ==
           EDGE_NET_NOT_FOUND);

    memset(multicast_frame, 0, sizeof(multicast_frame));
    multicast_frame[0] = 0x33u;
    multicast_frame[1] = 0x33u;
    multicast_frame[5] = 0x16u;
    memcpy(multicast_frame + 6u, container2_mac, 6u);
    multicast_frame[12] = 0x86u;
    multicast_frame[13] = 0xddu;
    multicast_frame[14] = 0x60u;
    multicast_frame[20] = 58u;
    multicast_frame[54] = 143u;
    multicast_frame[61] = 1u;
    multicast_frame[62] = 4u;
    multicast_frame[66] = 0xffu;
    multicast_frame[67] = 0x3eu;
    multicast_frame[80] = 0x56u;
    multicast_frame[81] = 0x78u;
    packet = packet_from_frame(multicast_frame, 82u, 640u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) == EDGE_NET_OK);
    assert(mdb.family == 10u && mdb.group_address[14] == 0x56u &&
           mdb.group_address[15] == 0x78u);
    multicast_frame[62] = 3u;
    packet = packet_from_frame(multicast_frame, 82u, 650u);
    assert(edge_net_device_transmit(14, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_mdb_snapshot(10, 0u, &mdb) ==
           EDGE_NET_NOT_FOUND);

    edge_net_bridge_fdb_age(1200u, 500u);
    assert(edge_net_bridge_fdb_snapshot(10, 0u, &fdb) ==
           EDGE_NET_NOT_FOUND);
    assert(edge_net_bridge_fdb_add(
               10, container2_mac, 13, 1, 1000u) == EDGE_NET_OK);
    edge_net_bridge_fdb_age(UINT64_MAX, 1u);
    assert(edge_net_bridge_fdb_snapshot(10, 0u, &fdb) == EDGE_NET_OK);
    assert(fdb.is_static == 1u);

    assert(edge_net_bridge_vlan_snapshot(11, 0u, &bridge_vlan) ==
           EDGE_NET_OK);
    assert(bridge_vlan.vlan_id == 1u && bridge_vlan.pvid == 1u &&
           bridge_vlan.untagged == 1u);
    assert(edge_net_bridge_vlan_update(11, 1u, 1u, 0, 0, 0) ==
           EDGE_NET_OK);
    assert(edge_net_bridge_vlan_update(13, 1u, 1u, 0, 0, 0) ==
           EDGE_NET_OK);
    assert(edge_net_bridge_vlan_update(11, 100u, 100u, 1, 1, 1) ==
           EDGE_NET_OK);
    assert(edge_net_bridge_vlan_update(13, 100u, 100u, 1, 1, 1) ==
           EDGE_NET_OK);
    assert(edge_net_bridge_vlan_filtering_set(10, 1) == EDGE_NET_OK);
    assert(edge_net_device_snapshot(10, &snapshot) == EDGE_NET_OK);
    assert(snapshot.bridge_vlan_filtering == 1u);
    assert(edge_net_bridge_vlan_snapshot(13, 0u, &bridge_vlan) ==
           EDGE_NET_OK);
    assert(bridge_vlan.vlan_id == 100u && bridge_vlan.pvid == 1u &&
           bridge_vlan.untagged == 1u);
    receives_before = container2_endpoint.receives;
    memcpy(frame, broadcast, 6u);
    memcpy(frame + 6u, container1_mac, 6u);
    packet = packet_from_frame(frame, sizeof(frame), 350u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == receives_before + 1u);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_vlan_update(13, 100u, 100u, 0, 0, 0) ==
           EDGE_NET_OK);
    packet = packet_from_frame(frame, sizeof(frame), 375u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_OK);
    assert(container2_endpoint.receives == receives_before + 1u);
    edge_net_packet_release(&packet);
    assert(edge_net_bridge_vlan_filtering_set(10, 0) == EDGE_NET_OK);

    assert(edge_net_device_set_link(
               12, 0u, EDGE_NET_DEVICE_FLAG_UP, 0u, 0) == EDGE_NET_OK);
    packet = packet_from_frame(frame, sizeof(frame), 400u);
    assert(edge_net_device_transmit(12, &packet) == EDGE_NET_LINK_DOWN);
    edge_net_packet_release(&packet);
    assert(edge_net_device_set_link(
               12, EDGE_NET_DEVICE_FLAG_UP, EDGE_NET_DEVICE_FLAG_UP,
               0u, 0) == EDGE_NET_OK);

    assert(edge_net_device_move(14, 3u) == EDGE_NET_OK);
    assert(edge_net_device_snapshot(14, &snapshot) == EDGE_NET_OK);
    assert(snapshot.configuration.network_namespace == 3u);
    assert(snapshot.configuration.tx_queue_length == 1000u);
    assert(edge_net_device_set_tx_queue_length(14, 2048u) == EDGE_NET_OK);
    assert(edge_net_device_snapshot(14, &snapshot) == EDGE_NET_OK);
    assert(snapshot.configuration.tx_queue_length == 2048u);
    assert(snapshot.master_ifindex == 0);
    assert(edge_net_device_rename(14, 3u, "renamed0") == EDGE_NET_OK);
    assert(edge_net_device_find(3u, "renamed0", &ifindex) == EDGE_NET_OK);
    assert(ifindex == 14);

    assert(edge_net_namespace_destroy(3u) == EDGE_NET_OK);
    assert(edge_net_device_snapshot(14, &snapshot) == EDGE_NET_NOT_FOUND);
    assert(edge_net_device_unregister(11) == EDGE_NET_OK);
    assert(edge_net_device_snapshot(12, &snapshot) == EDGE_NET_NOT_FOUND);
    assert(edge_net_device_unregister(10) == EDGE_NET_OK);

    {
        static const uint8_t lower_mac[6] = {
            0x02u, 0x42u, 0, 0, 0, 0x20u
        };
        test_endpoint_t lower_endpoint;
        test_endpoint_t vlan_endpoint;
        edge_net_device_configuration_t lower;
        edge_net_device_configuration_t vlan;
        edge_net_device_configuration_t dummy;
        edge_net_qdisc_configuration_t qdisc_configuration;
        edge_net_qdisc_snapshot_t qdisc_snapshot;
        edge_net_packet_t clone;
        uint8_t tagged_frame[68];
        uint32_t releases_before_clone = release_count;

        memset(&lower_endpoint, 0, sizeof(lower_endpoint));
        memset(&vlan_endpoint, 0, sizeof(vlan_endpoint));
        lower = configuration(
            20, 0u, EDGE_NET_DEVICE_PHYSICAL, "lower0",
            lower_mac, &lower_endpoint);
        vlan = configuration(
            21, 0u, EDGE_NET_DEVICE_VLAN, "lower0.123",
            lower_mac, &vlan_endpoint);
        vlan.lower_ifindex = 20;
        vlan.vlan_id = 123u;
        vlan.vlan_protocol = 0x8100u;
        dummy = configuration(
            22, 0u, EDGE_NET_DEVICE_DUMMY, "dummy0",
            lower_mac, 0);
        assert(edge_net_device_register(&lower) == EDGE_NET_OK);
        assert(edge_net_device_register(&vlan) == EDGE_NET_OK);
        assert(edge_net_device_register(&dummy) == EDGE_NET_OK);

        memset(frame, 0, sizeof(frame));
        memcpy(frame, broadcast, 6u);
        memcpy(frame + 6u, lower_mac, 6u);
        frame[12] = 0x08u;
        frame[13] = 0x00u;
        packet = packet_from_frame(frame, sizeof(frame), 500u);
        assert(edge_net_packet_clone(&clone, &packet) == EDGE_NET_OK);
        edge_net_packet_release(&packet);
        assert(release_count == releases_before_clone);
        assert(edge_net_device_transmit(21, &clone) == EDGE_NET_OK);
        assert(lower_endpoint.transmits == 1u);
        assert(lower_endpoint.bytes == sizeof(tagged_frame));
        assert(memcmp(lower_endpoint.last_frame, frame, 12u) == 0);
        assert(lower_endpoint.last_frame[12] == 0x81u);
        assert(lower_endpoint.last_frame[13] == 0x00u);
        assert(lower_endpoint.last_frame[14] == 0x00u);
        assert(lower_endpoint.last_frame[15] == 123u);
        assert(lower_endpoint.last_frame[16] == 0x08u);
        assert(lower_endpoint.last_frame[17] == 0x00u);
        assert(memcmp(
                   lower_endpoint.last_frame + 18u,
                   frame + 14u, sizeof(frame) - 14u) == 0);
        edge_net_packet_release(&clone);
        assert(release_count == releases_before_clone + 1u);

        memcpy(tagged_frame, lower_endpoint.last_frame,
               sizeof(tagged_frame));
        packet = packet_from_frame(
            tagged_frame, sizeof(tagged_frame), 600u);
        assert(edge_net_device_receive(20, &packet) == EDGE_NET_OK);
        assert(vlan_endpoint.receives == 1u);
        assert(vlan_endpoint.bytes == sizeof(frame));
        assert(memcmp(vlan_endpoint.last_frame, frame, sizeof(frame)) == 0);
        assert(vlan_endpoint.last_packet_input_ifindex == 21);
        edge_net_packet_release(&packet);

        packet = packet_from_frame(frame, sizeof(frame), 700u);
        assert(edge_net_device_transmit(22, &packet) == EDGE_NET_OK);
        edge_net_packet_release(&packet);
        assert(edge_net_device_snapshot(22, &snapshot) == EDGE_NET_OK);
        assert(snapshot.tx_packets == 1u);
        assert(snapshot.tx_bytes == sizeof(frame));
        assert(snapshot.tx_drops == 0u);

        assert(edge_net_qdisc_snapshot(22, &qdisc_snapshot) == EDGE_NET_OK);
        assert(qdisc_snapshot.configuration.kind ==
               EDGE_NET_QDISC_NOQUEUE);
        memset(&qdisc_configuration, 0, sizeof(qdisc_configuration));
        qdisc_configuration.kind = EDGE_NET_QDISC_BFIFO;
        qdisc_configuration.handle = 0x10000u;
        qdisc_configuration.parent = UINT32_MAX;
        qdisc_configuration.limit = 32u;
        assert(edge_net_qdisc_replace(
                   22, &qdisc_configuration) == EDGE_NET_OK);
        packet = packet_from_frame(frame, sizeof(frame), 710u);
        assert(edge_net_device_transmit(22, &packet) == EDGE_NET_NO_SPACE);
        edge_net_packet_release(&packet);
        assert(edge_net_qdisc_snapshot(22, &qdisc_snapshot) == EDGE_NET_OK);
        assert(qdisc_snapshot.drops == 1u &&
               qdisc_snapshot.packets == 0u &&
               qdisc_snapshot.queue_length == 0u &&
               qdisc_snapshot.backlog == 0u);
        qdisc_configuration.kind = EDGE_NET_QDISC_PFIFO;
        qdisc_configuration.handle = 0x20000u;
        qdisc_configuration.limit = 8u;
        assert(edge_net_qdisc_replace(
                   22, &qdisc_configuration) == EDGE_NET_OK);
        packet = packet_from_frame(frame, sizeof(frame), 720u);
        assert(edge_net_device_transmit(22, &packet) == EDGE_NET_OK);
        edge_net_packet_release(&packet);
        assert(edge_net_qdisc_snapshot(22, &qdisc_snapshot) == EDGE_NET_OK);
        assert(qdisc_snapshot.configuration.kind == EDGE_NET_QDISC_PFIFO &&
               qdisc_snapshot.packets == 1u &&
               qdisc_snapshot.bytes == sizeof(frame) &&
               qdisc_snapshot.queue_length == 0u &&
               qdisc_snapshot.backlog == 0u);
        assert(edge_net_qdisc_delete(22, 0x10000u) == EDGE_NET_NOT_FOUND);
        assert(edge_net_qdisc_delete(22, 0x20000u) == EDGE_NET_OK);
        assert(edge_net_qdisc_snapshot(22, &qdisc_snapshot) == EDGE_NET_OK);
        assert(qdisc_snapshot.configuration.kind ==
               EDGE_NET_QDISC_NOQUEUE);

        assert(edge_net_device_set_carrier(20, 0) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(21, &snapshot) == EDGE_NET_OK);
        assert(snapshot.configuration.carrier == 0u);
        packet = packet_from_frame(frame, sizeof(frame), 800u);
        assert(edge_net_device_transmit(21, &packet) ==
               EDGE_NET_LINK_DOWN);
        edge_net_packet_release(&packet);
        assert(edge_net_device_unregister(20) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(21, &snapshot) ==
               EDGE_NET_NOT_FOUND);
        assert(edge_net_device_unregister(22) == EDGE_NET_OK);
    }

    {
        static const uint8_t lower_mac[6] = {
            0x02u, 0x42u, 0, 0, 0, 0x30u
        };
        static const uint8_t first_mac[6] = {
            0x02u, 0x42u, 0, 0, 0, 0x31u
        };
        static const uint8_t second_mac[6] = {
            0x02u, 0x42u, 0, 0, 0, 0x32u
        };
        test_endpoint_t lower_endpoint;
        test_endpoint_t first_endpoint;
        test_endpoint_t second_endpoint;
        edge_net_device_configuration_t lower;
        edge_net_device_configuration_t first;
        edge_net_device_configuration_t second;

        memset(&lower_endpoint, 0, sizeof(lower_endpoint));
        memset(&first_endpoint, 0, sizeof(first_endpoint));
        memset(&second_endpoint, 0, sizeof(second_endpoint));
        lower = configuration(
            30, 0u, EDGE_NET_DEVICE_PHYSICAL, "mac-lower0",
            lower_mac, &lower_endpoint);
        first = configuration(
            31, 0u, EDGE_NET_DEVICE_MACVLAN, "macvlan0",
            first_mac, &first_endpoint);
        first.lower_ifindex = 30;
        first.virtual_mode = EDGE_NET_MACVLAN_MODE_BRIDGE;
        second = configuration(
            32, 0u, EDGE_NET_DEVICE_MACVLAN, "macvlan1",
            second_mac, &second_endpoint);
        second.lower_ifindex = 30;
        second.virtual_mode = EDGE_NET_MACVLAN_MODE_BRIDGE;
        assert(edge_net_device_register(&lower) == EDGE_NET_OK);
        assert(edge_net_device_register(&first) == EDGE_NET_OK);
        assert(edge_net_device_register(&second) == EDGE_NET_OK);

        memset(frame, 0, sizeof(frame));
        memcpy(frame, second_mac, 6u);
        memcpy(frame + 6u, first_mac, 6u);
        frame[12] = 0x08u;
        frame[13] = 0x00u;
        packet = packet_from_frame(frame, sizeof(frame), 900u);
        assert(edge_net_device_transmit(31, &packet) == EDGE_NET_OK);
        assert(second_endpoint.receives == 1u);
        assert(second_endpoint.last_packet_input_ifindex == 32);
        assert(lower_endpoint.transmits == 0u);
        edge_net_packet_release(&packet);

        memcpy(frame, broadcast, 6u);
        packet = packet_from_frame(frame, sizeof(frame), 1000u);
        assert(edge_net_device_transmit(31, &packet) == EDGE_NET_OK);
        assert(second_endpoint.receives == 2u);
        assert(lower_endpoint.transmits == 1u);
        edge_net_packet_release(&packet);

        memcpy(frame, first_mac, 6u);
        memcpy(frame + 6u, lower_mac, 6u);
        packet = packet_from_frame(frame, sizeof(frame), 1100u);
        assert(edge_net_device_receive(30, &packet) == EDGE_NET_OK);
        assert(first_endpoint.receives == 1u);
        assert(lower_endpoint.receives == 0u);
        edge_net_packet_release(&packet);

        memcpy(frame, lower_mac, 6u);
        packet = packet_from_frame(frame, sizeof(frame), 1200u);
        assert(edge_net_device_receive(30, &packet) == EDGE_NET_OK);
        assert(lower_endpoint.receives == 1u);
        edge_net_packet_release(&packet);

        assert(edge_net_device_set_carrier(30, 0) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(31, &snapshot) == EDGE_NET_OK);
        assert(snapshot.configuration.carrier == 0u);
        assert(edge_net_device_unregister(30) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(31, &snapshot) ==
               EDGE_NET_NOT_FOUND);
        assert(edge_net_device_snapshot(32, &snapshot) ==
               EDGE_NET_NOT_FOUND);
    }

    {
        static const uint8_t lower_mac[6] = {
            0x02u, 0x42u, 0, 0, 0, 0x40u
        };
        static const uint8_t first_address[4] = {10u, 40u, 0u, 2u};
        static const uint8_t second_address[4] = {10u, 40u, 0u, 3u};
        test_endpoint_t lower_endpoint;
        test_endpoint_t first_endpoint;
        test_endpoint_t second_endpoint;
        edge_net_device_configuration_t lower;
        edge_net_device_configuration_t first;
        edge_net_device_configuration_t second;
        uint32_t first_ipv4;
        uint32_t second_ipv4;

        memcpy(&first_ipv4, first_address, sizeof(first_ipv4));
        memcpy(&second_ipv4, second_address, sizeof(second_ipv4));
        memset(&lower_endpoint, 0, sizeof(lower_endpoint));
        memset(&first_endpoint, 0, sizeof(first_endpoint));
        memset(&second_endpoint, 0, sizeof(second_endpoint));
        lower = configuration(
            40, 0u, EDGE_NET_DEVICE_PHYSICAL, "ip-lower0",
            lower_mac, &lower_endpoint);
        first = configuration(
            41, 0u, EDGE_NET_DEVICE_IPVLAN, "ipvlan0",
            lower_mac, &first_endpoint);
        first.lower_ifindex = 40;
        first.virtual_mode = EDGE_NET_IPVLAN_MODE_L2;
        first.virtual_flags = EDGE_NET_IPVLAN_FLAG_BRIDGE;
        second = configuration(
            42, 0u, EDGE_NET_DEVICE_IPVLAN, "ipvlan1",
            lower_mac, &second_endpoint);
        second.lower_ifindex = 40;
        second.virtual_mode = EDGE_NET_IPVLAN_MODE_L2;
        second.virtual_flags = EDGE_NET_IPVLAN_FLAG_BRIDGE;
        assert(edge_net_device_register(&lower) == EDGE_NET_OK);
        assert(edge_net_device_register(&first) == EDGE_NET_OK);
        assert(edge_net_device_register(&second) == EDGE_NET_OK);
        assert(edge_net_device_set_ipv4(41, first_ipv4, 24u, 0u) ==
               EDGE_NET_OK);
        assert(edge_net_device_set_ipv4(42, second_ipv4, 24u, 0u) ==
               EDGE_NET_OK);

        memset(frame, 0, sizeof(frame));
        memcpy(frame, lower_mac, 6u);
        memcpy(frame + 6u, lower_mac, 6u);
        frame[12] = 0x08u;
        frame[13] = 0x00u;
        frame[14] = 0x45u;
        memcpy(frame + 26u, first_address, sizeof(first_address));
        memcpy(frame + 30u, second_address, sizeof(second_address));
        packet = packet_from_frame(frame, sizeof(frame), 1300u);
        assert(edge_net_device_transmit(41, &packet) == EDGE_NET_OK);
        assert(second_endpoint.receives == 1u);
        assert(second_endpoint.last_packet_input_ifindex == 42);
        assert(lower_endpoint.transmits == 0u);
        edge_net_packet_release(&packet);

        packet = packet_from_frame(frame, sizeof(frame), 1400u);
        assert(edge_net_device_receive(40, &packet) == EDGE_NET_OK);
        assert(second_endpoint.receives == 2u);
        assert(lower_endpoint.receives == 0u);
        edge_net_packet_release(&packet);

        memcpy(frame + 30u, "\x0a\x28\x00\x09", 4u);
        packet = packet_from_frame(frame, sizeof(frame), 1500u);
        assert(edge_net_device_transmit(41, &packet) == EDGE_NET_OK);
        assert(lower_endpoint.transmits == 1u);
        edge_net_packet_release(&packet);

        assert(edge_net_device_set_carrier(40, 0) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(41, &snapshot) == EDGE_NET_OK);
        assert(snapshot.configuration.carrier == 0u);
        assert(edge_net_device_unregister(40) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(41, &snapshot) ==
               EDGE_NET_NOT_FOUND);
        assert(edge_net_device_snapshot(42, &snapshot) ==
               EDGE_NET_NOT_FOUND);
    }

    {
        static const uint8_t bond_mac[6] = {
            0x02u, 0x42u, 0, 0, 0, 0x50u
        };
        static const uint8_t first_mac[6] = {
            0x02u, 0x42u, 0, 0, 0, 0x51u
        };
        static const uint8_t second_mac[6] = {
            0x02u, 0x42u, 0, 0, 0, 0x52u
        };
        test_endpoint_t bond_endpoint;
        test_endpoint_t first_endpoint;
        test_endpoint_t second_endpoint;
        edge_net_device_configuration_t bond;
        edge_net_device_configuration_t first;
        edge_net_device_configuration_t second;

        memset(&bond_endpoint, 0, sizeof(bond_endpoint));
        memset(&first_endpoint, 0, sizeof(first_endpoint));
        memset(&second_endpoint, 0, sizeof(second_endpoint));
        bond = configuration(
            50, 0u, EDGE_NET_DEVICE_BOND, "bond0",
            bond_mac, &bond_endpoint);
        bond.virtual_mode = EDGE_NET_BOND_MODE_ACTIVE_BACKUP;
        bond.virtual_flags = EDGE_NET_BOND_HASH_LAYER2;
        first = configuration(
            51, 0u, EDGE_NET_DEVICE_PHYSICAL, "bond-port0",
            first_mac, &first_endpoint);
        second = configuration(
            52, 0u, EDGE_NET_DEVICE_PHYSICAL, "bond-port1",
            second_mac, &second_endpoint);
        assert(edge_net_device_register(&bond) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(50, &snapshot) == EDGE_NET_OK);
        assert(snapshot.configuration.carrier == 0u);
        assert(edge_net_device_register(&first) == EDGE_NET_OK);
        assert(edge_net_device_register(&second) == EDGE_NET_OK);
        assert(edge_net_device_set_master(51, 50) == EDGE_NET_OK);
        assert(edge_net_device_set_master(52, 50) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(50, &snapshot) == EDGE_NET_OK);
        assert(snapshot.configuration.carrier == 1u);

        memset(frame, 0, sizeof(frame));
        memcpy(frame, broadcast, 6u);
        memcpy(frame + 6u, bond_mac, 6u);
        frame[12] = 0x08u;
        frame[13] = 0x00u;
        packet = packet_from_frame(frame, sizeof(frame), 1600u);
        assert(edge_net_device_transmit(50, &packet) == EDGE_NET_OK);
        assert(first_endpoint.transmits == 1u);
        assert(second_endpoint.transmits == 0u);
        edge_net_packet_release(&packet);

        assert(edge_net_device_set_carrier(51, 0) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(50, &snapshot) == EDGE_NET_OK);
        assert(snapshot.configuration.carrier == 1u);
        packet = packet_from_frame(frame, sizeof(frame), 1700u);
        assert(edge_net_device_transmit(50, &packet) == EDGE_NET_OK);
        assert(first_endpoint.transmits == 1u);
        assert(second_endpoint.transmits == 1u);
        edge_net_packet_release(&packet);

        packet = packet_from_frame(frame, sizeof(frame), 1800u);
        assert(edge_net_device_receive(52, &packet) == EDGE_NET_OK);
        assert(bond_endpoint.receives == 1u);
        assert(bond_endpoint.last_packet_input_ifindex == 50);
        edge_net_packet_release(&packet);

        assert(edge_net_device_set_master(52, 0) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(50, &snapshot) == EDGE_NET_OK);
        assert(snapshot.configuration.carrier == 0u);
        packet = packet_from_frame(frame, sizeof(frame), 1900u);
        assert(edge_net_device_transmit(50, &packet) ==
               EDGE_NET_LINK_DOWN);
        edge_net_packet_release(&packet);
        assert(edge_net_device_unregister(51) == EDGE_NET_OK);
        assert(edge_net_device_unregister(52) == EDGE_NET_OK);
        assert(edge_net_device_unregister(50) == EDGE_NET_OK);
    }

    puts("network core unit tests passed");
    return 0;
}
