/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent network device and packet core.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_NET_NETWORK_CORE_H
#define EDGEOS_NET_NETWORK_CORE_H

#include <stdint.h>

#define EDGE_NET_PACKET_SEGMENT_MAX 16u
#define EDGE_NET_DEVICE_NAME_MAX 16u
#define EDGE_NET_DEVICE_MAX 128u
#define EDGE_NET_BRIDGE_VLAN_MAX 4094u
#define EDGE_NET_NAMESPACE_MAX 128u
#define EDGE_NET_BRIDGE_FDB_MAX 256u
#define EDGE_NET_BRIDGE_MDB_MAX 256u
#define EDGE_NET_HOOK_MAX 32u
#define EDGE_NET_BRIDGE_PORT_STATE 0x0001u
#define EDGE_NET_BRIDGE_PORT_HAIRPIN 0x0002u
#define EDGE_NET_BRIDGE_PORT_LEARNING 0x0004u
#define EDGE_NET_BRIDGE_PORT_UNICAST_FLOOD 0x0008u
#define EDGE_NET_BRIDGE_PORT_MULTICAST_FLOOD 0x0010u
#define EDGE_NET_BRIDGE_PORT_BROADCAST_FLOOD 0x0020u
#define EDGE_NET_BRIDGE_PORT_ISOLATED 0x0040u
#define EDGE_NET_BRIDGE_STATE_DISABLED 0u
#define EDGE_NET_BRIDGE_STATE_LISTENING 1u
#define EDGE_NET_BRIDGE_STATE_LEARNING 2u
#define EDGE_NET_BRIDGE_STATE_FORWARDING 3u
#define EDGE_NET_BRIDGE_STATE_BLOCKING 4u
#define EDGE_NET_NAMESPACE_ALL UINT32_MAX

#define EDGE_NET_DEVICE_FLAG_UP 0x00000001u
#define EDGE_NET_DEVICE_FLAG_BROADCAST 0x00000002u
#define EDGE_NET_DEVICE_FLAG_LOOPBACK 0x00000008u
#define EDGE_NET_DEVICE_FLAG_RUNNING 0x00000040u
#define EDGE_NET_DEVICE_FLAG_MULTICAST 0x00001000u

enum edge_net_result {
    EDGE_NET_OK = 0,
    EDGE_NET_INVALID = -1,
    EDGE_NET_NOT_FOUND = -2,
    EDGE_NET_EXISTS = -3,
    EDGE_NET_NO_SPACE = -4,
    EDGE_NET_LINK_DOWN = -5,
    EDGE_NET_MESSAGE_TOO_LARGE = -6,
    EDGE_NET_WRONG_NAMESPACE = -7,
    EDGE_NET_NOT_SUPPORTED = -8,
    EDGE_NET_BUSY = -9
};

enum edge_net_device_kind {
    EDGE_NET_DEVICE_LOOPBACK = 1,
    EDGE_NET_DEVICE_PHYSICAL = 2,
    EDGE_NET_DEVICE_VETH = 3,
    EDGE_NET_DEVICE_BRIDGE = 4,
    EDGE_NET_DEVICE_TUN = 5,
    EDGE_NET_DEVICE_TAP = 6,
    EDGE_NET_DEVICE_VLAN = 7,
    EDGE_NET_DEVICE_DUMMY = 8,
    EDGE_NET_DEVICE_MACVLAN = 9,
    EDGE_NET_DEVICE_IPVLAN = 10,
    EDGE_NET_DEVICE_BOND = 11,
    EDGE_NET_DEVICE_VRF = 12
};

enum edge_net_bond_mode {
    EDGE_NET_BOND_MODE_ROUND_ROBIN = 0,
    EDGE_NET_BOND_MODE_ACTIVE_BACKUP = 1,
    EDGE_NET_BOND_MODE_XOR = 2,
    EDGE_NET_BOND_MODE_BROADCAST = 3
};

enum edge_net_bond_hash_policy {
    EDGE_NET_BOND_HASH_LAYER2 = 0,
    EDGE_NET_BOND_HASH_LAYER34 = 1,
    EDGE_NET_BOND_HASH_LAYER23 = 2,
    EDGE_NET_BOND_HASH_ENCAP23 = 3,
    EDGE_NET_BOND_HASH_ENCAP34 = 4,
    EDGE_NET_BOND_HASH_VLAN_SRCMAC = 5
};

enum edge_net_macvlan_mode {
    EDGE_NET_MACVLAN_MODE_PRIVATE = 1,
    EDGE_NET_MACVLAN_MODE_VEPA = 2,
    EDGE_NET_MACVLAN_MODE_BRIDGE = 4,
    EDGE_NET_MACVLAN_MODE_PASSTHRU = 8
};

enum edge_net_ipvlan_mode {
    EDGE_NET_IPVLAN_MODE_L2 = 0,
    EDGE_NET_IPVLAN_MODE_L3 = 1,
    EDGE_NET_IPVLAN_MODE_L3S = 2
};

enum edge_net_ipvlan_flags {
    EDGE_NET_IPVLAN_FLAG_BRIDGE = 0,
    EDGE_NET_IPVLAN_FLAG_PRIVATE = 1,
    EDGE_NET_IPVLAN_FLAG_VEPA = 2
};

enum edge_net_qdisc_kind {
    EDGE_NET_QDISC_NOQUEUE = 0,
    EDGE_NET_QDISC_PFIFO = 1,
    EDGE_NET_QDISC_BFIFO = 2
};

enum edge_net_packet_checksum_state {
    EDGE_NET_CHECKSUM_NONE = 0,
    EDGE_NET_CHECKSUM_COMPLETE = 1,
    EDGE_NET_CHECKSUM_PARTIAL = 2,
    EDGE_NET_CHECKSUM_UNNECESSARY = 3
};

enum edge_net_hook_stage {
    EDGE_NET_HOOK_INGRESS = 0,
    EDGE_NET_HOOK_LOCAL_INPUT = 1,
    EDGE_NET_HOOK_FORWARD = 2,
    EDGE_NET_HOOK_LOCAL_OUTPUT = 3,
    EDGE_NET_HOOK_EGRESS = 4
};

enum edge_net_hook_verdict {
    EDGE_NET_VERDICT_DROP = 0,
    EDGE_NET_VERDICT_ACCEPT = 1,
    EDGE_NET_VERDICT_STOLEN = 2,
    EDGE_NET_VERDICT_QUEUE = 3,
    EDGE_NET_VERDICT_REPEAT = 4
};

typedef struct edge_net_packet_segment {
    const uint8_t *data;
    uint32_t length;
} edge_net_packet_segment_t;

typedef struct edge_net_packet_metadata {
    uint32_t network_namespace;
    int32_t input_ifindex;
    int32_t output_ifindex;
    uint32_t mark;
    uint32_t priority;
    uint16_t protocol;
    uint16_t vlan_id;
    uint16_t vlan_protocol;
    uint16_t mac_header;
    uint16_t network_header;
    uint16_t transport_header;
    uint8_t checksum_state;
    uint8_t route_type;
    uint8_t vlan_priority;
    uint8_t vlan_tag_present;
    uint8_t vlan_untagged;
    uint8_t bridge_path;
    uint64_t timestamp_ns;
} edge_net_packet_metadata_t;

typedef void (*edge_net_packet_release_fn)(void *context);

typedef struct edge_net_packet {
    volatile uint32_t references;
    uint32_t total_length;
    uint8_t segment_count;
    edge_net_packet_metadata_t metadata;
    edge_net_packet_segment_t segments[EDGE_NET_PACKET_SEGMENT_MAX];
    edge_net_packet_release_fn release;
    void *release_context;
} edge_net_packet_t;

typedef enum edge_net_hook_verdict (*edge_net_hook_fn)(
    enum edge_net_hook_stage stage, edge_net_packet_t *packet,
    void *context);

typedef struct edge_net_hook_registration {
    uint32_t network_namespace;
    enum edge_net_hook_stage stage;
    int32_t priority;
    edge_net_hook_fn callback;
    void *context;
} edge_net_hook_registration_t;

typedef void (*edge_net_receive_fn)(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context);

typedef void (*edge_net_transmit_fn)(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context);

typedef struct edge_net_device_configuration {
    int32_t ifindex;
    uint32_t network_namespace;
    enum edge_net_device_kind kind;
    uint32_t flags;
    uint32_t mtu;
    uint32_t tx_queue_length;
    uint8_t carrier;
    uint8_t hardware_address[6];
    int32_t lower_ifindex;
    uint16_t vlan_id;
    uint16_t vlan_protocol;
    uint16_t virtual_mode;
    uint16_t virtual_flags;
    uint32_t routing_table;
    char name[EDGE_NET_DEVICE_NAME_MAX];
    edge_net_receive_fn receive;
    edge_net_transmit_fn transmit;
    void *callback_context;
    void *receive_context;
    void *transmit_context;
} edge_net_device_configuration_t;

typedef struct edge_net_device_snapshot {
    edge_net_device_configuration_t configuration;
    int32_t peer_ifindex;
    int32_t master_ifindex;
    uint32_t ipv4_address;
    uint32_t ipv4_gateway;
    uint8_t ipv4_prefix_length;
    uint8_t hairpin;
    uint8_t ipv6_disabled;
    uint8_t ipv6_forwarding;
    uint8_t ipv6_accept_ra;
    uint8_t ipv6_autoconf;
    uint8_t bridge_vlan_filtering;
    uint8_t bridge_state;
    uint8_t bridge_learning;
    uint8_t bridge_unicast_flood;
    uint8_t bridge_multicast_flood;
    uint8_t bridge_broadcast_flood;
    uint8_t bridge_isolated;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_drops;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_drops;
} edge_net_device_snapshot_t;

typedef struct edge_net_qdisc_configuration {
    enum edge_net_qdisc_kind kind;
    uint32_t handle;
    uint32_t parent;
    uint32_t limit;
} edge_net_qdisc_configuration_t;

typedef struct edge_net_qdisc_snapshot {
    edge_net_qdisc_configuration_t configuration;
    uint64_t bytes;
    uint64_t packets;
    uint64_t drops;
    uint32_t queue_length;
    uint32_t backlog;
} edge_net_qdisc_snapshot_t;

typedef struct edge_net_bridge_fdb_entry {
    int32_t bridge_ifindex;
    int32_t port_ifindex;
    uint8_t hardware_address[6];
    uint16_t vlan_id;
    uint8_t is_static;
    uint64_t last_seen_ns;
} edge_net_bridge_fdb_entry_t;

typedef struct edge_net_bridge_vlan_entry {
    int32_t ifindex;
    uint16_t vlan_id;
    uint8_t pvid;
    uint8_t untagged;
} edge_net_bridge_vlan_entry_t;

typedef struct edge_net_bridge_mdb_entry {
    int32_t bridge_ifindex;
    int32_t port_ifindex;
    uint8_t hardware_address[6];
    uint16_t vlan_id;
    uint8_t family;
    uint8_t group_address[16];
    uint8_t is_static;
    uint64_t last_seen_ns;
} edge_net_bridge_mdb_entry_t;

void edge_net_core_reset(void);

int edge_net_packet_initialize(
    edge_net_packet_t *packet, const edge_net_packet_segment_t *segments,
    uint8_t segment_count, const edge_net_packet_metadata_t *metadata,
    edge_net_packet_release_fn release, void *release_context);
int edge_net_packet_retain(edge_net_packet_t *packet);
void edge_net_packet_release(edge_net_packet_t *packet);
int edge_net_packet_clone(
    edge_net_packet_t *clone, edge_net_packet_t *source);
int edge_net_packet_linearize(
    const edge_net_packet_t *packet, void *output, uint32_t capacity);
int edge_net_packet_read(
    const edge_net_packet_t *packet, uint32_t offset,
    void *output, uint32_t length);

int edge_net_hook_register(
    const edge_net_hook_registration_t *registration,
    uint32_t *handle);
int edge_net_hook_unregister(uint32_t handle);

int edge_net_namespace_ensure(uint32_t network_namespace);
int edge_net_namespace_destroy(uint32_t network_namespace);
int edge_net_namespace_ipv4_forwarding_get(
    uint32_t network_namespace, int *enabled);
int edge_net_namespace_ipv4_forwarding_set(
    uint32_t network_namespace, int enabled);
int edge_net_namespace_ipv6_setting_get(
    uint32_t network_namespace, uint32_t setting, int *value);
int edge_net_namespace_ipv6_setting_set(
    uint32_t network_namespace, uint32_t setting, int value);
int edge_net_namespace_bridge_filter_get(
    uint32_t network_namespace, uint32_t family, int *enabled);
int edge_net_namespace_bridge_filter_set(
    uint32_t network_namespace, uint32_t family, int enabled);

int edge_net_device_register(
    const edge_net_device_configuration_t *configuration);
int edge_net_veth_register_pair(
    const edge_net_device_configuration_t *first,
    const edge_net_device_configuration_t *second);
int edge_net_device_unregister(int32_t ifindex);
int edge_net_device_move(int32_t ifindex, uint32_t network_namespace);
int edge_net_device_rename(
    int32_t ifindex, uint32_t network_namespace, const char *name);
int edge_net_device_set_link(
    int32_t ifindex, uint32_t flags, uint32_t change,
    uint32_t mtu, int set_mtu);
int edge_net_device_set_tx_queue_length(
    int32_t ifindex, uint32_t tx_queue_length);
int edge_net_device_set_carrier(int32_t ifindex, int carrier);
int edge_net_device_set_callbacks(
    int32_t ifindex, edge_net_receive_fn receive,
    edge_net_transmit_fn transmit, void *context);
int edge_net_device_set_receive_callback(
    int32_t ifindex, edge_net_receive_fn receive, void *context);
int edge_net_device_set_transmit_callback(
    int32_t ifindex, edge_net_transmit_fn transmit, void *context);
int edge_net_device_set_master(int32_t ifindex, int32_t master_ifindex);
int edge_net_device_set_hairpin(int32_t ifindex, int enabled);
int edge_net_device_set_bridge_port_controls(
    int32_t ifindex, uint32_t mask, uint8_t state, int hairpin,
    int learning, int unicast_flood, int multicast_flood,
    int broadcast_flood, int isolated);
int edge_net_bridge_vlan_filtering_set(int32_t ifindex, int enabled);
int edge_net_bridge_vlan_update(
    int32_t ifindex, uint16_t first_vlan, uint16_t last_vlan,
    int pvid, int untagged, int add);
int edge_net_bridge_vlan_snapshot(
    int32_t ifindex, uint32_t ordinal,
    edge_net_bridge_vlan_entry_t *entry);
int edge_net_device_set_ipv4(
    int32_t ifindex, uint32_t address, uint8_t prefix_length,
    uint32_t gateway);
int edge_net_device_get_ipv6_setting(
    int32_t ifindex, uint32_t setting, int *value);
int edge_net_device_set_ipv6_setting(
    int32_t ifindex, uint32_t setting, int value);
int edge_net_device_snapshot(
    int32_t ifindex, edge_net_device_snapshot_t *snapshot);
int edge_net_route_interface_snapshot(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_device_snapshot_t *snapshot);
int edge_net_device_snapshot_at(
    uint32_t network_namespace, uint32_t ordinal,
    edge_net_device_snapshot_t *snapshot);
int edge_net_device_find(
    uint32_t network_namespace, const char *name, int32_t *ifindex);

int edge_net_qdisc_replace(
    int32_t ifindex,
    const edge_net_qdisc_configuration_t *configuration);
int edge_net_qdisc_delete(int32_t ifindex, uint32_t handle);
int edge_net_qdisc_snapshot(
    int32_t ifindex, edge_net_qdisc_snapshot_t *snapshot);

int edge_net_device_transmit(int32_t ifindex, edge_net_packet_t *packet);
int edge_net_device_receive(int32_t ifindex, edge_net_packet_t *packet);

int edge_net_bridge_fdb_add(
    int32_t bridge_ifindex, const uint8_t hardware_address[6],
    int32_t port_ifindex, int is_static, uint64_t now_ns);
int edge_net_bridge_fdb_add_vlan(
    int32_t bridge_ifindex, const uint8_t hardware_address[6],
    int32_t port_ifindex, uint16_t vlan_id, int is_static,
    uint64_t now_ns);
int edge_net_bridge_fdb_delete(
    int32_t bridge_ifindex, const uint8_t hardware_address[6]);
int edge_net_bridge_fdb_delete_vlan(
    int32_t bridge_ifindex, const uint8_t hardware_address[6],
    uint16_t vlan_id);
int edge_net_bridge_fdb_snapshot(
    int32_t bridge_ifindex, uint32_t ordinal,
    edge_net_bridge_fdb_entry_t *entry);
int edge_net_bridge_mdb_add(
    const edge_net_bridge_mdb_entry_t *entry);
int edge_net_bridge_mdb_delete(
    int32_t bridge_ifindex, int32_t port_ifindex,
    const uint8_t hardware_address[6], uint16_t vlan_id);
int edge_net_bridge_mdb_delete_group(
    int32_t bridge_ifindex, int32_t port_ifindex,
    uint8_t family, const uint8_t *group_address, uint16_t vlan_id);
int edge_net_bridge_mdb_snapshot(
    int32_t bridge_ifindex, uint32_t ordinal,
    edge_net_bridge_mdb_entry_t *entry);
void edge_net_bridge_mdb_age(uint64_t now_ns, uint64_t maximum_age_ns);
void edge_net_bridge_fdb_age(uint64_t now_ns, uint64_t maximum_age_ns);

#endif
