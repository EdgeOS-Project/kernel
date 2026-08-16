/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux netlink policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_NETLINK_H
#define EDGEOS_KERNEL_LINUX_NETLINK_H

#include <stdint.h>

#include "kernel/socket_runtime.h"
#include "net/network_core.h"

typedef int (*edge_linux_netlink_kernel_request_fn)(
    void *context, const void *payload, uint32_t length);

typedef int (*edge_linux_rtnetlink_ipv4_update_fn)(
    int32_t ifindex, uint32_t network_namespace,
    uint32_t address, uint8_t prefix_length, int active);

typedef struct edge_linux_rtnetlink_ipv4_neighbor {
    uint32_t address;
    int32_t ifindex;
    uint8_t hardware_address[6];
    uint16_t state;
    uint8_t flags;
} edge_linux_rtnetlink_ipv4_neighbor_t;

typedef struct edge_linux_rtnetlink_ipv4_provider {
    int (*neighbor_at)(uint32_t network_namespace, int ordinal,
                       edge_linux_rtnetlink_ipv4_neighbor_t *neighbor);
    int (*configure_neighbor)(uint32_t network_namespace, int32_t ifindex,
                              uint32_t address,
                              const uint8_t hardware_address[6],
                              uint16_t state, uint8_t flags, int active);
} edge_linux_rtnetlink_ipv4_provider_t;

typedef struct edge_linux_rtnetlink_ipv6_address {
    uint8_t address[16];
    uint8_t prefix_length;
    uint8_t scope;
    uint32_t flags;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
} edge_linux_rtnetlink_ipv6_address_t;

typedef struct edge_linux_rtnetlink_ipv6_router {
    uint8_t address[16];
    uint32_t lifetime;
    uint8_t preference;
} edge_linux_rtnetlink_ipv6_router_t;

typedef struct edge_linux_rtnetlink_ipv6_neighbor {
    uint8_t address[16];
    uint8_t hardware_address[6];
    uint16_t state;
    uint8_t is_router;
} edge_linux_rtnetlink_ipv6_neighbor_t;

typedef struct edge_linux_rtnetlink_ipv6_provider {
    int (*address_at)(int ordinal,
                      edge_linux_rtnetlink_ipv6_address_t *address);
    int (*configure_address)(uint32_t network_namespace, int32_t ifindex,
                             const uint8_t address[16],
                             uint8_t prefix_length, uint32_t flags,
                             uint32_t valid_lifetime,
                             uint32_t preferred_lifetime, int active);
    void (*synchronize_links)(void);
    void (*remove_interface)(uint32_t network_namespace, int32_t ifindex);
    int (*router_at)(int ordinal,
                     edge_linux_rtnetlink_ipv6_router_t *router);
    int (*configure_default_router)(const uint8_t address[16], int active);
    int (*neighbor_at)(int ordinal,
                       edge_linux_rtnetlink_ipv6_neighbor_t *neighbor);
} edge_linux_rtnetlink_ipv6_provider_t;

enum edge_linux_netfilter_translation {
    EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION = 1,
    EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE = 2
};

typedef struct edge_linux_netfilter_tuple {
    uint32_t network_namespace;
    int32_t input_ifindex;
    int32_t output_ifindex;
    uint8_t family;
    uint8_t protocol;
    char input_interface[16];
    char output_interface[16];
    uint8_t source_address[16];
    uint8_t destination_address[16];
    uint16_t source_port;
    uint16_t destination_port;
} edge_linux_netfilter_tuple_t;

typedef struct edge_linux_conntrack_snapshot {
    uint64_t identifier;
    uint64_t packets;
    edge_linux_netfilter_tuple_t original;
    edge_linux_netfilter_tuple_t translated;
} edge_linux_conntrack_snapshot_t;

typedef struct edge_linux_route_query {
    uint32_t network_namespace;
    uint8_t family;
    uint8_t source[16];
    uint8_t destination[16];
    uint32_t mark;
    int32_t input_ifindex;
    int32_t output_ifindex;
    uint32_t uid;
} edge_linux_route_query_t;

typedef struct edge_linux_route_result {
    uint32_t table;
    uint32_t priority;
    uint32_t metric;
    int32_t output_ifindex;
    uint8_t family;
    uint8_t type;
    uint8_t scope;
    uint8_t prefix_length;
    uint8_t gateway[16];
    uint8_t preferred_source[16];
} edge_linux_route_result_t;

typedef struct edge_linux_network_interface_snapshot {
    char name[16];
    int32_t ifindex;
    uint32_t flags;
    uint32_t mtu;
    uint32_t tx_queue_length;
    uint32_t ipv4_address;
    uint32_t ipv4_gateway;
    uint8_t ipv4_prefix_length;
    uint8_t carrier;
    uint16_t hardware_type;
    uint8_t hardware_address[6];
} edge_linux_network_interface_snapshot_t;

/*
 * Routes one already-copied netlink datagram either to the protocol's kernel
 * endpoint or to Linux port/group subscribers.  Architecture runtimes own
 * socket storage and wakeups; destination parsing and protocol policy are
 * shared so sendto(2) and sendmsg(2) behave identically on every architecture.
 */
int edge_linux_netlink_send(
    int32_t descriptor, uint32_t protocol,
    const kernel_socket_address_t *destination,
    const void *payload, uint32_t length,
    void *request_context,
    edge_linux_netlink_kernel_request_fn kernel_request);

/*
 * Builds a Linux netfilter control-plane reply without depending on either
 * architecture's socket storage.  The caller queues the returned datagram in
 * its native socket backend.
 */
int edge_linux_netfilter_respond(
    uint32_t port_id, const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *response_length);

/* Applies one namespace's installed local packet translation rules. */
int edge_linux_netfilter_translate_local(
    edge_linux_netfilter_tuple_t *tuple,
    enum edge_linux_netfilter_translation translation);

/* Applies forwarding-path translation and connection tracking state. */
int edge_linux_netfilter_translate_forward(
    edge_linux_netfilter_tuple_t *tuple,
    enum edge_linux_netfilter_translation translation);

/* Connects the shared nftables evaluator to every network namespace. */
int edge_linux_netfilter_enable_datapath(void);

/* Resolves one Linux xtables extension revision shared by both ABIs. */
int edge_linux_netfilter_extension_revision(
    const char *name, int target, uint8_t requested,
    uint8_t *highest_supported);

/* Publishes the current external IPv4 address used by MASQUERADE rules. */
void edge_linux_netfilter_set_ipv4_masquerade_address(uint32_t address);

/* Returns one live connection owned by the requested network namespace. */
int edge_linux_conntrack_snapshot(
    uint32_t network_namespace, uint32_t ordinal,
    edge_linux_conntrack_snapshot_t *snapshot);

/* Namespace-aware variant used by architecture socket runtimes. */
int edge_linux_netfilter_respond_in_namespace(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *response_length);

/* Applies architecture-independent dynamic link and address mutations. */
int edge_linux_rtnetlink_apply(
    uint32_t network_namespace, const void *payload, uint32_t length,
    int *handled);

/* Publishes bridge IPv4 changes to the shared network stack. */
void edge_linux_rtnetlink_set_ipv4_update_callback(
    edge_linux_rtnetlink_ipv4_update_fn callback);

/* Connects IPv4 neighbor discovery and static entries to rtnetlink. */
void edge_linux_rtnetlink_set_ipv4_provider(
    const edge_linux_rtnetlink_ipv4_provider_t *provider);

/* Connects the shared Linux route ABI to the active IPv6 data plane. */
void edge_linux_rtnetlink_set_ipv6_provider(
    const edge_linux_rtnetlink_ipv6_provider_t *provider);

/* Returns nonzero when a dynamic link owns the supplied IPv4 address. */
int edge_linux_rtnetlink_ipv4_is_local(uint32_t address);
int edge_linux_rtnetlink_ipv4_is_local_in_namespace(
    uint32_t network_namespace, uint32_t address);

/* Returns the primary IPv4 address assigned inside one network namespace. */
int edge_linux_rtnetlink_ipv4_primary(
    uint32_t network_namespace, uint32_t *address);

/* Returns the network namespace that owns one dynamic IPv4 address. */
int edge_linux_rtnetlink_ipv4_owner(
    uint32_t address, uint32_t *network_namespace);

/* Releases all shared network state owned by a departed namespace. */
void edge_linux_network_namespace_destroy(uint32_t network_namespace);

/* Appends dynamic links that match an RTM_GETLINK request. */
int edge_linux_rtnetlink_append_links(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count);

/* Appends IPv4 addresses owned by dynamic links. */
int edge_linux_rtnetlink_append_addresses(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count);

/* Appends a connected IPv4 route owned by a dynamic link. */
int edge_linux_rtnetlink_append_route(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count);

/* Appends policy-routing rules that match an RTM_GETRULE request. */
int edge_linux_rtnetlink_append_rules(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count);

/* Appends modern nexthop objects and weighted groups. */
int edge_linux_rtnetlink_append_nexthops(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count);

/* Resolves installed rules and routes using shared longest-prefix policy. */
int edge_linux_route_lookup(
    const edge_linux_route_query_t *query,
    edge_linux_route_result_t *result);

/* Returns one shared dynamic interface visible in a network namespace. */
int edge_linux_network_interface_by_name(
    uint32_t network_namespace, const char *name,
    edge_linux_network_interface_snapshot_t *snapshot);
int edge_linux_network_interface_by_index(
    uint32_t network_namespace, int32_t ifindex,
    edge_linux_network_interface_snapshot_t *snapshot);
int edge_linux_network_interface_at(
    uint32_t network_namespace, uint32_t ordinal,
    edge_linux_network_interface_snapshot_t *snapshot);

/* Applies legacy interface configuration through the shared device model. */
int edge_linux_network_interface_configure(
    uint32_t network_namespace, int32_t ifindex,
    uint32_t flags, uint32_t change, uint32_t mtu, int set_mtu,
    uint32_t tx_queue_length, int set_tx_queue_length);
int edge_linux_network_interface_configure_ipv4(
    uint32_t network_namespace, int32_t ifindex,
    uint32_t address, uint8_t prefix_length, uint32_t gateway);

/* Registers and removes shared TUN/TAP interfaces for /dev/net/tun. */
int edge_linux_network_tuntap_create(
    uint32_t network_namespace, const char *name,
    enum edge_net_device_kind kind, edge_net_receive_fn receive,
    edge_net_transmit_fn transmit, void *context,
    int32_t requested_ifindex, int32_t *ifindex);
int edge_linux_network_tuntap_destroy(
    uint32_t network_namespace, int32_t ifindex);

/* Appends IPv6 neighbors owned by the active shared data plane. */
int edge_linux_rtnetlink_append_neighbors(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count);

/* Appends bridge multicast database entries visible in one namespace. */
int edge_linux_rtnetlink_append_mdb(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count);

/* Appends root queueing disciplines for interfaces in one namespace. */
int edge_linux_rtnetlink_append_qdiscs(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count);

#endif
