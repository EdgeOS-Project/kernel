#ifndef NET_LWIP_STACK_H
#define NET_LWIP_STACK_H

#include "net/netdev.h"

#include <stdint.h>

struct netif;

void lwip_stack_init(void);
void lwip_stack_poll(void);
void lwip_stack_core_enter(void);
void lwip_stack_core_exit(void);
int lwip_stack_is_ready(void);
int lwip_stack_bind_netdev(edge_netdev_handle_t handle);
int lwip_stack_unbind_netdev(edge_netdev_handle_t handle);
edge_netdev_handle_t lwip_stack_get_netdev(void);
int lwip_stack_configure_ipv4(uint32_t addr_be, uint32_t netmask_be, uint32_t gw_be);
int lwip_stack_configure_local_ipv4_alias(
    int32_t ifindex, uint32_t network_namespace,
    uint32_t addr_be, uint8_t prefix_length, int active);
int lwip_stack_get_ipv4(uint32_t *addr_be, uint32_t *netmask_be, uint32_t *gw_be);
int lwip_stack_get_ipv4_neighbor(int ordinal, uint32_t *addr_be,
                                 uint8_t mac_out[6], int *ifindex_out);
int lwip_stack_get_mac(uint8_t mac_out[6]);
int lwip_stack_set_link_state(int up);
int lwip_stack_get_link_state(void);
int lwip_stack_set_mtu(uint16_t mtu);
uint16_t lwip_stack_get_mtu(void);
int lwip_stack_send_packet_frame(const void *frame, uint16_t len);
int lwip_stack_recv_packet_frame(uint8_t *frame_out, uint32_t *len_out);
int lwip_stack_packet_frame_pending(void);
/* Nonzero generation of successfully published generic receive frames. */
uint64_t lwip_stack_packet_frame_readiness_sequence(void);
int lwip_stack_send_raw_ipv4(const uint8_t *packet, uint16_t len);
struct netif *lwip_stack_select_socket_route(
    uint32_t network_namespace, uint8_t family,
    const uint8_t source[16], const uint8_t destination[16],
    uint32_t mark, int32_t bound_ifindex,
    uint8_t preferred_source[16], int32_t *selected_ifindex);
int lwip_stack_send_icmp_echo(
    uint32_t network_namespace, uint32_t dst_ip_be,
    const uint8_t *icmp_payload, uint16_t icmp_len, uint8_t ttl);
int lwip_stack_recv_icmp_reply_for_id(uint16_t id_be, uint8_t *ip_packet_out, uint32_t *ip_packet_len, uint32_t *src_ip_be);
int lwip_stack_recv_icmp_packet(uint8_t *ip_packet_out, uint32_t *ip_packet_len, uint32_t *src_ip_be);
int lwip_stack_icmp_reply_pending_for_id(uint16_t id_be);
int lwip_stack_icmp_packet_pending(void);
/* Nonzero generation shared by published IPv4 and IPv6 ICMP records. */
uint64_t lwip_stack_icmp_readiness_sequence(void);
int lwip_stack_send_icmpv6_echo(
    uint32_t network_namespace, const uint8_t dst_ip6[16],
    const uint8_t *icmp_payload, uint16_t icmp_len, uint8_t hop_limit);
int lwip_stack_recv_icmpv6_reply_for_id(uint16_t id_be, uint8_t *packet_out, uint32_t *packet_len, uint8_t src_ip6_out[16]);
int lwip_stack_icmpv6_reply_pending_for_id(uint16_t id_be);
int lwip_stack_get_ipv6_addr(uint8_t out[16], int prefer_global);
int lwip_stack_get_ipv6_addr_at(int ordinal, uint8_t out[16], uint8_t *prefix_len, uint8_t *scope, uint8_t *flags);
int lwip_stack_configure_ipv6(const uint8_t address[16],
                              uint8_t prefix_length, int active);
int lwip_stack_configure_interface_ipv6(
    int32_t ifindex, uint32_t network_namespace,
    const uint8_t address[16], uint8_t prefix_length,
    uint32_t flags, uint32_t valid_lifetime,
    uint32_t preferred_lifetime, int active);
int lwip_stack_get_ipv6_router(int ordinal, uint8_t address[16],
                               uint32_t *lifetime, uint8_t *preference);
int lwip_stack_configure_ipv6_default_router(const uint8_t address[16],
                                              int active);
int lwip_stack_get_ipv6_neighbor(int ordinal, uint8_t address[16],
                                 uint8_t hardware_address[6],
                                 uint16_t *state, uint8_t *is_router);

typedef enum {
    LWIP_IPV6_SETTING_DISABLE = 0,
    LWIP_IPV6_SETTING_FORWARDING = 1,
    LWIP_IPV6_SETTING_ACCEPT_RA = 2,
    LWIP_IPV6_SETTING_AUTOCONF = 3
} lwip_ipv6_setting_t;

typedef enum {
    LWIP_IPV6_SCOPE_ALL = 0,
    LWIP_IPV6_SCOPE_DEFAULT = 1,
    LWIP_IPV6_SCOPE_ETH0 = 2,
    LWIP_IPV6_SCOPE_INTERFACE_BASE = 0x10000
} lwip_ipv6_scope_t;

#define LWIP_IPV6_SCOPE_FOR_IFINDEX(ifindex) \
    ((lwip_ipv6_scope_t)(LWIP_IPV6_SCOPE_INTERFACE_BASE + (ifindex)))

typedef struct {
    uint64_t in_receives;
    uint64_t in_header_errors;
    uint64_t in_no_routes;
    uint64_t in_unknown_protocols;
    uint64_t in_discards;
    uint64_t in_delivers;
    uint64_t out_forwards;
    uint64_t out_requests;
    uint64_t out_discards;
    uint64_t out_no_routes;
    uint64_t reassembly_requests;
    uint64_t reassembly_failures;
    uint64_t fragments_created;
    uint64_t icmp_in_messages;
    uint64_t icmp_in_errors;
    uint64_t icmp_out_messages;
    uint64_t icmp_out_errors;
} lwip_stack_ipv6_stats_t;

int lwip_stack_ipv6_setting_get(lwip_ipv6_scope_t scope,
                                lwip_ipv6_setting_t setting);
int lwip_stack_ipv6_setting_set(lwip_ipv6_scope_t scope,
                                lwip_ipv6_setting_t setting, int value);
int lwip_stack_ipv6_setting_get_in_namespace(
    uint32_t network_namespace, lwip_ipv6_scope_t scope,
    lwip_ipv6_setting_t setting);
int lwip_stack_ipv6_setting_set_in_namespace(
    uint32_t network_namespace, lwip_ipv6_scope_t scope,
    lwip_ipv6_setting_t setting, int value);
int lwip_stack_get_ipv6_stats(lwip_stack_ipv6_stats_t *stats);
void lwip_stack_get_link_stats(uint64_t *rx_packets, uint64_t *rx_bytes, uint64_t *tx_packets, uint64_t *tx_bytes);
int lwip_stack_tcp_rx_fin_seen_v4(uint32_t local_ip_be, uint16_t local_port,
                                  uint32_t remote_ip_be, uint16_t remote_port,
                                  uint32_t *counter_out);
int lwip_stack_reload_system_config(void);
int lwip_stack_set_hostname(const char *name);
const char *lwip_stack_get_hostname(void);

#endif
