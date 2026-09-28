/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS lwIP integration hooks.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_NET_LWIP_HOOKS_H
#define EDGEOS_NET_LWIP_HOOKS_H

#include <stdint.h>

struct netif;
struct pbuf;

int edge_lwip_packet_input_hook(struct pbuf *packet,
                                struct netif *input_interface);
int edge_lwip_ipv4_local_address_hook(
    struct netif *interface, const void *address);
struct netif *edge_lwip_ipv4_route_hook(const void *destination);
struct netif *edge_lwip_ipv4_route_source_hook(
    const void *source, const void *destination);
struct netif *edge_lwip_ipv6_route_hook(
    const void *source, const void *destination);
const void *edge_lwip_ipv6_gateway_hook(
    struct netif *interface, const void *destination);
int edge_lwip_ipv4_canforward_hook(struct pbuf *packet,
                                   uint32_t destination);

#define LWIP_HOOK_IP4_INPUT(packet, input_interface) \
    edge_lwip_packet_input_hook((packet), (input_interface))
#define LWIP_HOOK_IP6_INPUT(packet, input_interface) \
    edge_lwip_packet_input_hook((packet), (input_interface))
#define LWIP_HOOK_IP4_LOCAL_ADDRESS(interface, address) \
    edge_lwip_ipv4_local_address_hook((interface), (address))
#define LWIP_HOOK_IP4_ROUTE(destination) \
    edge_lwip_ipv4_route_hook((destination))
#define LWIP_HOOK_IP4_ROUTE_SRC(source, destination) \
    edge_lwip_ipv4_route_source_hook((source), (destination))
#define LWIP_HOOK_IP6_ROUTE(source, destination) \
    edge_lwip_ipv6_route_hook((source), (destination))
#define LWIP_HOOK_ND6_GET_GW(interface, destination) \
    edge_lwip_ipv6_gateway_hook((interface), (destination))
#define LWIP_HOOK_IP4_CANFORWARD(packet, destination) \
    edge_lwip_ipv4_canforward_hook((packet), (destination))

#endif
