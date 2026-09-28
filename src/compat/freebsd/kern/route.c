/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD FIB and IPv6 scope bridge backed by the EdgeOS route table. */

#include <stddef.h>
#include <stdint.h>
#include <sys/param.h>

#include "kernel/linux_abi.h"
#include "kernel/linux_netlink.h"
#include <net/if_var.h>
#include <net/route/nhop.h>
#include <netinet/in.h>
#include <netinet/in_fib.h>
#include <netinet6/in6_fib.h>
#include <netinet6/scope6_var.h>
#include <sys/errno.h>

#define BSD_ROUTE_CACHE_INTERFACES 256U
#define BSD_NHF_GATEWAY 0x0200U

struct bsd_route_cache_entry {
    struct nhop_object next_hop;
    struct ifaddr source_address;
    union {
        struct sockaddr_in ipv4;
        struct sockaddr_in6 ipv6;
    } source;
};

static struct bsd_route_cache_entry
    g_ipv4_route_cache[BSD_ROUTE_CACHE_INTERFACES];
static struct bsd_route_cache_entry
    g_ipv6_route_cache[BSD_ROUTE_CACHE_INTERFACES];

static int
bsd_route_bytes_are_zero(const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (bytes[index] != 0)
            return 0;
    }
    return 1;
}

static uint32_t
bsd_route_network_namespace(uint32_t fib_number)
{
    if (vnet0)
        return vnet0->instance;
    return fib_number;
}

static struct nhop_object *
bsd_route_finish(const edge_linux_route_result_t *result, int family)
{
    struct bsd_route_cache_entry *entry;
    struct nhop_object *next_hop;
    if_t interface;
    size_t address_length;

    if (!result || result->output_ifindex <= 0 ||
        (unsigned int)result->output_ifindex >= BSD_ROUTE_CACHE_INTERFACES)
        return 0;
    interface = ifnet_byindex((unsigned int)result->output_ifindex);
    if (!interface)
        return 0;
    if (family == AF_INET) {
        entry = &g_ipv4_route_cache[result->output_ifindex];
        address_length = 4U;
    } else {
        entry = &g_ipv6_route_cache[result->output_ifindex];
        address_length = 16U;
    }
    next_hop = &entry->next_hop;
    __builtin_memset(entry, 0, sizeof(*entry));
    next_hop->nh_ifp = interface;
    next_hop->nh_aifp = interface;
    next_hop->nh_mtu = (uint16_t)if_getmtu(interface);
    entry->source_address.ifa_ifp = interface;
    if (family == AF_INET) {
        entry->source.ipv4.sin_len = sizeof(entry->source.ipv4);
        entry->source.ipv4.sin_family = AF_INET;
        if (!bsd_route_bytes_are_zero(result->preferred_source, 4U))
            __builtin_memcpy(&entry->source.ipv4.sin_addr,
                result->preferred_source, 4U);
        else
            entry->source.ipv4.sin_addr.s_addr = interface->if_ipv4_address;
        entry->source_address.ifa_addr =
            (struct sockaddr *)&entry->source.ipv4;
        if (!bsd_route_bytes_are_zero(result->gateway, address_length)) {
            next_hop->nh_flags |= BSD_NHF_GATEWAY;
            next_hop->gw4_sa.sin_len = sizeof(next_hop->gw4_sa);
            next_hop->gw4_sa.sin_family = AF_INET;
            __builtin_memcpy(&next_hop->gw4_sa.sin_addr,
                result->gateway, address_length);
        }
    } else {
        entry->source.ipv6.sin6_len = sizeof(entry->source.ipv6);
        entry->source.ipv6.sin6_family = AF_INET6;
        __builtin_memcpy(&entry->source.ipv6.sin6_addr,
            result->preferred_source, address_length);
        entry->source_address.ifa_addr =
            (struct sockaddr *)&entry->source.ipv6;
        if (!bsd_route_bytes_are_zero(result->gateway, address_length)) {
            next_hop->nh_flags |= BSD_NHF_GATEWAY;
            next_hop->gw6_sa.sin6_len = sizeof(next_hop->gw6_sa);
            next_hop->gw6_sa.sin6_family = AF_INET6;
            __builtin_memcpy(&next_hop->gw6_sa.sin6_addr,
                result->gateway, address_length);
        }
    }
    next_hop->nh_ifa = &entry->source_address;
    return next_hop;
}

struct nhop_object *
fib4_lookup(uint32_t fib_number, struct in_addr destination,
    uint32_t scope_id, uint32_t flags, uint32_t flow_id)
{
    edge_linux_route_query_t query;
    edge_linux_route_result_t result;

    (void)flags;
    (void)flow_id;
    __builtin_memset(&query, 0, sizeof(query));
    query.network_namespace = bsd_route_network_namespace(fib_number);
    query.family = EDGE_LINUX_AF_INET;
    query.output_ifindex = (int32_t)scope_id;
    __builtin_memcpy(query.destination, &destination, 4U);
    if (edge_linux_route_lookup(&query, &result) < 0)
        return 0;
    return bsd_route_finish(&result, AF_INET);
}

struct nhop_object *
fib6_lookup(uint32_t fib_number, const struct in6_addr *destination,
    uint32_t scope_id, uint32_t flags, uint32_t flow_id)
{
    edge_linux_route_query_t query;
    edge_linux_route_result_t result;

    (void)flags;
    (void)flow_id;
    if (!destination)
        return 0;
    __builtin_memset(&query, 0, sizeof(query));
    query.network_namespace = bsd_route_network_namespace(fib_number);
    query.family = EDGE_LINUX_AF_INET6;
    query.output_ifindex = (int32_t)scope_id;
    __builtin_memcpy(query.destination, destination, 16U);
    if (edge_linux_route_lookup(&query, &result) < 0)
        return 0;
    return bsd_route_finish(&result, AF_INET6);
}

int
sa6_embedscope(struct sockaddr_in6 *socket_address, int use_default)
{
    uint32_t zone_id;

    (void)use_default;
    if (!socket_address)
        return EINVAL;
    zone_id = socket_address->sin6_scope_id;
    if (zone_id != 0 &&
        (IN6_IS_SCOPE_LINKLOCAL(&socket_address->sin6_addr) ||
        IN6_IS_ADDR_MC_INTFACELOCAL(&socket_address->sin6_addr))) {
        if (!ifnet_byindex(zone_id))
            return ENXIO;
        socket_address->sin6_addr.s6_addr16[1] =
            htons((uint16_t)zone_id);
        socket_address->sin6_scope_id = 0;
    }
    return 0;
}

int
sa6_recoverscope(struct sockaddr_in6 *socket_address)
{
    uint32_t zone_id;

    if (!socket_address)
        return EINVAL;
    if (!IN6_IS_SCOPE_LINKLOCAL(&socket_address->sin6_addr) &&
        !IN6_IS_ADDR_MC_INTFACELOCAL(&socket_address->sin6_addr))
        return 0;
    zone_id = ntohs(socket_address->sin6_addr.s6_addr16[1]);
    if (zone_id == 0)
        return 0;
    if (!ifnet_byindex(zone_id))
        return ENXIO;
    socket_address->sin6_addr.s6_addr16[1] = 0;
    socket_address->sin6_scope_id = zone_id;
    return 0;
}
