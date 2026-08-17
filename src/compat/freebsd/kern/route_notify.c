/* SPDX-License-Identifier: MPL-2.0 */
/* Linux rtnetlink notifications for imported FreeBSD network drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/net/if_var.h"
#include "kernel/linux_abi.h"
#include "kernel/socket_runtime.h"

#define BSD_RTNL_NEWLINK 16u
#define BSD_RTNL_GROUP_LINK 1u
#define BSD_RTNL_IFLA_ADDRESS 1u
#define BSD_RTNL_IFLA_IFNAME 3u
#define BSD_RTNL_IFLA_MTU 4u
#define BSD_RTNL_IFLA_OPERSTATE 16u
#define BSD_RTNL_IFLA_CARRIER 33u
#define BSD_RTNL_IFLA_EDGEOS_WIRELESS 0x3f00u
#define BSD_RTNL_ARPHRD_ETHER 1u
#define BSD_RTNL_IFF_UP 0x00000001u
#define BSD_RTNL_IFF_BROADCAST 0x00000002u
#define BSD_RTNL_IFF_RUNNING 0x00000040u
#define BSD_RTNL_IFF_PROMISC 0x00000100u
#define BSD_RTNL_IFF_ALLMULTI 0x00000200u
#define BSD_RTNL_IFF_MULTICAST 0x00001000u
#define BSD_RTNL_IFF_LOWER_UP 0x00010000u
#define BSD_RTNL_OPER_UNKNOWN 0u
#define BSD_RTNL_OPER_DOWN 2u
#define BSD_RTNL_OPER_UP 6u
#define BSD_RTNL_PACKET_CAPACITY 2048u

struct bsd_rtnl_header {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
};

struct bsd_rtnl_link {
    uint8_t family;
    uint8_t padding;
    uint16_t type;
    int32_t index;
    uint32_t flags;
    uint32_t change;
};

struct bsd_rtnl_attribute {
    uint16_t length;
    uint16_t type;
};

struct bsd_rtnl_wireless_event {
    int32_t operation;
    uint32_t data_length;
};

static size_t
route_notify_align(size_t length)
{
    return (length + 3u) & ~(size_t)3u;
}

static void
route_notify_copy(void *destination, const void *source, size_t length)
{
    uint8_t *output = destination;
    const uint8_t *input = source;

    while (length--)
        *output++ = *input++;
}

static void
route_notify_zero(void *destination, size_t length)
{
    uint8_t *output = destination;

    while (length--)
        *output++ = 0;
}

static size_t
route_notify_name_length(const char *name)
{
    size_t length = 0;

    if (!name)
        return 0;
    while (length < IFNAMSIZ - 1u && name[length])
        length++;
    return length + 1u;
}

static int32_t
route_notify_interface_index(const struct ifnet *interface)
{
    uint32_t registry_index;

    if (!interface || !interface->if_bridge_handle)
        return 0;
    registry_index = (uint32_t)interface->if_bridge_handle;
    return registry_index == 0 ? 0 : (int32_t)(registry_index + 1u);
}

static uint32_t
route_notify_linux_flags(const struct ifnet *interface)
{
    uint32_t flags = 0;

    if (!interface)
        return 0;
    if (interface->if_flags & IFF_UP)
        flags |= BSD_RTNL_IFF_UP;
    if (interface->if_flags & IFF_BROADCAST)
        flags |= BSD_RTNL_IFF_BROADCAST;
    if (interface->if_flags & IFF_PROMISC)
        flags |= BSD_RTNL_IFF_PROMISC;
    if (interface->if_flags & IFF_ALLMULTI)
        flags |= BSD_RTNL_IFF_ALLMULTI;
    if (interface->if_flags & IFF_MULTICAST)
        flags |= BSD_RTNL_IFF_MULTICAST;
    if (interface->if_drv_flags & IFF_DRV_RUNNING)
        flags |= BSD_RTNL_IFF_RUNNING;
    if (interface->if_link_state == LINK_STATE_UP)
        flags |= BSD_RTNL_IFF_LOWER_UP;
    return flags;
}

static uint32_t
route_notify_linux_change(int flags_mask)
{
    uint32_t change = 0;

    if (!flags_mask)
        return UINT32_MAX;
    if (flags_mask & IFF_UP)
        change |= BSD_RTNL_IFF_UP;
    if (flags_mask & IFF_BROADCAST)
        change |= BSD_RTNL_IFF_BROADCAST;
    if (flags_mask & IFF_PROMISC)
        change |= BSD_RTNL_IFF_PROMISC;
    if (flags_mask & IFF_ALLMULTI)
        change |= BSD_RTNL_IFF_ALLMULTI;
    if (flags_mask & IFF_MULTICAST)
        change |= BSD_RTNL_IFF_MULTICAST;
    if (flags_mask & IFF_DRV_RUNNING)
        change |= BSD_RTNL_IFF_RUNNING | BSD_RTNL_IFF_LOWER_UP;
    return change;
}

static size_t
route_notify_add_attribute(uint8_t *packet, size_t offset, size_t capacity,
    uint16_t type, const void *data, size_t data_length)
{
    struct bsd_rtnl_attribute attribute;
    size_t raw_length = sizeof(attribute) + data_length;
    size_t aligned_length = route_notify_align(raw_length);

    if (!packet || (!data && data_length) ||
        raw_length > UINT16_MAX || offset > capacity ||
        aligned_length > capacity - offset)
        return 0;
    attribute.length = (uint16_t)raw_length;
    attribute.type = type;
    route_notify_copy(packet + offset, &attribute, sizeof(attribute));
    if (data_length)
        route_notify_copy(packet + offset + sizeof(attribute),
            data, data_length);
    if (aligned_length > raw_length)
        route_notify_zero(packet + offset + raw_length,
            aligned_length - raw_length);
    return offset + aligned_length;
}

static size_t
route_notify_begin(uint8_t *packet, size_t capacity,
    const struct ifnet *interface, int flags_mask)
{
    struct bsd_rtnl_header header;
    struct bsd_rtnl_link link;
    size_t offset;
    uint32_t mtu;
    uint8_t carrier;
    uint8_t operational_state;

    if (!packet || !interface ||
        capacity < sizeof(header) + sizeof(link))
        return 0;
    route_notify_zero(&header, sizeof(header));
    header.type = BSD_RTNL_NEWLINK;
    route_notify_zero(&link, sizeof(link));
    link.type = BSD_RTNL_ARPHRD_ETHER;
    link.index = route_notify_interface_index(interface);
    link.flags = route_notify_linux_flags(interface);
    link.change = route_notify_linux_change(flags_mask);
    route_notify_copy(packet, &header, sizeof(header));
    route_notify_copy(packet + sizeof(header), &link, sizeof(link));
    offset = sizeof(header) + sizeof(link);
    offset = route_notify_add_attribute(packet, offset, capacity,
        BSD_RTNL_IFLA_IFNAME, interface->if_name_storage,
        route_notify_name_length(interface->if_name_storage));
    if (!offset)
        return 0;
    offset = route_notify_add_attribute(packet, offset, capacity,
        BSD_RTNL_IFLA_ADDRESS, interface->if_mac,
        sizeof(interface->if_mac));
    if (!offset)
        return 0;
    mtu = (uint32_t)interface->if_mtu;
    offset = route_notify_add_attribute(packet, offset, capacity,
        BSD_RTNL_IFLA_MTU, &mtu, sizeof(mtu));
    if (!offset)
        return 0;
    carrier = interface->if_link_state == LINK_STATE_UP ? 1u : 0u;
    operational_state = carrier ? BSD_RTNL_OPER_UP :
        (interface->if_link_state == LINK_STATE_DOWN ?
            BSD_RTNL_OPER_DOWN : BSD_RTNL_OPER_UNKNOWN);
    offset = route_notify_add_attribute(packet, offset, capacity,
        BSD_RTNL_IFLA_OPERSTATE, &operational_state,
        sizeof(operational_state));
    if (!offset)
        return 0;
    return route_notify_add_attribute(packet, offset, capacity,
        BSD_RTNL_IFLA_CARRIER, &carrier, sizeof(carrier));
}

static void
route_notify_publish(uint8_t *packet, size_t length)
{
    struct bsd_rtnl_header *header;

    if (!packet || length < sizeof(*header) || length > UINT32_MAX)
        return;
    header = (struct bsd_rtnl_header *)(void *)packet;
    header->length = (uint32_t)length;
    (void)kernel_socket_broadcast_netlink_datagram(
        EDGE_LINUX_NETLINK_ROUTE, BSD_RTNL_GROUP_LINK,
        packet, (uint32_t)length);
}

void
rt_ifmsg(struct ifnet *interface, int flags_mask)
{
    uint8_t packet[BSD_RTNL_PACKET_CAPACITY];
    size_t length;

    length = route_notify_begin(packet, sizeof(packet), interface,
        flags_mask);
    if (length)
        route_notify_publish(packet, length);
}

void
rt_ieee80211msg(struct ifnet *interface, int operation,
    void *data, size_t data_length)
{
    uint8_t packet[BSD_RTNL_PACKET_CAPACITY];
    struct bsd_rtnl_wireless_event event;
    size_t offset;
    size_t payload_length;

    if ((!data && data_length) ||
        data_length > sizeof(packet) - sizeof(event))
        return;
    offset = route_notify_begin(packet, sizeof(packet), interface, 0);
    if (!offset)
        return;
    event.operation = operation;
    event.data_length = (uint32_t)data_length;
    payload_length = sizeof(event) + data_length;
    if (offset + route_notify_align(sizeof(struct bsd_rtnl_attribute) +
        payload_length) > sizeof(packet))
        return;
    route_notify_copy(packet + offset + sizeof(struct bsd_rtnl_attribute),
        &event, sizeof(event));
    if (data_length)
        route_notify_copy(packet + offset +
            sizeof(struct bsd_rtnl_attribute) + sizeof(event),
            data, data_length);
    offset = route_notify_add_attribute(packet, offset, sizeof(packet),
        BSD_RTNL_IFLA_EDGEOS_WIRELESS,
        packet + offset + sizeof(struct bsd_rtnl_attribute),
        payload_length);
    if (offset)
        route_notify_publish(packet, offset);
}
