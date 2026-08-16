/* SPDX-License-Identifier: MPL-2.0 */
/* Shared IPv4 configuration and address-format bridge for BSD drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/net/if_var.h"
#include "compat/freebsd/netinet/in.h"
#include "compat/freebsd/netinet/in_var.h"
#include "compat/freebsd/sys/sockio.h"
#include "net/lwip_stack.h"

#define BSD_IN_EINVAL 22
#define BSD_IN_EAFNOSUPPORT 47

int
in_control(struct socket *socket, unsigned long command, char *data,
    if_t interface, struct thread *thread)
{
    struct ifreq *request = (struct ifreq *)data;

    (void)socket;
    (void)thread;
    if (!interface || !data)
        return BSD_IN_EINVAL;
    if (command == SIOCAIFADDR) {
        const struct in_aliasreq *alias = (const struct in_aliasreq *)data;

        if (alias->ifra_addr.sin_family != AF_INET)
            return BSD_IN_EAFNOSUPPORT;
        interface->if_ipv4_address = alias->ifra_addr.sin_addr.s_addr;
        interface->if_ipv4_netmask = alias->ifra_mask.sin_addr.s_addr;
        interface->if_ipv4_gateway = alias->ifra_dstaddr.sin_addr.s_addr;
        if (interface->if_bridge_handle &&
            lwip_stack_get_netdev() != interface->if_bridge_handle &&
            lwip_stack_bind_netdev(interface->if_bridge_handle) != 0)
            return BSD_IN_EINVAL;
        return lwip_stack_configure_ipv4(interface->if_ipv4_address,
            interface->if_ipv4_netmask, interface->if_ipv4_gateway);
    }
    if (command == SIOCGIFADDR) {
        struct sockaddr_in *address =
            (struct sockaddr_in *)&request->ifr_addr;

        address->sin_len = sizeof(*address);
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = interface->if_ipv4_address;
        return 0;
    }
    if (command == SIOCDIFADDR) {
        interface->if_ipv4_address = 0;
        interface->if_ipv4_netmask = 0;
        interface->if_ipv4_gateway = 0;
        if (lwip_stack_get_netdev() == interface->if_bridge_handle)
            return lwip_stack_configure_ipv4(0, 0, 0);
        return 0;
    }
    return BSD_IN_EINVAL;
}

char *
inet_ntop(int family, const void *address, char *buffer,
    size_t buffer_length)
{
    const uint8_t *bytes = address;
    int length;

    if (!address || !buffer || buffer_length == 0)
        return 0;
    if (family == AF_INET) {
        length = bsd_snprintf(buffer, buffer_length, "%u.%u.%u.%u",
            bytes[0], bytes[1], bytes[2], bytes[3]);
    } else if (family == AF_INET6) {
        length = bsd_snprintf(buffer, buffer_length,
            "%x:%x:%x:%x:%x:%x:%x:%x",
            ((unsigned int)bytes[0] << 8) | bytes[1],
            ((unsigned int)bytes[2] << 8) | bytes[3],
            ((unsigned int)bytes[4] << 8) | bytes[5],
            ((unsigned int)bytes[6] << 8) | bytes[7],
            ((unsigned int)bytes[8] << 8) | bytes[9],
            ((unsigned int)bytes[10] << 8) | bytes[11],
            ((unsigned int)bytes[12] << 8) | bytes[13],
            ((unsigned int)bytes[14] << 8) | bytes[15]);
    } else {
        return 0;
    }
    if (length < 0 || (size_t)length >= buffer_length)
        return 0;
    return buffer;
}
