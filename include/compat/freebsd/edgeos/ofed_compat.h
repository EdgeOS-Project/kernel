/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_COMPAT_FREEBSD_OFED_COMPAT_H
#define EDGEOS_COMPAT_FREEBSD_OFED_COMPAT_H

#include <sys/param.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_vlan_var.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>

#define ip bsd_ipv4_header

#define RT_DEFAULT_FIB 0
#define NHF_GATEWAY 0x0200
#define NHR_NONE 0x00

#ifdef EDGEOS_BSD_IRDMA
static inline if_t
ip6_ifp_find(struct vnet *network, struct in6_addr address, uint16_t scope_id)
{
    struct sockaddr_in6 socket_address = {0};
    struct ifaddr *interface_address;
    if_t interface;

    (void)network;
    (void)scope_id;
    socket_address.sin6_len = sizeof(socket_address);
    socket_address.sin6_family = AF_INET6;
    socket_address.sin6_addr = address;
    interface_address = ifa_ifwithaddr(
        (const struct sockaddr *)&socket_address);
    interface = interface_address ? interface_address->ifa_ifp : 0;
    if (interface)
        if_ref(interface);
    return interface;
}
#endif

struct inpcb;
struct inpcbinfo;

#endif
