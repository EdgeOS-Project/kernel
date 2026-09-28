/* SPDX-License-Identifier: MPL-2.0 */
/*
 * FreeBSD IPv4 address lifecycle state is owned by the native network stack.
 * Imported hardware drivers use this header only as an umbrella dependency;
 * packet addresses and interfaces are provided by the shared bridge types.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_NETINET_IN_VAR_H
#define EDGEOS_COMPAT_FREEBSD_NETINET_IN_VAR_H

#include <net/if_var.h>
#include <netinet/in.h>

struct in_ifaddr {
    struct ifaddr ia_ifa;
    struct sockaddr_in ia_addr;
    struct sockaddr_in ia_dstaddr;
    struct sockaddr_in ia_sockmask;
};

struct in_aliasreq {
    char ifra_name[IFNAMSIZ];
    struct sockaddr_in ifra_addr;
    struct sockaddr_in ifra_dstaddr;
    struct sockaddr_in ifra_mask;
};

struct in_multi;
struct socket;
struct thread;

int in_control(struct socket *socket, unsigned long command, char *data,
    if_t interface, struct thread *thread);

#endif
