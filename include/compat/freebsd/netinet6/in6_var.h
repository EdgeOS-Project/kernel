/* SPDX-License-Identifier: MPL-2.0 */
/*
 * IPv6 interface-address lifecycle belongs to the native network stack.
 * Hardware drivers share the packet and interface types exposed here.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_NETINET6_IN6_VAR_H
#define EDGEOS_COMPAT_FREEBSD_NETINET6_IN6_VAR_H

#include <net/if.h>
#include <netinet/in.h>

struct in6_ifaddr;
struct in6_multi;

#endif
