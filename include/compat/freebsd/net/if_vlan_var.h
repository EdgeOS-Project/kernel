/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NET_IF_VLAN_VAR_H_
#define _NET_IF_VLAN_VAR_H_

#include <net/if_var.h>

#define VLAN_CAPABILITIES(ifp) do { (void)(ifp); } while (0)
#define VLAN_TRUNKDEV(ifp) (ifp)
#define VLAN_TAG(ifp, tagp) (*(tagp) = 0, 0)
#define VLAN_DEVAT(ifp, vid) ((void)(ifp), (void)(vid), (if_t)0)

#endif
