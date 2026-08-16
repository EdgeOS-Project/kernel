/* SPDX-License-Identifier: BSD-2-Clause */
/* Single-network-instance view used by the EdgeOS BSD bridge. */

#ifndef _NET_VNET_H_
#define _NET_VNET_H_

#include <sys/epoch.h>

struct vnet {
    unsigned int instance;
};

extern struct vnet *vnet0;

#define VNET_DECLARE(type, name) extern type name
#define VNET_DEFINE(type, name) type name
#define VNET_DEFINE_STATIC(type, name) static type name
#define VNET(name) name
#define VNET_PTR(name) (&(name))

#ifndef CURVNET_SET
#define CURVNET_SET(vnet) do { (void)(vnet); } while (0)
#endif
#ifndef CURVNET_SET_QUIET
#define CURVNET_SET_QUIET(vnet) CURVNET_SET(vnet)
#endif
#ifndef CURVNET_RESTORE
#define CURVNET_RESTORE() do { } while (0)
#endif

#endif
