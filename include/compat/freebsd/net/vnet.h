/* SPDX-License-Identifier: BSD-2-Clause */
/* Single-network-instance view used by the EdgeOS BSD bridge. */

#ifndef _NET_VNET_H_
#define _NET_VNET_H_

#include <sys/epoch.h>

struct vnet {
    unsigned int instance;
};

extern struct vnet *vnet0;

#define VNET_ITERATOR_DECL(name) struct vnet *name
#define VNET_LIST_RLOCK() do { } while (0)
#define VNET_LIST_RUNLOCK() do { } while (0)
#define VNET_FOREACH(name) \
    for ((name) = vnet0; (name) != 0; (name) = 0)
#define TD_TO_VNET(thread) (vnet0)

#define VNET_DECLARE(type, name) extern type name
#define VNET_DEFINE(type, name) type name
#define VNET_DEFINE_STATIC(type, name) static type name
#define VNET(name) name
#define VNET_PTR(name) (&(name))
#define VNET_SYSINIT(ident, subsystem, order, function, argument) \
    SYSINIT(ident, subsystem, order, function, argument)
#define VNET_SYSUNINIT(ident, subsystem, order, function, argument) \
    SYSUNINIT(ident, subsystem, order, function, argument)

#ifndef CURVNET_SET
#define CURVNET_SET(vnet) do { } while (0)
#endif
#ifndef CURVNET_SET_QUIET
#define CURVNET_SET_QUIET(vnet) CURVNET_SET(vnet)
#endif
#ifndef CURVNET_RESTORE
#define CURVNET_RESTORE() do { } while (0)
#endif

#endif
