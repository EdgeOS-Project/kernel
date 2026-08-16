/* SPDX-License-Identifier: MPL-2.0 */
/* Shared registration adapter for the original EdgeOS network backend. */

#ifndef EDGEOS_NET_NATIVE_NETDEV_H
#define EDGEOS_NET_NATIVE_NETDEV_H

#include "net/netdev.h"

int edge_native_netdev_register(void);
int edge_native_netdev_unregister(void);
edge_netdev_handle_t edge_native_netdev_get_handle(void);

#endif
