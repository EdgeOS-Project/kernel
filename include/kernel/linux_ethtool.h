/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux ethtool Netlink policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_ETHTOOL_H
#define EDGEOS_KERNEL_LINUX_ETHTOOL_H

#include <stdint.h>

#define EDGE_LINUX_GENL_ID_ETHTOOL 19u
#define EDGE_LINUX_GENL_ETHTOOL_VERSION 1u

#define EDGE_LINUX_ETHTOOL_MSG_LINKINFO_GET 2u
#define EDGE_LINUX_ETHTOOL_MSG_LINKMODES_GET 4u
#define EDGE_LINUX_ETHTOOL_MSG_LINKSTATE_GET 6u
#define EDGE_LINUX_ETHTOOL_MSG_CHANNELS_GET 17u
#define EDGE_LINUX_ETHTOOL_MSG_STATS_GET 32u

int edge_linux_ethtool_respond(
    uint32_t network_namespace, uint32_t port_id,
    const void *request, uint32_t request_length,
    void *response, uint32_t response_capacity, uint32_t *response_length);

#endif
