/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux Generic Netlink policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_GENETLINK_H
#define EDGEOS_KERNEL_LINUX_GENETLINK_H

#include <stdint.h>

#define EDGE_LINUX_NETLINK_GENERIC 16u
#define EDGE_LINUX_GENL_ID_CTRL 16u
#define EDGE_LINUX_GENL_CTRL_VERSION 2u

/*
 * Responds to Generic Netlink controller family discovery requests. Only
 * families with working kernel handlers are exposed.
 */
int edge_linux_genetlink_respond(
    uint32_t network_namespace, uint32_t port_id,
    const void *request, uint32_t request_length,
    void *response, uint32_t response_capacity, uint32_t *response_length);

#endif
