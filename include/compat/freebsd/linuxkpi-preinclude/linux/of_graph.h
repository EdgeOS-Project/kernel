/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS LinuxKPI Open Firmware graph compatibility. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_OF_GRAPH_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_OF_GRAPH_H_

#include <linux/of.h>

struct of_endpoint {
    unsigned int port;
    unsigned int id;
    const struct device_node *local_node;
};

static inline struct device_node *
of_graph_get_endpoint_by_regs(const struct device_node *parent,
    int port_reg, int reg)
{
    (void)parent;
    (void)port_reg;
    (void)reg;
    return NULL;
}

static inline struct device_node *
of_graph_get_remote_endpoint(const struct device_node *node)
{
    (void)node;
    return NULL;
}

static inline struct device_node *
of_graph_get_port_parent(struct device_node *node)
{
    (void)node;
    return NULL;
}

#endif
