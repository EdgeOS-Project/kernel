/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD builds exclude Linux reserved-memory operations in ath11k. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_OF_RESERVED_MEM_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_OF_RESERVED_MEM_H_

#include <linux/types.h>

struct device_node;

struct reserved_mem {
    const char *name;
    phys_addr_t base;
    phys_addr_t size;
    void *priv;
};

static inline struct reserved_mem *
of_reserved_mem_lookup(struct device_node *node)
{
    (void)node;
    return NULL;
}

#endif
