/* SPDX-License-Identifier: BSD-2-Clause */
/* Share one resource object between LinuxKPI ranges and FreeBSD rman. */

#ifndef _LINUXKPI_LINUX_IOPORT_H
#define _LINUXKPI_LINUX_IOPORT_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <sys/rman.h>

#define DEFINE_RES_MEM(start_value, size_value) \
    (struct resource) { \
        .start = (start_value), \
        .end = (start_value) + (size_value) - 1, \
    }

static inline resource_size_t
resource_size(const struct resource *resource)
{
    return resource->end - resource->start + 1;
}

static inline bool
resource_contains(const struct resource *outer,
    const struct resource *inner)
{
    return outer->start <= inner->start && outer->end >= inner->end;
}

#endif
