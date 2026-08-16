/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Preserve FreeBSD's optional netmap build boundary for imported drivers.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_DEV_NETMAP_NETMAP_KERN_H
#define EDGEOS_COMPAT_FREEBSD_DEV_NETMAP_NETMAP_KERN_H

#ifdef DEV_NETMAP
#include_next <dev/netmap/netmap_kern.h>
#endif

#endif
