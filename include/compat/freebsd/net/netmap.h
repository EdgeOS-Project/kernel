/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Preserve FreeBSD's optional netmap build boundary for imported drivers.
 *
 * Several network drivers include netmap headers unconditionally even when
 * the kernel configuration does not contain netmap.  The FreeBSD build then
 * compiles every netmap-dependent code path out through DEV_NETMAP.  EdgeOS
 * follows the same contract until the complete netmap subsystem is enabled.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_NET_NETMAP_H
#define EDGEOS_COMPAT_FREEBSD_NET_NETMAP_H

#ifdef DEV_NETMAP
#include_next <net/netmap.h>
#endif

#endif
