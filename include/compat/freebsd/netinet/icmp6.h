/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Import the complete FreeBSD ICMPv6 wire ABI without FreeBSD network-stack
 * statistics and tracing declarations. Hardware drivers consume packet
 * layouts and protocol constants, while EdgeOS owns stack accounting.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_NETINET_ICMP6_H
#define EDGEOS_COMPAT_FREEBSD_NETINET_ICMP6_H

#ifdef _KERNEL
#define EDGEOS_ICMP6_RESTORE_KERNEL
#undef _KERNEL
#endif

#include_next <netinet/icmp6.h>

#ifdef EDGEOS_ICMP6_RESTORE_KERNEL
#define _KERNEL
#undef EDGEOS_ICMP6_RESTORE_KERNEL
#endif

#endif
