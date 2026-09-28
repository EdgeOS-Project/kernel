/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Compatibility boundary for FreeBSD generated system-call argument types.
 *
 * Imported drivers use EdgeOS kernel services and must not declare FreeBSD
 * system-call entry points.  Drivers that only include sysproto.h for common
 * kernel declarations can therefore use this intentionally declaration-free
 * boundary header.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_SYSPROTO_H
#define EDGEOS_COMPAT_FREEBSD_SYS_SYSPROTO_H

#endif
