/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD compiler-definition adapter for imported driver sources. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_CDEFS_H
#define EDGEOS_COMPAT_FREEBSD_SYS_CDEFS_H

/*
 * A Linux build host may load features.h through compiler support headers
 * before the bridge reaches FreeBSD cdefs.h.  Those host feature selections
 * must not hide FreeBSD kernel types from imported target sources.
 */
#ifdef _POSIX_SOURCE
#undef _POSIX_SOURCE
#endif
#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#include_next <sys/cdefs.h>

#ifdef __FBSDID
#undef __FBSDID
#endif
#define __FBSDID(identifier)

#endif
