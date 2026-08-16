/* SPDX-License-Identifier: MPL-2.0 */
/* Host-toolchain adapter for FreeBSD target ABI limits. */

#ifndef EDGEOS_FREEBSD_COMPAT_SYS_SYSLIMITS_H
#define EDGEOS_FREEBSD_COMPAT_SYS_SYSLIMITS_H

/*
 * Linux host limits.h may publish these names before the imported FreeBSD
 * headers are reached.  The bridge compiles FreeBSD target code, so discard
 * only the conflicting host definitions immediately before loading the
 * target header.  Keeping this adjustment here also makes later limits.h
 * includes harmless.
 */
#ifdef PATH_MAX
#undef PATH_MAX
#endif
#ifdef PIPE_BUF
#undef PIPE_BUF
#endif

#if defined(__GNUC__) || defined(__clang__)
#include_next <sys/syslimits.h>
#else
#error "The BSD driver bridge requires a compiler with include_next support"
#endif

#endif
