/* SPDX-License-Identifier: MPL-2.0 */
/* Route imported code to the FreeBSD target limits, not host libc limits. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_LIMITS_H
#define EDGEOS_COMPAT_FREEBSD_SYS_LIMITS_H

#if defined(__GNUC__) || defined(__clang__)
#include_next <sys/limits.h>
#else
#error "The BSD driver bridge requires a compiler with include_next support"
#endif

#endif
