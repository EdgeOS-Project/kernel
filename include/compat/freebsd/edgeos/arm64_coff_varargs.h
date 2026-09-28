/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 COFF variable-argument setup for the FreeBSD LP64 frontend. */

#ifndef EDGEOS_COMPAT_FREEBSD_ARM64_COFF_VARARGS_H
#define EDGEOS_COMPAT_FREEBSD_ARM64_COFF_VARARGS_H

#include <stdarg.h>

#if defined(__aarch64__) && defined(EDGEOS_BSD_COFF_TARGET)
/*
 * The FreeBSD frontend models va_list as the AAPCS64 state structure, while
 * the COFF backend supplies a contiguous Windows ARM64 argument save area.
 * Clearing the unused AAPCS64 register fields selects the shared stack cursor
 * that the backend initializes and keeps imported variadic code source-exact.
 */
#undef va_start
#define va_start(arguments, last_named)                                  \
    (__builtin_memset(&(arguments), 0, sizeof(arguments)),               \
        __builtin_va_start((arguments), (last_named)))
#endif

#endif
