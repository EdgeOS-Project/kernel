/* SPDX-License-Identifier: MPL-2.0 */
/* Shared 64-bit machine types for the EdgeOS FreeBSD driver bridge. */

#ifndef _MACHINE__TYPES_H_
#define _MACHINE__TYPES_H_

#ifndef _SYS__TYPES_H_
#error "Do not include machine/_types.h directly; include sys/_types.h"
#endif

#include <machine/_limits.h>

#if __SIZEOF_POINTER__ != 8
#error "The EdgeOS FreeBSD driver bridge requires a 64-bit target"
#endif

#if defined(__x86_64__)
#define __NO_STRICT_ALIGNMENT
#elif !defined(__aarch64__) && !defined(EDGEOS_BSD_ARM64)
#error "Unsupported EdgeOS FreeBSD driver bridge architecture"
#endif

typedef __int32_t __clock_t;
typedef __int64_t __critical_t;
#ifndef _STANDALONE
typedef double __double_t;
typedef float __float_t;
#endif
typedef __int32_t __int_fast8_t;
typedef __int32_t __int_fast16_t;
typedef __int32_t __int_fast32_t;
typedef __int64_t __int_fast64_t;
typedef __int64_t __register_t;
typedef __int64_t __segsz_t;
typedef __int64_t __time_t;
#define __SIZEOF_TIME_T __SIZEOF_INT64_T
typedef __uint32_t __uint_fast8_t;
typedef __uint32_t __uint_fast16_t;
typedef __uint32_t __uint_fast32_t;
typedef __uint64_t __uint_fast64_t;
typedef __uint64_t __u_register_t;
typedef __uint64_t __vm_paddr_t;

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
typedef unsigned int ___wchar_t;
#define __WCHAR_MIN 0
#define __WCHAR_MAX __UINT_MAX
#else
typedef int ___wchar_t;
#define __WCHAR_MIN __INT_MIN
#define __WCHAR_MAX __INT_MAX
#endif

#endif
