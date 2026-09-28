/* SPDX-License-Identifier: MPL-2.0 */
/* Shared 64-bit target limits for the EdgeOS FreeBSD driver bridge. */

#ifndef _MACHINE__LIMITS_H_
#define _MACHINE__LIMITS_H_

#if __SIZEOF_POINTER__ != 8
#error "The EdgeOS FreeBSD driver bridge requires a 64-bit target"
#endif

#define __CHAR_BIT 8
#define __SHRT_BIT 16
#define __INT_BIT 32
#define __LONG_BIT (__SIZEOF_LONG__ * 8)
#define __LLONG_BIT 64
#define __WORD_BIT 32

#define __SCHAR_MAX 0x7f
#define __SCHAR_MIN (-0x7f - 1)
#define __UCHAR_MAX 0xff

#define __SHRT_MAX 0x7fff
#define __SHRT_MIN (-0x7fff - 1)
#define __USHRT_MAX 0xffff

#define __INT_MAX 0x7fffffff
#define __INT_MIN (-0x7fffffff - 1)
#define __UINT_MAX 0xffffffffU

#if __SIZEOF_LONG__ == 8
#define __LONG_MAX 0x7fffffffffffffffL
#define __LONG_MIN (-0x7fffffffffffffffL - 1)
#define __ULONG_MAX 0xffffffffffffffffUL
#elif __SIZEOF_LONG__ == 4
#define __LONG_MAX 0x7fffffffL
#define __LONG_MIN (-0x7fffffffL - 1)
#define __ULONG_MAX 0xffffffffUL
#else
#error "Unsupported long size for the EdgeOS FreeBSD driver bridge"
#endif

#define __LLONG_MAX 0x7fffffffffffffffLL
#define __LLONG_MIN (-0x7fffffffffffffffLL - 1)
#define __ULLONG_MAX 0xffffffffffffffffULL

#define __SSIZE_MAX __LLONG_MAX
#define __SIZE_T_MAX __ULLONG_MAX
#define __OFF_MAX __LLONG_MAX
#define __OFF_MIN __LLONG_MIN
#define __UQUAD_MAX __ULLONG_MAX
#define __QUAD_MAX __LLONG_MAX
#define __QUAD_MIN __LLONG_MIN

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#define __MINSIGSTKSZ (1024 * 4)
#elif defined(__x86_64__)
#define __MINSIGSTKSZ (512 * 4)
#else
#error "Unsupported EdgeOS FreeBSD driver bridge architecture"
#endif

#endif
