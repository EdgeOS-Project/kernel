/* SPDX-License-Identifier: MPL-2.0 */
/* Shared 64-bit integer constants for the EdgeOS FreeBSD driver bridge. */

#ifndef _MACHINE__STDINT_H_
#define _MACHINE__STDINT_H_

#include <machine/_limits.h>

#define INT8_C(value) (value)
#define INT16_C(value) (value)
#define INT32_C(value) (value)
#if __SIZEOF_LONG__ == 8
#define INT64_C(value) (value##L)
#define UINT64_C(value) (value##UL)
#define INT64_MIN (-0x7fffffffffffffffL - 1)
#define INT64_MAX 0x7fffffffffffffffL
#define UINT64_MAX 0xffffffffffffffffUL
#else
#define INT64_C(value) (value##LL)
#define UINT64_C(value) (value##ULL)
#define INT64_MIN (-0x7fffffffffffffffLL - 1)
#define INT64_MAX 0x7fffffffffffffffLL
#define UINT64_MAX 0xffffffffffffffffULL
#endif

#define UINT8_C(value) (value)
#define UINT16_C(value) (value)
#define UINT32_C(value) (value##U)

#define INTMAX_C(value) INT64_C(value)
#define UINTMAX_C(value) UINT64_C(value)

#define INT8_MIN (-0x7f - 1)
#define INT16_MIN (-0x7fff - 1)
#define INT32_MIN (-0x7fffffff - 1)

#define INT8_MAX 0x7f
#define INT16_MAX 0x7fff
#define INT32_MAX 0x7fffffff

#define UINT8_MAX 0xff
#define UINT16_MAX 0xffff
#define UINT32_MAX 0xffffffffU

#define INT_LEAST8_MIN INT8_MIN
#define INT_LEAST16_MIN INT16_MIN
#define INT_LEAST32_MIN INT32_MIN
#define INT_LEAST64_MIN INT64_MIN
#define INT_LEAST8_MAX INT8_MAX
#define INT_LEAST16_MAX INT16_MAX
#define INT_LEAST32_MAX INT32_MAX
#define INT_LEAST64_MAX INT64_MAX
#define UINT_LEAST8_MAX UINT8_MAX
#define UINT_LEAST16_MAX UINT16_MAX
#define UINT_LEAST32_MAX UINT32_MAX
#define UINT_LEAST64_MAX UINT64_MAX

#define INT_FAST8_MIN INT32_MIN
#define INT_FAST16_MIN INT32_MIN
#define INT_FAST32_MIN INT32_MIN
#define INT_FAST64_MIN INT64_MIN
#define INT_FAST8_MAX INT32_MAX
#define INT_FAST16_MAX INT32_MAX
#define INT_FAST32_MAX INT32_MAX
#define INT_FAST64_MAX INT64_MAX
#define UINT_FAST8_MAX UINT32_MAX
#define UINT_FAST16_MAX UINT32_MAX
#define UINT_FAST32_MAX UINT32_MAX
#define UINT_FAST64_MAX UINT64_MAX

#define INTPTR_MIN INT64_MIN
#define INTPTR_MAX INT64_MAX
#define UINTPTR_MAX UINT64_MAX
#define INTMAX_MIN INT64_MIN
#define INTMAX_MAX INT64_MAX
#define UINTMAX_MAX UINT64_MAX
#define PTRDIFF_MIN INT64_MIN
#define PTRDIFF_MAX INT64_MAX
#define SIG_ATOMIC_MIN INT64_MIN
#define SIG_ATOMIC_MAX INT64_MAX
#define SIZE_MAX UINT64_MAX
#define WINT_MIN INT32_MIN
#define WINT_MAX INT32_MAX

#if __ISO_C_VISIBLE >= 2023
#define INT_FAST8_WIDTH 32
#define INT_FAST16_WIDTH 32
#define INT_FAST32_WIDTH 32
#define INT_FAST64_WIDTH 64
#define INTPTR_WIDTH 64
#define INTMAX_WIDTH 64
#define PTRDIFF_WIDTH 64
#define SIG_ATOMIC_WIDTH 64
#define SIZE_WIDTH 64
#define WCHAR_WIDTH 32
#define WINT_WIDTH 32
#endif

#endif
