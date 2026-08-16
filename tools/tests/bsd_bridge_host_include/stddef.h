/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal compiler-backed types for freestanding BSD bridge unit tests. */

#ifndef EDGEOS_BSD_BRIDGE_HOST_STDDEF_H
#define EDGEOS_BSD_BRIDGE_HOST_STDDEF_H

typedef __PTRDIFF_TYPE__ ptrdiff_t;
typedef __SIZE_TYPE__ size_t;
typedef __WCHAR_TYPE__ wchar_t;

#define NULL ((void *)0)
#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#endif
