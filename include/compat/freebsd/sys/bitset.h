/* SPDX-License-Identifier: MPL-2.0 */
/* Include-order adapter for FreeBSD bitset consumers. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_BITSET_H
#define EDGEOS_COMPAT_FREEBSD_SYS_BITSET_H

#if defined(BSD_BRIDGE_HOST_TEST)
#include <stddef.h>
#define _BITSET_BITS (sizeof(unsigned long) * 8u)
#define __bitset_words(size) (((size) + _BITSET_BITS - 1u) / _BITSET_BITS)
#define BITSET_DEFINE(type, size) \
    struct type { unsigned long __bits[__bitset_words(size)]; }
#define BIT_ZERO(size, pointer) do { \
    for (size_t index = 0; index < __bitset_words(size); ++index) \
        (pointer)->__bits[index] = 0; \
} while (0)
#define BIT_SET(size, bit, pointer) \
    ((pointer)->__bits[(bit) / _BITSET_BITS] |= \
        1ul << ((bit) % _BITSET_BITS))
#define BIT_CLR(size, bit, pointer) \
    ((pointer)->__bits[(bit) / _BITSET_BITS] &= \
        ~(1ul << ((bit) % _BITSET_BITS)))
#define BIT_ISSET(size, bit, pointer) \
    (((pointer)->__bits[(bit) / _BITSET_BITS] & \
        (1ul << ((bit) % _BITSET_BITS))) != 0)
#else
#include <sys/_bitset.h>
#include_next <sys/bitset.h>
#endif

#endif
