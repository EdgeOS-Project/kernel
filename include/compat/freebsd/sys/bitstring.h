/* SPDX-License-Identifier: BSD-2-Clause */
/* Compact bit-string operations required by iflib receive rings. */

#ifndef _SYS_BITSTRING_H_
#define _SYS_BITSTRING_H_

#include <stddef.h>
#include <stdint.h>

#include "malloc.h"

typedef unsigned long bitstr_t;

#define BITSTR_BITS (sizeof(bitstr_t) * 8u)
#define bitstr_size(count)                                               \
    ((((size_t)(count) + BITSTR_BITS - 1u) / BITSTR_BITS) *             \
        sizeof(bitstr_t))
#define bit_decl(name, count)                                            \
    ((name)[bitstr_size(count) / sizeof(bitstr_t)])

static inline bitstr_t *
bit_alloc(size_t count, struct malloc_type *type, int flags)
{
    return bsd_malloc(bitstr_size(count), type, flags | M_ZERO);
}

static inline int
bit_test(const bitstr_t *bits, size_t bit)
{
    return (bits[bit / BITSTR_BITS] &
        ((bitstr_t)1u << (bit % BITSTR_BITS))) != 0;
}

/*
 * Search helpers receive the logical bit count, so they can inspect only the
 * bytes that belong to the caller's object. This matters for BSD drivers that
 * intentionally use the bit-string iteration API with fixed-width integer
 * masks smaller than bitstr_t.
 */
static inline int
bsd_bit_test_bounded(const bitstr_t *bits, size_t bit)
{
    const unsigned char *bytes = (const unsigned char *)(const void *)bits;

    return (bytes[bit / 8u] &
        (unsigned char)(1u << (bit % 8u))) != 0;
}

static inline void
bit_set(bitstr_t *bits, size_t bit)
{
    bits[bit / BITSTR_BITS] |= (bitstr_t)1u << (bit % BITSTR_BITS);
}

static inline void
bit_clear(bitstr_t *bits, size_t bit)
{
    bits[bit / BITSTR_BITS] &= ~((bitstr_t)1u << (bit % BITSTR_BITS));
}

static inline void
bit_nclear(bitstr_t *bits, size_t start, size_t stop)
{
    if (stop < start)
        return;
    for (size_t bit = start; bit <= stop; ++bit)
        bit_clear(bits, bit);
}

static inline void
bit_nset(bitstr_t *bits, size_t start, size_t stop)
{
    if (stop < start)
        return;
    for (size_t bit = start; bit <= stop; ++bit)
        bit_set(bits, bit);
}

static inline int
bit_ntest(const bitstr_t *bits, size_t start, size_t stop, int match)
{
    if (stop < start)
        return 1;
    for (size_t bit = start; bit <= stop; ++bit) {
        if (bsd_bit_test_bounded(bits, bit) != (match != 0))
            return 0;
    }
    return 1;
}

static inline int
bsd_bit_find_clear(const bitstr_t *bits, size_t start, size_t count)
{
    for (size_t bit = start; bit < count; ++bit) {
        if (!bsd_bit_test_bounded(bits, bit))
            return (int)bit;
    }
    return -1;
}

static inline int
bsd_bit_find_set(const bitstr_t *bits, size_t start, size_t count)
{
    for (size_t bit = start; bit < count; ++bit) {
        if (bsd_bit_test_bounded(bits, bit))
            return (int)bit;
    }
    return -1;
}

static inline int
bsd_bit_find_area(const bitstr_t *bits, size_t start, size_t count,
    size_t size, int match)
{
    size_t run_start = start;
    size_t run_length = 0;

    if (start > count || size > count - start)
        return -1;
    if (size == 0)
        return (int)start;

    for (size_t bit = start; bit < count; ++bit) {
        if (bsd_bit_test_bounded(bits, bit) == (match != 0)) {
            if (run_length == 0)
                run_start = bit;
            ++run_length;
            if (run_length == size)
                return (int)run_start;
        } else {
            run_length = 0;
        }
    }
    return -1;
}

static inline int
bsd_bit_count(const bitstr_t *bits, size_t start, size_t count)
{
    size_t total = 0;

    if (start >= count)
        return 0;
    for (size_t bit = start; bit < count; ++bit)
        total += (size_t)bsd_bit_test_bounded(bits, bit);
    return (int)total;
}

#define bit_ffs_at(bits, start, count, result)                           \
    (*(result) = bsd_bit_find_set((bits), (start), (count)))
#define bit_ffs(bits, count, result)                                     \
    (*(result) = bsd_bit_find_set((bits), 0, (count)))
#define bit_ffc_at(bits, start, count, result)                           \
    (*(result) = bsd_bit_find_clear((bits), (start), (count)))
#define bit_ffc(bits, count, result)                                     \
    (*(result) = bsd_bit_find_clear((bits), 0, (count)))
#define bit_ffs_area_at(bits, start, count, size, result)                 \
    (*(result) = bsd_bit_find_area(                                      \
        (bits), (start), (count), (size), 1))
#define bit_ffc_area_at(bits, start, count, size, result)                 \
    (*(result) = bsd_bit_find_area(                                      \
        (bits), (start), (count), (size), 0))
#define bit_ffs_area(bits, count, size, result)                           \
    bit_ffs_area_at((bits), 0, (count), (size), (result))
#define bit_ffc_area(bits, count, size, result)                           \
    bit_ffc_area_at((bits), 0, (count), (size), (result))
#define bit_count(bits, start, count, result)                            \
    (*(result) = bsd_bit_count((bits), (start), (count)))

#define bit_foreach_at(bits, start, count, iterator)                     \
    for ((iterator) = bsd_bit_find_set((bits), (start), (count));        \
         (iterator) != -1;                                               \
         (iterator) = bsd_bit_find_set(                                  \
             (bits), (size_t)(iterator) + 1u, (count)))
#define bit_foreach(bits, count, iterator)                               \
    bit_foreach_at((bits), 0, (count), (iterator))
#define bit_foreach_unset_at(bits, start, count, iterator)               \
    for ((iterator) = bsd_bit_find_clear((bits), (start), (count));      \
         (iterator) != -1;                                               \
         (iterator) = bsd_bit_find_clear(                                \
             (bits), (size_t)(iterator) + 1u, (count)))
#define bit_foreach_unset(bits, count, iterator)                         \
    bit_foreach_unset_at((bits), 0, (count), (iterator))

#endif
