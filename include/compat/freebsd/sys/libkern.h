/* SPDX-License-Identifier: MPL-2.0 */
/* Kernel utility declarations provided by the shared BSD bridge runtime. */

#ifndef _SYS_LIBKERN_H_
#define _SYS_LIBKERN_H_

#include "systm.h"
#include <sys/bitcount.h>

#define bitcount16(value) __bitcount16((uint16_t)(value))
#define bitcount32(value) __bitcount32((uint32_t)(value))
#define bitcount64(value) __bitcount64((uint64_t)(value))

typedef int bsd_qsort_compare_t(const void *, const void *);
struct malloc_type;
void qsort(void *base, size_t count, size_t size,
    bsd_qsort_compare_t *compare);
u_long random(void);
char *strdup_flags(const char *text, struct malloc_type *type, int flags);

#define LIBKERN_LEN_BCD2BIN 154
#define LIBKERN_LEN_BIN2BCD 100
#define LIBKERN_LEN_HEX2ASCII 36

static inline u_quad_t
uqmax(u_quad_t left, u_quad_t right)
{
    return left > right ? left : right;
}

static inline u_long
ulmin(u_long left, u_long right)
{
    return left < right ? left : right;
}

static inline u_long
ulmax(u_long left, u_long right)
{
    return left > right ? left : right;
}

static inline uintmax_t
ummin(uintmax_t left, uintmax_t right)
{
    return left < right ? left : right;
}

static inline uintmax_t
ummax(uintmax_t left, uintmax_t right)
{
    return left > right ? left : right;
}

static inline unsigned char
bcd2bin(int bcd)
{
    return (unsigned char)(((bcd >> 4) * 10) + (bcd & 0x0f));
}

static inline unsigned char
bin2bcd(int binary)
{
    return (unsigned char)(((binary / 10) << 4) | (binary % 10));
}

static inline int
validbcd(int bcd)
{
    return bcd >= 0 && bcd <= 0x99 &&
        (bcd & 0x0f) <= 9 && ((bcd >> 4) & 0x0f) <= 9;
}

static inline int
bsd_ilog2(uint64_t value)
{
    KASSERT(value != 0, ("ilog2 argument must be nonzero"));
    return 63 - __builtin_clzll(value);
}

static inline int64_t
signed_extend64(uint64_t bitmap, int lsb, int width)
{
    return ((int64_t)(bitmap << (63 - lsb - (width - 1)))) >>
        (63 - (width - 1));
}

static inline int32_t
signed_extend32(uint32_t bitmap, int lsb, int width)
{
    return ((int32_t)(bitmap << (31 - lsb - (width - 1)))) >>
        (31 - (width - 1));
}

#define ilog2(value) bsd_ilog2((uint64_t)(value))
#define order_base_2(value) ilog2(2 * (value) - 1)

#ifndef bitcount
#define bitcount(value) __bitcount((unsigned int)(value))
#endif

#endif
