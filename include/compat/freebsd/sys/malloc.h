/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD malloc interface for unmodified driver sources. */

#ifndef _SYS_MALLOC_H_
#define _SYS_MALLOC_H_

#include <edgeos/malloc.h>
#include <edgeos/allocator.h>

#include <stdbool.h>
#include <stdint.h>

#ifndef M_PCB
#define M_PCB M_DEVBUF
#endif

#define malloc(size, type, flags) bsd_malloc((size), (type), (flags))
#define mallocarray(count, size, type, flags) \
    bsd_mallocarray((count), (size), (type), (flags))
#define malloc_aligned(size, alignment, type, flags) \
    bsd_malloc_aligned((size), (alignment), (type), (flags))
#define malloc_domainset(size, type, domainset, flags) \
    bsd_malloc((size), (type), (flags))
#define malloc_usable_size(allocation) \
    bsd_kmalloc_usable_size((allocation))

static inline size_t
malloc_size(size_t size)
{
    return size;
}

static inline bool
WOULD_OVERFLOW(size_t count, size_t size)
{
    return count != 0 && size > SIZE_MAX / count;
}
#define contigmalloc(size, type, flags, low, high, alignment, boundary) \
    bsd_contigmalloc((size), (type), (flags), (low), (high), \
        (alignment), (boundary))
#define contigmalloc_domainset(size, type, policy, flags, low, high, \
    alignment, boundary) \
    bsd_contigmalloc_domainset((size), (type), (policy), (flags), \
        (low), (high), (alignment), (boundary))
#define contigfree(allocation, size, type) \
    bsd_contigfree((allocation), (size), (type))
#define realloc(allocation, size, type, flags) \
    bsd_realloc((allocation), (size), (type), (flags))
#define reallocarray(allocation, count, size, type, flags) \
    bsd_reallocarray((allocation), (count), (size), (type), (flags))
static inline void *
bsd_reallocf(void *allocation, size_t size, struct malloc_type *type,
    int flags)
{
    void *replacement = bsd_realloc(allocation, size, type, flags);

    if (!replacement && allocation)
        bsd_free(allocation, type);
    return replacement;
}
#define reallocf(allocation, size, type, flags) \
    bsd_reallocf((allocation), (size), (type), (flags))
#define strdup(text, type) bsd_strdup((text), (type))
#ifdef BSD_BRIDGE_HOST_TEST
#define free(allocation, type) bsd_free((allocation), (type))
#else
static inline void
free(void *allocation, struct malloc_type *type)
{
    bsd_free(allocation, type);
}
#endif
#define zfree(allocation, type) bsd_free((allocation), (type))

#endif
