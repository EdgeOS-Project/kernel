/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD malloc-type adapter backed by the shared bridge allocator. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/malloc.h"

MALLOC_DEFINE(M_CACHE, "cache", "BSD bridge cache allocations");
MALLOC_DEFINE(M_DEVBUF, "devbuf", "BSD bridge device allocations");
MALLOC_DEFINE(M_IOV, "iov", "BSD bridge I/O vector allocations");
MALLOC_DEFINE(M_LINKER, "linker", "BSD bridge linker metadata");
MALLOC_DEFINE(M_PARGS, "proc-args", "BSD bridge process argument allocations");
MALLOC_DEFINE(M_SESSION, "session", "BSD bridge session allocations");
MALLOC_DEFINE(M_SUBPROC, "subproc", "BSD bridge subprocess allocations");
MALLOC_DEFINE(M_TEMP, "temp", "BSD bridge temporary allocations");

#define BSD_MALLOC_ALIGNED_MAGIC 0x425344414c49474eULL
#define BSD_MALLOC_PAGE_SIZE 4096U

typedef struct bsd_malloc_aligned_header {
    uint64_t magic;
    void *base;
    size_t requested;
    size_t alignment;
} bsd_malloc_aligned_header_t;

static uint32_t
allocator_flags(int flags)
{
    uint32_t result = 0;

    if ((flags & M_WAITOK) != 0)
        result |= BSD_M_WAITOK;
    else
        result |= BSD_M_NOWAIT;
    if ((flags & M_ZERO) != 0)
        result |= BSD_M_ZERO;
    return result;
}

static void
record_allocation(struct malloc_type *type, size_t bytes)
{
    if (!type)
        return;
    (void)__atomic_fetch_add(&type->bytes_allocated, bytes, __ATOMIC_RELAXED);
    (void)__atomic_fetch_add(&type->allocation_count, 1, __ATOMIC_RELAXED);
}

static void
record_free(struct malloc_type *type, size_t bytes)
{
    if (!type)
        return;
    (void)__atomic_fetch_add(&type->bytes_freed, bytes, __ATOMIC_RELAXED);
    (void)__atomic_fetch_add(&type->free_count, 1, __ATOMIC_RELAXED);
}

static int
power_of_two(size_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

static bsd_malloc_aligned_header_t *
aligned_header(void *allocation)
{
    bsd_malloc_aligned_header_t *header;
    size_t available;

    if (!allocation)
        return 0;
    header = (bsd_malloc_aligned_header_t *)((uint8_t *)allocation -
        sizeof(*header));
    if (header->magic != BSD_MALLOC_ALIGNED_MAGIC || !header->base ||
        !power_of_two(header->alignment) ||
        ((uintptr_t)allocation & (header->alignment - 1)) != 0)
        return 0;
    available = bsd_kmalloc_usable_size(header->base);
    if (available < sizeof(*header) ||
        header->requested > available - sizeof(*header))
        return 0;
    return header;
}

void *
bsd_malloc(size_t size, struct malloc_type *type, int flags)
{
    void *allocation;

    if (size >= BSD_MALLOC_PAGE_SIZE &&
        (size & (BSD_MALLOC_PAGE_SIZE - 1u)) == 0)
        return bsd_malloc_aligned(size, BSD_MALLOC_PAGE_SIZE, type, flags);
    allocation = bsd_kmalloc(size, allocator_flags(flags));

    if (allocation)
        record_allocation(type, bsd_kmalloc_usable_size(allocation));
    return allocation;
}

void *
bsd_mallocarray(size_t count, size_t size, struct malloc_type *type, int flags)
{
    void *allocation;

    if (size != 0 && count > SIZE_MAX / size)
        return 0;
    if (count * size >= BSD_MALLOC_PAGE_SIZE &&
        ((count * size) & (BSD_MALLOC_PAGE_SIZE - 1u)) == 0)
        return bsd_malloc(count * size, type, flags);
    allocation = bsd_kmallocarray(count, size, allocator_flags(flags));

    if (allocation)
        record_allocation(type, bsd_kmalloc_usable_size(allocation));
    return allocation;
}

void *
bsd_malloc_aligned(size_t size, size_t alignment,
    struct malloc_type *type, int flags)
{
    bsd_malloc_aligned_header_t *header;
    uintptr_t unaligned;
    uintptr_t aligned;
    size_t total;
    void *base;

    if (!power_of_two(alignment))
        return 0;
    if (alignment < sizeof(void *))
        alignment = sizeof(void *);
    if (size == 0)
        size = 1;
    if (size > SIZE_MAX - sizeof(*header) ||
        size + sizeof(*header) > SIZE_MAX - (alignment - 1))
        return 0;
    total = size + sizeof(*header) + alignment - 1;
    base = bsd_kmalloc(total, allocator_flags(flags));
    if (!base)
        return 0;
    unaligned = (uintptr_t)base + sizeof(*header);
    aligned = (unaligned + alignment - 1) & ~(uintptr_t)(alignment - 1);
    header = (bsd_malloc_aligned_header_t *)(aligned - sizeof(*header));
    header->magic = BSD_MALLOC_ALIGNED_MAGIC;
    header->base = base;
    header->requested = size;
    header->alignment = alignment;
    if ((flags & M_ZERO) != 0)
        __builtin_memset((void *)aligned, 0, size);
    record_allocation(type, bsd_kmalloc_usable_size(base));
    return (void *)aligned;
}

void *
bsd_realloc(void *allocation, size_t size, struct malloc_type *type, int flags)
{
    bsd_malloc_aligned_header_t *header = aligned_header(allocation);
    size_t old_size = header ? header->requested :
        bsd_kmalloc_usable_size(allocation);
    void *replacement =
        header ? bsd_malloc_aligned(size, header->alignment, type, flags) :
        bsd_krealloc(allocation, size, allocator_flags(flags));

    if (!replacement)
        return 0;
    if (header) {
        size_t copy_size = old_size < size ? old_size : size;

        __builtin_memcpy(replacement, allocation, copy_size);
        bsd_free(allocation, type);
        return replacement;
    }
    if (allocation) {
        record_free(type, old_size);
        record_allocation(type, bsd_kmalloc_usable_size(replacement));
    } else {
        record_allocation(type, bsd_kmalloc_usable_size(replacement));
    }
    return replacement;
}

void *
bsd_reallocarray(void *allocation, size_t count, size_t size,
    struct malloc_type *type, int flags)
{
    if (size != 0 && count > SIZE_MAX / size)
        return 0;
    return bsd_realloc(allocation, count * size, type, flags);
}

char *
bsd_strdup(const char *text, struct malloc_type *type)
{
    return bsd_strdup_flags(text, type, M_WAITOK);
}

char *
bsd_strdup_flags(const char *text, struct malloc_type *type, int flags)
{
    char *copy;
    size_t length;

    if (!text)
        return 0;
    length = __builtin_strlen(text) + 1;
    copy = bsd_malloc(length, type, flags);
    if (copy)
        __builtin_memcpy(copy, text, length);
    return copy;
}

char *
strdup_flags(const char *text, struct malloc_type *type, int flags)
{
    return bsd_strdup_flags(text, type, flags);
}

void
bsd_free(void *allocation, struct malloc_type *type)
{
    bsd_malloc_aligned_header_t *header;
    size_t size;

    if (!allocation)
        return;
    header = aligned_header(allocation);
    if (header) {
        void *base = header->base;

        size = bsd_kmalloc_usable_size(base);
        header->magic = 0;
        record_free(type, size);
        bsd_kfree(base);
        return;
    }
    size = bsd_kmalloc_usable_size(allocation);
    if (size == 0)
        return;
    record_free(type, size);
    bsd_kfree(allocation);
}
