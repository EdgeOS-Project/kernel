/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD malloc-type adapter backed by the EdgeOS BSD allocator. */

#ifndef EDGEOS_COMPAT_FREEBSD_MALLOC_H
#define EDGEOS_COMPAT_FREEBSD_MALLOC_H

#include <stddef.h>
#include <stdint.h>

#define M_NOWAIT 0x0001
#define M_WAITOK 0x0002
#define M_NORECLAIM 0x0080
#define M_ZERO 0x0100
#define M_NOVM 0x0200
#define M_USE_RESERVE 0x0400
#define M_NODUMP 0x0800
#define M_FIRSTFIT 0x1000
#define M_BESTFIT 0x2000
#define M_EXEC 0x4000
#define M_NEXTFIT 0x8000
#define M_NEVERFREED 0x10000
#define M_UNPROTECTED 0x20000

#define M_VERSION 2024073001UL

struct malloc_type {
    struct malloc_type *ks_next;
    unsigned long ks_version;
    const char *ks_shortdesc;
    const char *ks_longdesc;
    uint64_t bytes_allocated;
    uint64_t bytes_freed;
    uint64_t allocation_count;
    uint64_t free_count;
};

#define MALLOC_DEFINE(type, short_description, long_description)          \
    struct malloc_type type[1] __attribute__((used)) = {{                \
        .ks_next = 0,                                                     \
        .ks_version = M_VERSION,                                          \
        .ks_shortdesc = (short_description),                              \
        .ks_longdesc = (long_description),                                \
    }}

#define MALLOC_DECLARE(type) extern struct malloc_type type[1]

MALLOC_DECLARE(M_CACHE);
#if defined(EDGEOS_BSD_LOADABLE_MODULE)
/*
 * Keep the ubiquitous device allocation category in each loadable image.
 * This preserves direct, position-relative data references on every module
 * target without requiring changes to imported driver sources.
 */
static struct malloc_type M_DEVBUF[1] __attribute__((unused));
#else
MALLOC_DECLARE(M_DEVBUF);
#endif
MALLOC_DECLARE(M_IOV);
MALLOC_DECLARE(M_LINKER);
MALLOC_DECLARE(M_PARGS);
MALLOC_DECLARE(M_SESSION);
MALLOC_DECLARE(M_SUBPROC);
MALLOC_DECLARE(M_TEMP);

void *bsd_malloc(size_t size, struct malloc_type *type, int flags);
void *bsd_mallocarray(size_t count, size_t size, struct malloc_type *type,
    int flags);
void *bsd_malloc_aligned(size_t size, size_t alignment,
    struct malloc_type *type, int flags);
void *bsd_contigmalloc(unsigned long size, struct malloc_type *type,
    int flags, uint64_t low, uint64_t high, unsigned long alignment,
    uint64_t boundary);
struct domainset;
void *bsd_contigmalloc_domainset(unsigned long size,
    struct malloc_type *type, struct domainset *policy, int flags,
    uint64_t low, uint64_t high, unsigned long alignment,
    uint64_t boundary);
void bsd_contigfree(void *allocation, unsigned long size,
    struct malloc_type *type);
int bsd_contigmalloc_physical_address(const void *pointer,
    uint64_t *physical_address);
void *bsd_realloc(void *allocation, size_t size, struct malloc_type *type,
    int flags);
void *bsd_reallocarray(void *allocation, size_t count, size_t size,
    struct malloc_type *type, int flags);
char *bsd_strdup(const char *text, struct malloc_type *type);
char *bsd_strdup_flags(const char *text, struct malloc_type *type, int flags);
void bsd_free(void *allocation, struct malloc_type *type);

#endif
