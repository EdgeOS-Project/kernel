/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD hash-table allocator contract for the EdgeOS driver bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_HASH_H
#define EDGEOS_COMPAT_FREEBSD_HASH_H

struct malloc_type;

#define HASH_NOWAIT 0x00000001
#define HASH_WAITOK 0x00000002

void hashdestroy(void *table, struct malloc_type *type,
    unsigned long hashmask);
void *hashinit(int count, struct malloc_type *type,
    unsigned long *hashmask);
void *hashinit_flags(int count, struct malloc_type *type,
    unsigned long *hashmask, int flags);
void *phashinit(int count, struct malloc_type *type,
    unsigned long *entries);
void *phashinit_flags(int count, struct malloc_type *type,
    unsigned long *entries, int flags);

#endif
