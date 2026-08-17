/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1991, 1993
 *     The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Adapted for the EdgeOS FreeBSD driver bridge from FreeBSD subr_hash.c.
 */

#include <stddef.h>

#include "compat/freebsd/edgeos/hash.h"
#include "compat/freebsd/edgeos/malloc.h"

#ifndef BSD_BRIDGE_HOST_TEST
#include "compat/freebsd/sys/kassert.h"
#endif

static int
hash_mflags(int flags)
{
    return (flags & HASH_NOWAIT) != 0 ? M_NOWAIT : M_WAITOK;
}

void *
hashinit_flags(int elements, struct malloc_type *type,
    unsigned long *hashmask, int flags)
{
    void **table;
    unsigned long size;

#ifndef BSD_BRIDGE_HOST_TEST
    MPASS(elements > 0);
#endif
    if (elements <= 0 || hashmask == NULL)
        return NULL;

    for (size = 1; size <= (unsigned long)elements / 2; size <<= 1)
        continue;
    table = bsd_mallocarray(size, sizeof(*table), type,
        hash_mflags(flags) | M_ZERO);
    if (table != NULL)
        *hashmask = size - 1;
    return table;
}

void *
hashinit(int elements, struct malloc_type *type, unsigned long *hashmask)
{
    return hashinit_flags(elements, type, hashmask, HASH_WAITOK);
}

void
hashdestroy(void *table, struct malloc_type *type, unsigned long hashmask)
{
    if (table == NULL)
        return;
#if defined(INVARIANTS) && !defined(BSD_BRIDGE_HOST_TEST)
    void **buckets = table;

    for (unsigned long index = 0; index <= hashmask; ++index)
        KASSERT(buckets[index] == NULL,
            ("hashdestroy: table %p is not empty", table));
#else
    (void)hashmask;
#endif
    bsd_free(table, type);
}

void *
phashinit_flags(int elements, struct malloc_type *type,
    unsigned long *entries, int flags)
{
    static const int primes[] = {
        1, 13, 31, 61, 127, 251, 509, 761, 1021, 1531, 2039, 2557,
        3067, 3583, 4093, 4603, 5119, 5623, 6143, 6653, 7159, 7673,
        8191, 12281, 16381, 24571, 32749,
    };
    void **table;
    size_t index;

#ifndef BSD_BRIDGE_HOST_TEST
    MPASS(elements > 0);
#endif
    if (elements <= 0 || entries == NULL)
        return NULL;

    index = sizeof(primes) / sizeof(primes[0]) - 1;
    while (index > 0 && elements < primes[index])
        --index;
    table = bsd_mallocarray((size_t)primes[index], sizeof(*table), type,
        hash_mflags(flags) | M_ZERO);
    if (table != NULL)
        *entries = (unsigned long)primes[index];
    return table;
}

void *
phashinit(int elements, struct malloc_type *type, unsigned long *entries)
{
    return phashinit_flags(elements, type, entries, HASH_WAITOK);
}
