/* SPDX-License-Identifier: MPL-2.0 */
/* Atomic counter storage for imported BSD drivers. */

#include <stdint.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/sys/counter.h"

counter_u64_t
counter_u64_alloc(int flags)
{
    uint32_t allocator_flags =
        (flags & M_WAITOK) != 0 ? BSD_M_WAITOK : BSD_M_NOWAIT;

    return bsd_kmalloc(sizeof(uint64_t), allocator_flags | BSD_M_ZERO);
}

void
counter_u64_free(counter_u64_t counter)
{
    bsd_kfree(counter);
}

void
counter_u64_zero(counter_u64_t counter)
{
    if (counter)
        __atomic_store_n(counter, UINT64_C(0), __ATOMIC_RELAXED);
}
