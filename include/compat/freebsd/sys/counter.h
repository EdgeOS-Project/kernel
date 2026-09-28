/* SPDX-License-Identifier: BSD-2-Clause */
/* Atomic 64-bit counters for imported BSD driver frameworks. */

#ifndef _SYS_COUNTER_H_
#define _SYS_COUNTER_H_

#include <stdint.h>

typedef uint64_t *counter_u64_t;

counter_u64_t counter_u64_alloc(int flags);
void counter_u64_free(counter_u64_t counter);
void counter_u64_zero(counter_u64_t counter);

static inline uint64_t
counter_u64_fetch(counter_u64_t counter)
{
    return counter ?
        __atomic_load_n(counter, __ATOMIC_RELAXED) : UINT64_C(0);
}

static inline void
counter_u64_add(counter_u64_t counter, int64_t amount)
{
    if (counter)
        (void)__atomic_fetch_add(counter, (uint64_t)amount,
            __ATOMIC_RELAXED);
}

#define counter_enter() do { } while (0)
#define counter_exit() do { } while (0)
#define counter_u64_add_protected(counter, amount) \
    counter_u64_add((counter), (amount))

#endif
