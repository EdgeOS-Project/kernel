/* SPDX-License-Identifier: MPL-2.0 */
/* Safe page-table reader exclusion for the EdgeOS VMM bridge. */

#ifndef _SYS_SMR_H_
#define _SYS_SMR_H_

#include <stdint.h>

struct edgeos_smr {
    volatile uint32_t readers;
    volatile uint32_t writer;
};

typedef struct edgeos_smr *smr_t;

static inline void
smr_init(struct edgeos_smr *smr)
{
    if (!smr)
        return;
    smr->readers = 0;
    smr->writer = 0;
}

static inline void
smr_enter(smr_t smr)
{
    if (!smr)
        return;
    for (;;) {
        while (__atomic_load_n(&smr->writer, __ATOMIC_ACQUIRE) != 0)
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
        __atomic_fetch_add(&smr->readers, 1u, __ATOMIC_ACQUIRE);
        if (__atomic_load_n(&smr->writer, __ATOMIC_ACQUIRE) == 0)
            return;
        __atomic_fetch_sub(&smr->readers, 1u, __ATOMIC_RELEASE);
    }
}

static inline void
smr_exit(smr_t smr)
{
    if (smr)
        __atomic_fetch_sub(&smr->readers, 1u, __ATOMIC_RELEASE);
}

static inline void
edgeos_smr_write_enter(smr_t smr)
{
    if (!smr)
        return;
    while (__atomic_exchange_n(&smr->writer, 1u, __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&smr->writer, __ATOMIC_RELAXED) != 0)
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
    while (__atomic_load_n(&smr->readers, __ATOMIC_ACQUIRE) != 0)
        __atomic_signal_fence(__ATOMIC_ACQUIRE);
}

static inline void
edgeos_smr_write_exit(smr_t smr)
{
    if (smr)
        __atomic_store_n(&smr->writer, 0u, __ATOMIC_RELEASE);
}

static inline void
smr_synchronize(smr_t smr)
{
    edgeos_smr_write_enter(smr);
    edgeos_smr_write_exit(smr);
}

#endif
