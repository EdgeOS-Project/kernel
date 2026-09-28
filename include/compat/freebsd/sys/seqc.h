/* SPDX-License-Identifier: BSD-2-Clause */
/* Sequence counters used by FreeBSD LinuxKPI seqlocks. */

#ifndef _SYS_SEQC_H_
#define _SYS_SEQC_H_

#include <sys/lock.h>
#include <sys/systm.h>
#include <machine/atomic.h>
#include <machine/cpu.h>

typedef unsigned int seqc_t;

#define SEQC_MOD 1U
#define seqc_in_modify(seqc) (((seqc) & SEQC_MOD) != 0)

static inline void
seqc_write_begin(seqc_t *seqcp)
{
    critical_enter();
    MPASS(!seqc_in_modify(*seqcp));
    *seqcp += SEQC_MOD;
    atomic_thread_fence_rel();
}

static inline void
seqc_write_end(seqc_t *seqcp)
{
    atomic_thread_fence_rel();
    *seqcp += SEQC_MOD;
    MPASS(!seqc_in_modify(*seqcp));
    critical_exit();
}

static inline seqc_t
seqc_read_any(const seqc_t *seqcp)
{
    return atomic_load_acq_int(seqcp);
}

static inline seqc_t
seqc_read(const seqc_t *seqcp)
{
    seqc_t value;

    do {
        value = seqc_read_any(seqcp);
        if (seqc_in_modify(value))
            cpu_spinwait();
    } while (seqc_in_modify(value));
    return value;
}

#define seqc_consistent_no_fence(seqcp, oldseqc) \
    (*(seqcp) == (oldseqc))

#define seqc_consistent(seqcp, oldseqc) ({ \
    atomic_thread_fence_acq(); \
    seqc_consistent_no_fence((seqcp), (oldseqc)); \
})

static inline void
seqc_sleepable_write_begin(seqc_t *seqcp)
{
    MPASS(!seqc_in_modify(*seqcp));
    *seqcp += SEQC_MOD;
    atomic_thread_fence_rel();
}

static inline void
seqc_sleepable_write_end(seqc_t *seqcp)
{
    atomic_thread_fence_rel();
    *seqcp += SEQC_MOD;
    MPASS(!seqc_in_modify(*seqcp));
}

#endif
