/* SPDX-License-Identifier: BSD-2-Clause */
/* VDSO timekeeping ABI used by imported FreeBSD drivers. */

#ifndef _SYS_VDSO_H_
#define _SYS_VDSO_H_

#include <sys/types.h>
#include <sys/time.h>
#include <machine/vdso.h>

struct vdso_timehands {
    uint32_t th_algo;
    uint32_t th_gen;
    uint64_t th_scale;
    uint32_t th_offset_count;
    uint32_t th_counter_mask;
    struct bintime th_offset;
    struct bintime th_boottime;
    VDSO_TIMEHANDS_MD;
};

#define VDSO_TH_ALGO_1 0x1u
#define VDSO_TH_ALGO_2 0x2u
#define VDSO_TH_ALGO_3 0x3u
#define VDSO_TH_ALGO_4 0x4u

#endif
