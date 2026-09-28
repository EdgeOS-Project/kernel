/* SPDX-License-Identifier: BSD-2-Clause */
/* Machine-dependent VDSO timehand layout used by imported FreeBSD drivers. */

#ifndef _MACHINE_VDSO_H_
#define _MACHINE_VDSO_H_

#if defined(__x86_64__)
#define VDSO_TIMEHANDS_MD \
    uint32_t th_x86_shift; \
    uint32_t th_x86_hpet_idx; \
    uint64_t th_x86_pvc_last_systime; \
    uint8_t th_x86_pvc_stable_mask; \
    uint8_t th_res[15]

#define VDSO_TIMEHANDS_MD32 \
    uint32_t th_x86_shift; \
    uint32_t th_x86_hpet_idx; \
    uint32_t th_x86_pvc_last_systime[2]; \
    uint8_t th_x86_pvc_stable_mask; \
    uint8_t th_res[15]

#define VDSO_TH_ALGO_X86_TSC VDSO_TH_ALGO_1
#define VDSO_TH_ALGO_X86_HPET VDSO_TH_ALGO_2
#define VDSO_TH_ALGO_X86_HVTSC VDSO_TH_ALGO_3
#define VDSO_TH_ALGO_X86_PVCLK VDSO_TH_ALGO_4
#else
#define VDSO_TIMEHANDS_MD \
    uint32_t th_physical; \
    uint32_t th_res[7]
#define VDSO_TIMEHANDS_MD32 VDSO_TIMEHANDS_MD
#define VDSO_TH_ALGO_ARM_GENTIM VDSO_TH_ALGO_1
#endif

#endif
