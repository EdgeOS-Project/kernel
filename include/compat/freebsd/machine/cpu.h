/* SPDX-License-Identifier: MPL-2.0 */
/* Shared CPU relaxation helpers for the EdgeOS FreeBSD driver bridge. */

#ifndef _MACHINE_CPU_H_
#define _MACHINE_CPU_H_

#include <stdint.h>

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#include <machine/armreg.h>

#define CPU_AFF0(mpidr) ((unsigned int)(((mpidr) >> 0) & 0xff))
#define CPU_AFF1(mpidr) ((unsigned int)(((mpidr) >> 8) & 0xff))
#define CPU_AFF2(mpidr) ((unsigned int)(((mpidr) >> 16) & 0xff))
#define CPU_AFF3(mpidr) ((unsigned int)(((mpidr) >> 32) & 0xff))
#endif

#if defined(__x86_64__)
extern void (*vmm_suspend_p)(void);
extern void (*vmm_resume_p)(void);
#endif

#define CPU_IMPL_CAVIUM 0x43U
#define CPU_IMPL_ARM 0x41U
#define CPU_IMPL_APM 0x50U
#define CPU_PART_THUNDERX 0x0a1U
#define CPU_PART_EMAG8180 0x000U
#define CPU_PART_FOUNDATION 0xd00U

#define CPU_IMPL_TO_MIDR(value) (((uint32_t)(value) & 0xffU) << 24)
#define CPU_PART_TO_MIDR(value) (((uint32_t)(value) & 0xfffU) << 4)
#define CPU_VAR_TO_MIDR(value) (((uint32_t)(value) & 0xfU) << 20)
#define CPU_REV_TO_MIDR(value) ((uint32_t)(value) & 0xfU)
#define CPU_ARCH_TO_MIDR(value) (((uint32_t)(value) & 0xfU) << 16)

#define CPU_IMPL_MASK UINT32_C(0xff000000)
#define CPU_PART_MASK UINT32_C(0x0000fff0)
#define CPU_VAR_MASK UINT32_C(0x00f00000)
#define CPU_REV_MASK UINT32_C(0x0000000f)

#define CPU_ID_RAW(implementation, part, variant, revision)              \
    (CPU_IMPL_TO_MIDR(implementation) | CPU_PART_TO_MIDR(part) |        \
        CPU_VAR_TO_MIDR(variant) | CPU_REV_TO_MIDR(revision))

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#define cpu_spinwait() __asm __volatile("yield" : : : "memory")
#elif defined(__x86_64__)
#define cpu_spinwait() __asm __volatile("pause" : : : "memory")
#else
#error "Unsupported EdgeOS FreeBSD driver bridge architecture"
#endif

static __inline unsigned long long
get_cyclecount(void)
{
#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
    unsigned long long value;

    __asm __volatile("mrs %0, cntvct_el0" : "=r"(value));
    return value;
#elif defined(__x86_64__)
    unsigned int low;
    unsigned int high;

    __asm __volatile("rdtsc" : "=a"(low), "=d"(high));
    return ((unsigned long long)high << 32) | low;
#endif
}

static __inline unsigned int
get_midr(void)
{
#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
    unsigned long long value;

    __asm __volatile("mrs %0, midr_el1" : "=r"(value));
    return (unsigned int)value;
#else
    return 0;
#endif
}

#define CPU_MATCH(mask, implementation, part, variant, revision)        \
    ((((uint32_t)(mask)) & get_midr()) ==                               \
        (((uint32_t)(mask)) & CPU_ID_RAW(implementation, part,          \
            variant, revision)))

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
void get_kernel_reg_iss_masked(unsigned int iss, uint64_t *value,
    uint64_t mask);
void get_kernel_reg_iss(unsigned int iss, uint64_t *value);
#define get_kernel_reg(reg, value) get_kernel_reg_iss(reg ## _ISS, value)
#endif

#endif
