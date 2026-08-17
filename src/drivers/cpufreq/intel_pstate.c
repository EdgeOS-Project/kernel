/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Intel P-State support for CPUs exposing Hardware-Controlled Performance
 * States (HWP).  This follows the architectural CPUID/MSR interface published
 * by Intel SDM; it does not copy Linux implementation code.
 */

#include "drivers/intel_pstate.h"

#include "stdio.h"
#include "string.h"

#include <stdint.h>

#define CPUID_FEATURE_POWER 0x06u
#define CPUID_HWP          (1u << 7)
#define CPUID_HWP_EPP      (1u << 10)

#define MSR_IA32_PM_ENABLE        0x770u
#define MSR_IA32_HWP_CAPABILITIES 0x771u
#define MSR_IA32_HWP_REQUEST      0x774u

#define HWP_REQUEST_MIN_SHIFT     0u
#define HWP_REQUEST_MAX_SHIFT     8u
#define HWP_REQUEST_DESIRED_SHIFT 16u
#define HWP_REQUEST_EPP_SHIFT     24u
#define HWP_EPP_BALANCE_PERF      0x80u

typedef struct {
    uint8_t available;
    uint8_t hwp_epp;
    uint8_t lowest;
    uint8_t highest;
    uint8_t guaranteed;
    uint8_t efficient;
} intel_pstate_state_t;

static intel_pstate_state_t g_pstate;

static void cpuid_leaf(uint32_t leaf, uint32_t subleaf,
                       uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    uint32_t a, b, c, d;
    __asm__ __volatile__("cpuid"
                         : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                         : "a"(leaf), "c"(subleaf));
    if (eax) *eax = a;
    if (ebx) *ebx = b;
    if (ecx) *ecx = c;
    if (edx) *edx = d;
}

static uint64_t rdmsr64(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static void wrmsr64(uint32_t msr, uint64_t v) {
    __asm__ __volatile__("wrmsr" :: "c"(msr), "a"((uint32_t)v), "d"((uint32_t)(v >> 32)));
}

static int cpu_is_intel(void) {
    uint32_t eax, ebx, ecx, edx;
    char vendor[13];
    cpuid_leaf(0, 0, &eax, &ebx, &ecx, &edx);
    (void)eax;
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);
    vendor[12] = 0;
    return strcmp(vendor, "GenuineIntel") == 0;
}

static int cpu_has_cpuid_leaf(uint32_t leaf) {
    uint32_t max_leaf;
    cpuid_leaf(0, 0, &max_leaf, 0, 0, 0);
    return max_leaf >= leaf;
}

int intel_pstate_init(void) {
    uint32_t eax;
    uint64_t caps;
    uint64_t req;
    uint8_t desired;

    memset(&g_pstate, 0, sizeof(g_pstate));
    if (!cpu_is_intel()) {
        printf("[cpufreq] intel_pstate: non-Intel CPU\n");
        return -1;
    }
    if (!cpu_has_cpuid_leaf(CPUID_FEATURE_POWER)) {
        printf("[cpufreq] intel_pstate: CPUID.06H unavailable\n");
        return -1;
    }

    cpuid_leaf(CPUID_FEATURE_POWER, 0, &eax, 0, 0, 0);
    if ((eax & CPUID_HWP) == 0) {
        printf("[cpufreq] intel_pstate: HWP not supported by CPU/firmware\n");
        return -1;
    }

    wrmsr64(MSR_IA32_PM_ENABLE, rdmsr64(MSR_IA32_PM_ENABLE) | 1u);
    caps = rdmsr64(MSR_IA32_HWP_CAPABILITIES);
    g_pstate.highest = (uint8_t)(caps & 0xFFu);
    g_pstate.guaranteed = (uint8_t)((caps >> 8) & 0xFFu);
    g_pstate.efficient = (uint8_t)((caps >> 16) & 0xFFu);
    g_pstate.lowest = (uint8_t)((caps >> 24) & 0xFFu);
    if (g_pstate.lowest == 0 || g_pstate.highest == 0 || g_pstate.lowest > g_pstate.highest) {
        printf("[cpufreq] intel_pstate: invalid HWP caps raw=0x%llx\n", caps);
        return -1;
    }

    desired = g_pstate.efficient;
    if (desired < g_pstate.lowest || desired > g_pstate.highest) desired = g_pstate.guaranteed;
    if (desired < g_pstate.lowest || desired > g_pstate.highest) desired = g_pstate.highest;

    req = ((uint64_t)g_pstate.lowest << HWP_REQUEST_MIN_SHIFT) |
          ((uint64_t)g_pstate.highest << HWP_REQUEST_MAX_SHIFT) |
          ((uint64_t)desired << HWP_REQUEST_DESIRED_SHIFT);
    if (eax & CPUID_HWP_EPP) {
        req |= ((uint64_t)HWP_EPP_BALANCE_PERF << HWP_REQUEST_EPP_SHIFT);
        g_pstate.hwp_epp = 1;
    }
    wrmsr64(MSR_IA32_HWP_REQUEST, req);
    g_pstate.available = 1;

    printf("[cpufreq] intel_pstate: HWP enabled min=%u max=%u efficient=%u guaranteed=%u epp=%s\n",
           g_pstate.lowest, g_pstate.highest, g_pstate.efficient,
           g_pstate.guaranteed, g_pstate.hwp_epp ? "balance_performance" : "unsupported");
    return 0;
}

int intel_pstate_available(void) {
    return g_pstate.available ? 1 : 0;
}

uint32_t intel_pstate_lowest_perf(void) {
    return g_pstate.lowest;
}

uint32_t intel_pstate_highest_perf(void) {
    return g_pstate.highest;
}
