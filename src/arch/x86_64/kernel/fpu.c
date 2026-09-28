/* SPDX-License-Identifier: MPL-2.0 */
/* x86 floating-point and extended SIMD state management. */

#include "arch/x86_64/fpu.h"

#include "string.h"

#include <stdint.h>

#define X86_CPUID_FEATURE_XSAVE (1u << 26)
#define X86_CPUID_FEATURE_AVX (1u << 28)
#define X86_CR4_OSXSAVE (1ull << 18)
#define X86_XFEATURE_X87 (1ull << 0)
#define X86_XFEATURE_SSE (1ull << 1)
#define X86_XFEATURE_AVX (1ull << 2)

static uint64_t g_x86_xsave_features;
static uint32_t g_x86_xsave_size = EDGE_X86_FXSAVE_SIZE;
static int g_x86_xsave_enabled;

static void x86_fpu_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                          uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    __asm__ __volatile__("cpuid"
                         : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                         : "a"(leaf), "c"(subleaf));
}

static void x86_fpu_xsetbv(uint32_t index, uint64_t value) {
    uint32_t low = (uint32_t)value;
    uint32_t high = (uint32_t)(value >> 32);

    __asm__ __volatile__("xsetbv" :: "c"(index), "a"(low), "d"(high) :
                         "memory");
}

int x86_fpu_initialize_cpu(void) {
    uint32_t maximum;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint64_t cr4;
    uint64_t features;

    x86_fpu_cpuid(0, 0, &maximum, &ebx, &ecx, &edx);
    if (maximum < 0x0du) return 0;
    x86_fpu_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if ((ecx & (X86_CPUID_FEATURE_XSAVE | X86_CPUID_FEATURE_AVX)) !=
        (X86_CPUID_FEATURE_XSAVE | X86_CPUID_FEATURE_AVX))
        return 0;

    x86_fpu_cpuid(0x0du, 0, &eax, &ebx, &ecx, &edx);
    features = ((uint64_t)edx << 32) | eax;
    features &= X86_XFEATURE_X87 | X86_XFEATURE_SSE | X86_XFEATURE_AVX;
    if (features !=
        (X86_XFEATURE_X87 | X86_XFEATURE_SSE | X86_XFEATURE_AVX) ||
        ebx < EDGE_X86_FXSAVE_SIZE || ebx > EDGE_X86_XSAVE_MAX_SIZE)
        return 0;

    __asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= X86_CR4_OSXSAVE;
    __asm__ __volatile__("mov %0, %%cr4" :: "r"(cr4) : "memory");
    x86_fpu_xsetbv(0, features);
    x86_fpu_cpuid(0x0du, 0, &eax, &ebx, &ecx, &edx);
    if (ebx < EDGE_X86_FXSAVE_SIZE || ebx > EDGE_X86_XSAVE_MAX_SIZE)
        return 0;

    g_x86_xsave_features = features;
    g_x86_xsave_size = ebx;
    __atomic_store_n(&g_x86_xsave_enabled, 1, __ATOMIC_RELEASE);
    return 1;
}

int x86_fpu_xsave_enabled(void) {
    return __atomic_load_n(&g_x86_xsave_enabled, __ATOMIC_ACQUIRE);
}

uint32_t x86_fpu_extended_state_size(void) {
    return g_x86_xsave_size;
}

uint64_t x86_fpu_enabled_features(void) {
    return g_x86_xsave_features;
}

void x86_fpu_save_state(void *extended_state, void *legacy_state) {
    if (x86_fpu_xsave_enabled() && extended_state) {
        uint32_t low = (uint32_t)g_x86_xsave_features;
        uint32_t high = (uint32_t)(g_x86_xsave_features >> 32);

        __asm__ __volatile__("xsave64 (%0)"
                             :: "r"(extended_state), "a"(low), "d"(high) :
                             "memory");
        if (legacy_state)
            memcpy(legacy_state, extended_state, EDGE_X86_FXSAVE_SIZE);
        return;
    }
    if (legacy_state)
        __asm__ __volatile__("fxsave64 (%0)" :: "r"(legacy_state) :
                             "memory");
}

void x86_fpu_restore_state(void *extended_state, const void *legacy_state) {
    if (x86_fpu_xsave_enabled() && extended_state) {
        uint32_t low = (uint32_t)g_x86_xsave_features;
        uint32_t high = (uint32_t)(g_x86_xsave_features >> 32);

        if (legacy_state)
            memcpy(extended_state, legacy_state, EDGE_X86_FXSAVE_SIZE);
        __asm__ __volatile__("xrstor64 (%0)"
                             :: "r"(extended_state), "a"(low), "d"(high) :
                             "memory");
        return;
    }
    if (legacy_state)
        __asm__ __volatile__("fxrstor64 (%0)" :: "r"(legacy_state) :
                             "memory");
}
